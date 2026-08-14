use crate::{
    db::Database,
    error::{AppError, AppResult},
    models::{ExecOutput, HostProfile, SftpEntry, StreamEnvelope, TransferProgress},
    security,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use parking_lot::RwLock;
use russh::{
    ChannelMsg, Disconnect, Pty, client,
    keys::{self, PrivateKeyWithHashAlg, ssh_key},
};
use russh_sftp::client::SftpSession;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::ipc::Channel as IpcChannel;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch, Semaphore},
};
use uuid::Uuid;

#[derive(Clone)]
struct ClientHandler {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        *self.observed.lock().await = Some(fingerprint.clone());
        Ok(self
            .expected
            .as_ref()
            .map(|known| known == &fingerprint)
            .unwrap_or(true))
    }
}

type SshHandle = client::Handle<ClientHandler>;
struct ManagedConnection {
    handle: Arc<Mutex<SshHandle>>,
    profile: HostProfile,
}

enum TerminalCommand {
    Input(Vec<u8>),
    Resize(u32, u32),
    Close,
}
struct ManagedTerminal {
    host_id: String,
    sender: mpsc::Sender<TerminalCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalAuditEvent {
    pub session_id: String,
    pub host_id: String,
    pub command: String,
    pub exit_code: i32,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTerminalAudit {
    command: String,
    exit_code: i32,
}

const AUDIT_PREFIX: &[u8] = b"\x1b]777;sshops;";
const SHELL_AUDIT_BOOTSTRAP: &str = r#"__sshops_notice=''; if command -v base64 >/dev/null 2>&1; then __sshops_emit(){ local __sshops_payload; __sshops_payload=$(printf '%s' "$2" | base64 | tr -d '\r\n'); printf '\033]777;sshops;%s;%s\007' "$1" "$__sshops_payload"; }; if [ -n "$BASH_VERSION" ]; then __sshops_ready=0; __sshops_last_hist=$HISTCMD; __sshops_prompt(){ local __sshops_status=$?; local __sshops_hist=$HISTCMD; if [ "$__sshops_ready" = 1 ] && [ "$__sshops_hist" != "$__sshops_last_hist" ]; then local __sshops_cmd; __sshops_cmd=$(builtin fc -ln -1 2>/dev/null); __sshops_cmd="${__sshops_cmd#"${__sshops_cmd%%[![:space:]]*}"}"; [ -n "$__sshops_cmd" ] && __sshops_emit "$__sshops_status" "$__sshops_cmd"; fi; __sshops_last_hist=$__sshops_hist; __sshops_ready=1; return $__sshops_status; }; PROMPT_COMMAND="__sshops_prompt${PROMPT_COMMAND:+;$PROMPT_COMMAND}"; elif [ -n "$ZSH_VERSION" ]; then autoload -Uz add-zsh-hook 2>/dev/null; __sshops_pending=''; __sshops_preexec(){ __sshops_pending="$1"; }; __sshops_precmd(){ local __sshops_status=$?; if [ -n "$__sshops_pending" ]; then __sshops_emit "$__sshops_status" "$__sshops_pending"; __sshops_pending=''; fi; return $__sshops_status; }; if ! add-zsh-hook preexec __sshops_preexec 2>/dev/null || ! add-zsh-hook precmd __sshops_precmd 2>/dev/null; then __sshops_notice='[SSH Ops] Zsh command audit is unavailable'; fi; else __sshops_notice='[SSH Ops] Command audit supports Bash and Zsh only'; fi; else __sshops_notice='[SSH Ops] Command audit requires base64'; fi; stty echo 2>/dev/null; [ -n "$__sshops_notice" ] && printf '\033[33m%s\033[0m\r\n' "$__sshops_notice""#;

#[derive(Default)]
struct TerminalAuditParser {
    pending: Vec<u8>,
}

impl TerminalAuditParser {
    fn push(&mut self, data: &[u8]) -> (Vec<u8>, Vec<ParsedTerminalAudit>) {
        self.pending.extend_from_slice(data);
        let mut visible = Vec::new();
        let mut audits = Vec::new();
        loop {
            let Some(start) = find_bytes(&self.pending, AUDIT_PREFIX) else {
                let keep = partial_prefix_len(&self.pending, AUDIT_PREFIX);
                let emit_len = self.pending.len().saturating_sub(keep);
                visible.extend(self.pending.drain(..emit_len));
                break;
            };
            visible.extend(self.pending.drain(..start));
            let Some(end_relative) = self.pending[AUDIT_PREFIX.len()..].iter().position(|byte| *byte == 7) else {
                if self.pending.len() > 64 * 1024 { visible.push(self.pending.remove(0)); }
                break;
            };
            let end = AUDIT_PREFIX.len() + end_relative;
            let frame = self.pending[AUDIT_PREFIX.len()..end].to_vec();
            self.pending.drain(..=end);
            if let Some(audit) = parse_audit_frame(&frame) { audits.push(audit); }
        }
        (visible, audits)
    }

    fn finish(&mut self) -> Vec<u8> { std::mem::take(&mut self.pending) }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> { haystack.windows(needle.len()).position(|window| window == needle) }
fn partial_prefix_len(data: &[u8], prefix: &[u8]) -> usize { (1..prefix.len().min(data.len() + 1)).rev().find(|length| data.ends_with(&prefix[..*length])).unwrap_or(0) }
fn parse_audit_frame(frame: &[u8]) -> Option<ParsedTerminalAudit> {
    let frame = std::str::from_utf8(frame).ok()?;
    let (status, encoded) = frame.split_once(';')?;
    let command = String::from_utf8(BASE64_STANDARD.decode(encoded).ok()?).ok()?;
    if command.trim().is_empty() || command.len() > 10_000 { return None; }
    Some(ParsedTerminalAudit { command, exit_code: status.parse().ok()? })
}

pub struct SshManager {
    sessions: RwLock<HashMap<String, Arc<ManagedConnection>>>,
    terminals: RwLock<HashMap<String, ManagedTerminal>>,
    forwards: RwLock<HashMap<String, watch::Sender<bool>>>,
    transfers: RwLock<HashMap<String, (String, watch::Sender<bool>)>>,
    transfer_slots: RwLock<HashMap<String, Arc<Semaphore>>>,
    sequence: Arc<AtomicU64>,
}

impl Default for SshManager {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            terminals: RwLock::new(HashMap::new()),
            forwards: RwLock::new(HashMap::new()),
            transfers: RwLock::new(HashMap::new()),
            transfer_slots: RwLock::new(HashMap::new()),
            sequence: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl SshManager {
    pub fn is_connected(&self, host_id: &str) -> bool {
        self.sessions.read().contains_key(host_id)
    }
    pub async fn connect(
        &self,
        db: &Database,
        profile: HostProfile,
        supplied_password: Option<String>,
    ) -> AppResult<()> {
        if self.is_connected(&profile.id) {
            return Ok(());
        }
        let observed = Arc::new(Mutex::new(None));
        let expected = db.known_fingerprint(&profile.id)?;
        let handler = ClientHandler {
            expected: expected.clone(),
            observed: observed.clone(),
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(90)),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            ..Default::default()
        });
        let mut handle =
            client::connect(config, (profile.hostname.as_str(), profile.port), handler)
                .await
                .map_err(|e| AppError::Ssh(e.to_string()))?;
        let auth_ok = match profile.auth_method.as_str() {
            "password" => {
                let password = supplied_password
                    .or_else(|| {
                        profile
                            .credential_id
                            .as_deref()
                            .and_then(|id| security::read_secret(id).ok())
                    })
                    .ok_or_else(|| AppError::Permission("需要 SSH 密码".into()))?;
                handle
                    .authenticate_password(profile.username.clone(), password)
                    .await
                    .map_err(|e| AppError::Ssh(e.to_string()))?
                    .success()
            }
            "key" => {
                let path = profile
                    .private_key_path
                    .as_ref()
                    .ok_or_else(|| AppError::Validation("未配置私钥路径".into()))?;
                let passphrase = profile
                    .credential_id
                    .as_deref()
                    .and_then(|id| security::read_secret(id).ok());
                let key = keys::load_secret_key(Path::new(path), passphrase.as_deref())
                    .map_err(|e| AppError::Ssh(format!("无法读取私钥：{e}")))?;
                let hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|e| AppError::Ssh(e.to_string()))?
                    .flatten();
                handle
                    .authenticate_publickey(
                        profile.username.clone(),
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await
                    .map_err(|e| AppError::Ssh(e.to_string()))?
                    .success()
            }
            "keyboardInteractive" => {
                let password = supplied_password
                    .or_else(|| {
                        profile
                            .credential_id
                            .as_deref()
                            .and_then(|id| security::read_secret(id).ok())
                    })
                    .ok_or_else(|| AppError::Permission("需要键盘交互响应".into()))?;
                let mut response = handle
                    .authenticate_keyboard_interactive_start(
                        profile.username.clone(),
                        None::<String>,
                    )
                    .await
                    .map_err(|e| AppError::Ssh(e.to_string()))?;
                loop {
                    match response {
                        client::KeyboardInteractiveAuthResponse::Success => break true,
                        client::KeyboardInteractiveAuthResponse::Failure { .. } => break false,
                        client::KeyboardInteractiveAuthResponse::InfoRequest {
                            prompts, ..
                        } => {
                            response = handle
                                .authenticate_keyboard_interactive_respond(
                                    prompts.iter().map(|_| password.clone()).collect(),
                                )
                                .await
                                .map_err(|e| AppError::Ssh(e.to_string()))?;
                        }
                    }
                }
            }
            "agent" => {
                return Err(AppError::Other(
                    "SSH Agent 认证需要先在设置中选择 Windows OpenSSH Agent 密钥".into(),
                ));
            }
            other => return Err(AppError::Validation(format!("未知认证方式：{other}"))),
        };
        if !auth_ok {
            return Err(AppError::Permission("SSH 认证失败".into()));
        }
        if expected.is_none() {
            if let Some(fingerprint) = observed.lock().await.clone() {
                db.set_fingerprint(&profile.id, &fingerprint)?;
            }
        }
        self.sessions.write().insert(
            profile.id.clone(),
            Arc::new(ManagedConnection {
                handle: Arc::new(Mutex::new(handle)),
                profile,
            }),
        );
        Ok(())
    }

    pub async fn disconnect(&self, host_id: &str) -> AppResult<()> {
        let transfer_ids = self
            .transfers
            .read()
            .iter()
            .filter(|(_, (hid, _))| hid == host_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in transfer_ids {
            self.transfer_cancel(&id);
        }
        let terminal_ids = self
            .terminals
            .read()
            .iter()
            .filter(|(_, terminal)| terminal.host_id == host_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in terminal_ids {
            self.terminal_close(&id).await?;
        }
        let session = { self.sessions.write().remove(host_id) };
        if let Some(session) = session {
            session
                .handle
                .lock()
                .await
                .disconnect(Disconnect::ByApplication, "", "en")
                .await
                .map_err(|e| AppError::Ssh(e.to_string()))?;
        }
        Ok(())
    }

    pub fn transfer_cancel(&self, transfer_id: &str) {
        if let Some((_, cancel)) = self.transfers.write().remove(transfer_id) {
            let _ = cancel.send(true);
        }
    }
    fn transfer_slot(&self, host_id: &str) -> Arc<Semaphore> {
        if let Some(slot) = self.transfer_slots.read().get(host_id) { return slot.clone(); }
        let mut slots = self.transfer_slots.write(); slots.entry(host_id.into()).or_insert_with(|| Arc::new(Semaphore::new(2))).clone()
    }
    fn connection(&self, host_id: &str) -> AppResult<Arc<ManagedConnection>> {
        self.sessions
            .read()
            .get(host_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(format!("服务器 {host_id} 尚未连接")))
    }

    pub async fn exec(&self, host_id: &str, command: &str) -> AppResult<ExecOutput> {
        let connection = self.connection(host_id)?;
        let started = Instant::now();
        let handle = connection.handle.lock().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        channel
            .exec(true, command)
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        drop(handle);
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut code = 0;
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => {
                    code = exit_status as i32;
                    break;
                }
                _ => {}
            }
        }
        Ok(ExecOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
            exit_code: code,
            duration_ms: started.elapsed().as_millis() as u64,
        })
    }

    pub async fn exec_with_input(&self, host_id: &str, command: &str, input: Option<&str>) -> AppResult<ExecOutput> {
        let connection = self.connection(host_id)?;
        let started = Instant::now();
        let handle = connection.handle.lock().await;
        let mut channel = handle.channel_open_session().await.map_err(|e| AppError::Ssh(e.to_string()))?;
        channel.exec(true, command).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        if let Some(value) = input { channel.data_bytes(format!("{value}\n")).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
        drop(handle);
        let mut stdout = Vec::new(); let mut stderr = Vec::new(); let mut code = 0;
        while let Some(message) = channel.wait().await { match message { ChannelMsg::Data { data } => stdout.extend_from_slice(&data), ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data), ChannelMsg::ExitStatus { exit_status } => { code = exit_status as i32; break; }, _ => {} } }
        Ok(ExecOutput { stdout: String::from_utf8_lossy(&stdout).into_owned(), stderr: String::from_utf8_lossy(&stderr).into_owned(), exit_code: code, duration_ms: started.elapsed().as_millis() as u64 })
    }

    pub async fn sftp_list(&self, host_id: &str, path: &str) -> AppResult<Vec<SftpEntry>> {
        validate_remote_path(path)?;
        let connection = self.connection(host_id)?;
        let handle = connection.handle.lock().await;
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        drop(handle);
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        let entries = sftp
            .read_dir(path)
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?
            .map(|entry| {
                let metadata = entry.metadata();
                let kind = if metadata.is_dir() {
                    "directory"
                } else if metadata.is_symlink() {
                    "symlink"
                } else {
                    "file"
                };
                SftpEntry {
                    name: entry.file_name(),
                    path: entry.path(),
                    kind: kind.into(),
                    size: metadata.len(),
                    modified_at: None,
                    permissions: Some(metadata.permissions().to_string()),
                }
            })
            .collect();
        let _ = sftp.close().await;
        Ok(entries)
    }

    pub async fn sftp_upload(
        self: &Arc<Self>,
        host_id: &str,
        local_paths: Vec<String>,
        remote_directory: &str,
        ipc: IpcChannel<StreamEnvelope<TransferProgress>>,
    ) -> AppResult<String> {
        if !self.is_connected(host_id) {
            return Err(AppError::Validation("SSH 尚未连接".into()));
        }
        validate_remote_path(remote_directory)?;
        if local_paths.is_empty() { return Err(AppError::Validation("没有选择要上传的文件或目录".into())); }
        let transfer_id = Uuid::new_v4().to_string();
        let (cancel, receiver) = watch::channel(false);
        self.transfers.write().insert(transfer_id.clone(), (host_id.into(), cancel));
        let manager = Arc::clone(self);
        let hid = host_id.to_string();
        let remote_dir = remote_directory.to_string();
        let id = transfer_id.clone();
        let slot = self.transfer_slot(host_id);
        tokio::spawn(async move {
            send_transfer_state(&manager.sequence, &ipc, &hid, &id, "queued", None);
            let mut receiver = receiver;
            let _permit = tokio::select! {
                permit = slot.acquire_owned() => permit.expect("transfer semaphore"),
                _ = receiver.changed() => {
                    send_transfer_state(&manager.sequence, &ipc, &hid, &id, "cancelled", None);
                    manager.transfers.write().remove(&id);
                    return;
                }
            };
            let result = run_upload_transfer(&manager, &hid, local_paths, &remote_dir, &id, ipc.clone(), receiver).await;
            if let Err(error) = result {
                send_transfer_state(&manager.sequence, &ipc, &hid, &id, "error", Some(error.to_string()));
            }
            manager.transfers.write().remove(&id);
        });
        Ok(transfer_id)
    }

    pub async fn sftp_download(
        self: &Arc<Self>,
        host_id: &str,
        remote_paths: Vec<String>,
        local_directory: &str,
        ipc: IpcChannel<StreamEnvelope<TransferProgress>>,
    ) -> AppResult<String> {
        if !self.is_connected(host_id) {
            return Err(AppError::Validation("SSH 尚未连接".into()));
        }
        if remote_paths.is_empty() { return Err(AppError::Validation("没有选择要下载的文件或目录".into())); }
        if local_directory.trim().is_empty() { return Err(AppError::Validation("本地下载目录无效".into())); }
        for path in &remote_paths { validate_remote_path(path)?; }
        let transfer_id = Uuid::new_v4().to_string();
        let (cancel, receiver) = watch::channel(false);
        self.transfers.write().insert(transfer_id.clone(), (host_id.into(), cancel));
        let manager = Arc::clone(self);
        let hid = host_id.to_string();
        let local_dir = local_directory.to_string();
        let id = transfer_id.clone();
        let slot = self.transfer_slot(host_id);
        tokio::spawn(async move {
            send_transfer_state(&manager.sequence, &ipc, &hid, &id, "queued", None);
            let mut receiver = receiver;
            let _permit = tokio::select! {
                permit = slot.acquire_owned() => permit.expect("transfer semaphore"),
                _ = receiver.changed() => {
                    send_transfer_state(&manager.sequence, &ipc, &hid, &id, "cancelled", None);
                    manager.transfers.write().remove(&id);
                    return;
                }
            };
            let result = run_download_transfer(&manager, &hid, remote_paths, &local_dir, &id, ipc.clone(), receiver).await;
            if let Err(error) = result {
                send_transfer_state(&manager.sequence, &ipc, &hid, &id, "error", Some(error.to_string()));
            }
            manager.transfers.write().remove(&id);
        });
        Ok(transfer_id)
    }

    pub async fn sftp_delete(&self, host_id: &str, paths: &[String]) -> AppResult<()> {
        let sftp = open_sftp(self, host_id).await?;
        for path in paths {
            validate_remote_path(path)?;
            let metadata = sftp.symlink_metadata(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
            if metadata.is_dir() && !metadata.is_symlink() { remove_remote_tree(&sftp, path).await?; }
            else { sftp.remove_file(path).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
        }
        let _ = sftp.close().await;
        Ok(())
    }

    pub async fn sftp_rename(&self, host_id: &str, path: &str, new_path: &str) -> AppResult<()> {
        validate_remote_path(path)?; validate_remote_path(new_path)?;
        let sftp = open_sftp(self, host_id).await?;
        sftp.rename(path, new_path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        let _ = sftp.close().await;
        Ok(())
    }

    pub async fn sftp_mkdir(&self, host_id: &str, path: &str) -> AppResult<()> {
        validate_remote_path(path)?;
        let sftp = open_sftp(self, host_id).await?;
        sftp.create_dir(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        let _ = sftp.close().await;
        Ok(())
    }

    pub async fn sftp_copy(self: &Arc<Self>, host_id: &str, sources: Vec<String>, destination: String, ipc: IpcChannel<StreamEnvelope<TransferProgress>>) -> AppResult<String> {
        if !self.is_connected(host_id) { return Err(AppError::Validation("SSH 尚未连接".into())); }
        validate_remote_path(&destination)?;
        if sources.is_empty() { return Err(AppError::Validation("没有选择要复制的远程项目".into())); }
        let destination_normalized = destination.trim_end_matches('/');
        for source in &sources {
            validate_remote_copy_target(source, if destination_normalized.is_empty() { "/" } else { destination_normalized })?;
        }
        let id = Uuid::new_v4().to_string(); let (cancel, mut receiver) = watch::channel(false);
        self.transfers.write().insert(id.clone(), (host_id.into(), cancel));
        let manager = Arc::clone(self); let hid = host_id.to_string(); let tid = id.clone();
        let slot = self.transfer_slot(host_id);
        tokio::spawn(async move {
            send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "queued", None);
            let _permit = tokio::select! {
                permit = slot.acquire_owned() => permit.expect("transfer semaphore"),
                _ = receiver.changed() => {
                    send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "cancelled", None);
                    manager.transfers.write().remove(&tid);
                    return;
                }
            };
            let result = async {
                let sftp = open_sftp(&manager, &hid).await?;
                ensure_remote_directory(&sftp, &destination).await?;
                let mut files = Vec::new(); for source in &sources { collect_remote_files(&sftp, source, &destination, &mut files).await?; }
                let total = files.iter().map(|(_,_,size)| *size).sum::<u64>(); let mut transferred = 0u64;
                for (index, (source, target, size)) in files.iter().enumerate() {
                    if cancelled(&receiver) { let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "cancelled", None); return Ok::<(), AppError>(()); }
                    let mut input = sftp.open(source).await.map_err(|e| AppError::Ssh(e.to_string()))?; let mut output = sftp.create(target).await.map_err(|e| AppError::Ssh(e.to_string()))?; let mut buf = vec![0u8; 64 * 1024]; let mut current = 0u64; let mut last_emit = Instant::now() - Duration::from_secs(1);
                    loop { if cancelled(&receiver) { let _ = output.close().await; let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "cancelled", None); return Ok(()); } let n = input.read(&mut buf).await.map_err(|e| AppError::Ssh(e.to_string()))?; if n == 0 { break; } output.write_all(&buf[..n]).await.map_err(|e| AppError::Ssh(e.to_string()))?; current += n as u64; transferred += n as u64; if last_emit.elapsed() >= Duration::from_millis(120) || current == *size { last_emit = Instant::now(); let _ = ipc.send(StreamEnvelope { seq: manager.sequence.fetch_add(1, Ordering::Relaxed), timestamp: chrono::Utc::now().to_rfc3339(), host_id: hid.clone(), session_id: None, payload: TransferProgress { transfer_id: tid.clone(), host_id: hid.clone(), direction: "transfer".into(), current_path: source.clone(), transferred, total, status: "running".into(), error: None, file_index: index as u32 + 1, file_count: files.len() as u32, current_file_transferred: current, current_file_total: *size } }); } }
                    output.flush().await.map_err(|e| AppError::Ssh(e.to_string()))?; output.close().await.map_err(|e| AppError::Ssh(e.to_string()))?;
                }
                let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "completed", None); Ok(())
            }.await;
            if let Err(error) = result { send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "error", Some(error.to_string())); }
            manager.transfers.write().remove(&tid);
        });
        Ok(id)
    }

    pub async fn terminal_open(
        &self,
        host_id: &str,
        cols: u32,
        rows: u32,
        ipc: IpcChannel<StreamEnvelope<Vec<u8>>>,
        command_logging: bool,
        audit_sender: mpsc::UnboundedSender<TerminalAuditEvent>,
    ) -> AppResult<String> {
        let connection = self.connection(host_id)?;
        let handle = connection.handle.lock().await;
        let mut channel = handle
            .channel_open_session()
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        channel
            .request_pty(
                false,
                "xterm-256color",
                cols,
                rows,
                0,
                0,
                if command_logging { &[(Pty::ECHO, 0)] } else { &[] },
            )
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        channel
            .request_shell(true)
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
        drop(handle);
        let session_id = Uuid::new_v4().to_string();
        let (sender, mut receiver) = mpsc::channel::<TerminalCommand>(256);
        self.terminals.write().insert(
            session_id.clone(),
            ManagedTerminal {
                host_id: host_id.to_string(),
                sender,
            },
        );
        let id = session_id.clone();
        let hid = host_id.to_string();
        let sequence = self.sequence.clone();
        let mut writer = channel.make_writer();
        if command_logging {
            writer.write_all(SHELL_AUDIT_BOOTSTRAP.as_bytes()).await.map_err(AppError::Io)?;
            // The bootstrap is an interactive shell command and must be submitted.
            writer.write_all(b"\n").await.map_err(AppError::Io)?;
            writer.flush().await.map_err(AppError::Io)?;
        }
        tokio::spawn(async move {
            let mut audit_parser = TerminalAuditParser::default();
            loop {
                tokio::select! {
                    command=receiver.recv()=>match command {
                        Some(TerminalCommand::Input(data))=>{ if writer.write_all(&data).await.is_err(){break;} let _=writer.flush().await; },
                        Some(TerminalCommand::Resize(cols, rows))=>{ let _=channel.window_change(cols, rows, 0, 0).await; },
                        Some(TerminalCommand::Close)|None=>break
                    },
                    message=channel.wait()=>match message {
                        Some(ChannelMsg::Data{data})|Some(ChannelMsg::ExtendedData{data,..})=>{
                            let (visible, audits) = if command_logging { audit_parser.push(&data) } else { (data.to_vec(), Vec::new()) };
                            if !visible.is_empty() { let _=ipc.send(StreamEnvelope{seq:sequence.fetch_add(1,Ordering::Relaxed),timestamp:chrono::Utc::now().to_rfc3339(),host_id:hid.clone(),session_id:Some(id.clone()),payload:visible}); }
                            for audit in audits { let _ = audit_sender.send(TerminalAuditEvent { session_id: id.clone(), host_id: hid.clone(), command: audit.command, exit_code: audit.exit_code, timestamp: chrono::Utc::now().to_rfc3339() }); }
                        },
                        Some(ChannelMsg::ExitStatus{..})|None=>break,
                        _=>{}
                    }
                }
            }
            if command_logging { let remaining = audit_parser.finish(); if !remaining.is_empty() { let _=ipc.send(StreamEnvelope{seq:sequence.fetch_add(1,Ordering::Relaxed),timestamp:chrono::Utc::now().to_rfc3339(),host_id:hid,session_id:Some(id),payload:remaining}); } }
        });
        Ok(session_id)
    }
    pub async fn terminal_input(&self, session_id: &str, data: Vec<u8>) -> AppResult<()> {
        let sender = self
            .terminals
            .read()
            .get(session_id)
            .map(|t| t.sender.clone())
            .ok_or_else(|| AppError::NotFound("终端会话".into()))?;
        sender
            .send(TerminalCommand::Input(data))
            .await
            .map_err(|_| AppError::Ssh("终端已关闭".into()))
    }
    pub async fn terminal_resize(&self, session_id: &str, cols: u32, rows: u32) -> AppResult<()> {
        let sender = self.terminals.read().get(session_id).map(|terminal| terminal.sender.clone()).ok_or_else(|| AppError::NotFound("终端会话".into()))?;
        sender.send(TerminalCommand::Resize(cols, rows)).await.map_err(|_| AppError::Ssh("终端已关闭".into()))
    }
    pub async fn terminal_close(&self, session_id: &str) -> AppResult<()> {
        let terminal = { self.terminals.write().remove(session_id) };
        if let Some(terminal) = terminal {
            let _ = terminal.sender.send(TerminalCommand::Close).await;
        }
        Ok(())
    }
    pub fn profile(&self, host_id: &str) -> AppResult<HostProfile> {
        Ok(self.connection(host_id)?.profile.clone())
    }

    pub async fn forward_start(&self, profile: &crate::models::ForwardingProfile) -> AppResult<()> {
        if profile.kind == "remote" {
            return Err(AppError::Validation(
                "远程转发需要服务器端回调支持，当前连接不允许该类型".into(),
            ));
        }
        let connection = self.connection(&profile.host_id)?;
        let listener = TcpListener::bind((profile.bind_address.as_str(), profile.bind_port))
            .await
            .map_err(|e| AppError::Io(e))?;
        let (cancel, mut cancelled) = watch::channel(false);
        self.forward_stop(&profile.id);
        self.forwards.write().insert(profile.id.clone(), cancel);
        let id = profile.id.clone();
        let kind = profile.kind.clone();
        let target_host = profile.target_host.clone().unwrap_or_default();
        let target_port = profile.target_port.unwrap_or(0);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancelled.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((mut local, _)) = accepted else { break; };
                        let connection = connection.clone();
                        let target_host = target_host.clone();
                        let kind = kind.clone();
                        tokio::spawn(async move {
                            if kind == "dynamic" {
                                if let Ok((host, port)) = socks5_connect(&mut local).await {
                                    let _ = local.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                                    let _ = bridge_tcp(connection, &mut local, &host, port).await;
                                }
                            } else {
                                let _ = bridge_tcp(connection, &mut local, &target_host, target_port).await;
                            }
                        });
                    }
                }
            }
            let _ = id;
        });
        Ok(())
    }

    pub fn forward_stop(&self, id: &str) {
        if let Some(cancel) = self.forwards.write().remove(id) {
            let _ = cancel.send(true);
        }
    }
}

async fn open_sftp(manager: &SshManager, host_id: &str) -> AppResult<SftpSession> {
    let connection = manager.connection(host_id)?;
    let handle = connection.handle.lock().await;
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| AppError::Ssh(e.to_string()))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| AppError::Ssh(e.to_string()))?;
    drop(handle);
    SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| AppError::Ssh(e.to_string()))
}

fn validate_remote_path(path: &str) -> AppResult<()> {
    if path.is_empty() || path.contains('\0') || path.contains('\n') || path.contains('\r') || path.split('/').any(|part| part == "..") { return Err(AppError::Validation("远程路径无效".into())); }
    Ok(())
}

async fn remove_remote_tree(sftp: &SftpSession, path: &str) -> AppResult<()> {
    let metadata = sftp.symlink_metadata(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    if metadata.is_symlink() {
        sftp.remove_file(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        return Ok(());
    }
    if metadata.is_dir() {
        let entries = sftp.read_dir(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        for entry in entries { let child = entry.path(); let child_meta = entry.metadata(); if child_meta.is_dir() && !child_meta.is_symlink() { Box::pin(remove_remote_tree(sftp, &child)).await?; } else { sftp.remove_file(&child).await.map_err(|e| AppError::Ssh(e.to_string()))?; } }
        sftp.remove_dir(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    } else { sftp.remove_file(path).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
    Ok(())
}

async fn collect_remote_files(sftp: &SftpSession, source: &str, destination: &str, files: &mut Vec<(String, String, u64)>) -> AppResult<()> {
    validate_remote_path(source)?; validate_remote_path(destination)?;
    let metadata = sftp.symlink_metadata(source).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    let name = source.rsplit('/').find(|v| !v.is_empty()).unwrap_or("item"); let target_root = format!("{}/{}", destination.trim_end_matches('/'), name);
    if metadata.is_symlink() { return Ok(()); }
    if metadata.is_dir() {
        ensure_remote_directory(sftp, &target_root).await?;
        let entries = sftp.read_dir(source).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        for entry in entries { let child = entry.path(); let child_target = join_remote_path(&target_root, &entry.file_name()); if entry.metadata().is_dir() && !entry.metadata().is_symlink() { Box::pin(collect_remote_files(sftp, &child, &target_root, files)).await?; } else if !entry.metadata().is_symlink() { files.push((child, child_target, entry.metadata().len())); } }
    } else { files.push((source.into(), target_root, metadata.len())); }
    Ok(())
}

#[derive(Debug, Default)]
struct LocalUploadPlan {
    directories: Vec<String>,
    files: Vec<(PathBuf, String)>,
}

fn join_remote_path(base: &str, name: &str) -> String {
    if base == "/" { format!("/{name}") } else { format!("{}/{}", base.trim_end_matches('/'), name) }
}

fn collect_local_files(paths: &[String], remote_directory: &str) -> AppResult<LocalUploadPlan> {
    validate_remote_path(remote_directory)?;
    let mut plan = LocalUploadPlan::default();
    let mut stack = paths.iter().map(|p| (PathBuf::from(p), remote_directory.to_string())).collect::<Vec<_>>();
    while let Some((path, remote_base)) = stack.pop() {
        let metadata = std::fs::symlink_metadata(&path).map_err(AppError::Io)?;
        if metadata.file_type().is_symlink() { continue; }
        let name = path.file_name().and_then(|v| v.to_str()).unwrap_or("file");
        let remote = join_remote_path(&remote_base, name);
        if metadata.is_file() { plan.files.push((path, remote)); }
        else if metadata.is_dir() {
            plan.directories.push(remote.clone());
            for entry in std::fs::read_dir(&path).map_err(AppError::Io)? {
                let entry = entry.map_err(AppError::Io)?;
                stack.push((entry.path(), remote.clone()));
            }
        }
    }
    plan.directories.sort_by_key(|path| path.matches('/').count());
    plan.directories.dedup();
    Ok(plan)
}

async fn ensure_remote_directory(sftp: &SftpSession, path: &str) -> AppResult<()> {
    validate_remote_path(path)?;
    let absolute = path.starts_with('/');
    let mut current = if absolute { "/".to_string() } else { String::new() };
    for component in path.split('/').filter(|part| !part.is_empty()) {
        current = join_remote_path(if current.is_empty() { "." } else { &current }, component);
        if current.starts_with("./") { current = current[2..].to_string(); }
        match sftp.symlink_metadata(&current).await {
            Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {}
            Ok(_) => return Err(AppError::Validation(format!("远程路径不是目录：{current}"))),
            Err(_) => sftp.create_dir(&current).await.map_err(|error| AppError::Ssh(error.to_string()))?,
        }
    }
    Ok(())
}

fn send_transfer_state(sequence: &Arc<AtomicU64>, ipc: &IpcChannel<StreamEnvelope<TransferProgress>>, host_id: &str, transfer_id: &str, status: &str, error: Option<String>) {
    let _ = ipc.send(StreamEnvelope {
        seq: sequence.fetch_add(1, Ordering::Relaxed),
        timestamp: chrono::Utc::now().to_rfc3339(),
        host_id: host_id.into(),
        session_id: None,
        payload: TransferProgress {
            transfer_id: transfer_id.into(), host_id: host_id.into(), direction: "transfer".into(), current_path: String::new(), transferred: 0, total: 0, status: status.into(), error, file_index: 0, file_count: 0, current_file_transferred: 0, current_file_total: 0,
        },
    });
}

fn cancelled(receiver: &watch::Receiver<bool>) -> bool { *receiver.borrow() }

async fn run_upload_transfer(manager: &SshManager, host_id: &str, local_paths: Vec<String>, remote_directory: &str, transfer_id: &str, ipc: IpcChannel<StreamEnvelope<TransferProgress>>, mut cancel: watch::Receiver<bool>) -> AppResult<()> {
    if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
    let scan_remote_directory = remote_directory.to_string();
    let plan = tokio::task::spawn_blocking(move || collect_local_files(&local_paths, &scan_remote_directory)).await.map_err(|error| AppError::Other(error.to_string()))??;
    if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
    let total = plan.files.iter().filter_map(|(path, _)| std::fs::metadata(path).ok().map(|m| m.len())).sum::<u64>();
    let sftp = open_sftp(manager, host_id).await?;
    ensure_remote_directory(&sftp, remote_directory).await?;
    for directory in &plan.directories {
        if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); let _ = sftp.close().await; return Ok(()); }
        ensure_remote_directory(&sftp, directory).await?;
    }
    let mut transferred = 0u64;
    for (index, (local, remote)) in plan.files.iter().enumerate() {
        if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); let _ = sftp.close().await; return Ok(()); }
        if let Some(parent) = remote.rsplit_once('/').map(|x| x.0).filter(|value| !value.is_empty()) { ensure_remote_directory(&sftp, parent).await?; }
        let file_total = std::fs::metadata(local).map(|m| m.len()).unwrap_or(0);
        let was_cancelled = upload_file_cancelled(&sftp, local, remote, host_id, transfer_id, total, &mut transferred, file_total, index as u32 + 1, plan.files.len() as u32, &ipc, &mut cancel, &manager.sequence).await?;
        if was_cancelled { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); let _ = sftp.close().await; return Ok(()); }
    }
    let _ = sftp.close().await;
    send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "completed", None);
    Ok(())
}

async fn upload_file_cancelled(sftp: &SftpSession, local: &Path, remote: &str, host_id: &str, transfer_id: &str, total: u64, transferred: &mut u64, file_total: u64, file_index: u32, file_count: u32, ipc: &IpcChannel<StreamEnvelope<TransferProgress>>, cancel: &mut watch::Receiver<bool>, sequence: &Arc<AtomicU64>) -> AppResult<bool> {
    let mut input = tokio::fs::File::open(local).await.map_err(AppError::Io)?;
    let mut output = sftp.create(remote).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    let mut buffer = vec![0u8; 64 * 1024]; let mut current = 0u64; let mut last_emit = Instant::now() - Duration::from_secs(1);
    loop {
        if cancelled(cancel) { let _ = output.close().await; return Ok(true); }
        let n = tokio::select! {
            _ = cancel.changed() => { let _ = output.close().await; return Ok(true); }
            result = input.read(&mut buffer) => result.map_err(AppError::Io)?,
        };
        if n == 0 { break; }
        tokio::select! {
            _ = cancel.changed() => { let _ = output.close().await; return Ok(true); }
            result = output.write_all(&buffer[..n]) => result.map_err(|e| AppError::Ssh(e.to_string()))?,
        }
        current += n as u64; *transferred += n as u64;
        if last_emit.elapsed() >= Duration::from_millis(120) || current == file_total { last_emit = Instant::now(); let _ = ipc.send(StreamEnvelope { seq: sequence.fetch_add(1, Ordering::Relaxed), timestamp: chrono::Utc::now().to_rfc3339(), host_id: host_id.into(), session_id: None, payload: TransferProgress { transfer_id: transfer_id.into(), host_id: host_id.into(), direction: "upload".into(), current_path: local.display().to_string(), transferred: *transferred, total, status: "running".into(), error: None, file_index, file_count, current_file_transferred: current, current_file_total: file_total } }); }
    }
    output.flush().await.map_err(|e| AppError::Ssh(e.to_string()))?; output.close().await.map_err(|e| AppError::Ssh(e.to_string()))?; Ok(false)
}

#[derive(Debug, Default)]
struct RemoteDownloadPlan {
    directories: Vec<PathBuf>,
    files: Vec<(String, PathBuf, u64)>,
}

fn safe_remote_name(path: &str) -> AppResult<&str> {
    let name = path.rsplit('/').find(|part| !part.is_empty()).unwrap_or("download");
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') || name.contains('\0') {
        return Err(AppError::Validation("远程文件名无法安全保存到本地".into()));
    }
    Ok(name)
}

fn validate_remote_copy_target(source: &str, destination: &str) -> AppResult<()> {
    validate_remote_path(source)?;
    validate_remote_path(destination)?;
    let source_normalized = source.trim_end_matches('/');
    let target = join_remote_path(destination, safe_remote_name(source)?);
    if target == source_normalized || target.starts_with(&format!("{source_normalized}/")) {
        return Err(AppError::Validation("不能将远程文件或目录复制到自身内部".into()));
    }
    Ok(())
}

async fn collect_remote_download(sftp: &SftpSession, source: &str, relative: PathBuf, plan: &mut RemoteDownloadPlan) -> AppResult<()> {
    validate_remote_path(source)?;
    let metadata = sftp.symlink_metadata(source).await.map_err(|error| AppError::Ssh(error.to_string()))?;
    if metadata.is_symlink() { return Ok(()); }
    let target = relative.join(safe_remote_name(source)?);
    if metadata.is_dir() {
        plan.directories.push(target.clone());
        let entries = sftp.read_dir(source).await.map_err(|error| AppError::Ssh(error.to_string()))?;
        for entry in entries {
            let name = entry.file_name();
            safe_remote_name(&name)?;
            Box::pin(collect_remote_download(sftp, &entry.path(), target.clone(), plan)).await?;
        }
    } else {
        plan.files.push((source.to_string(), target, metadata.len()));
    }
    Ok(())
}

async fn run_download_transfer(manager: &SshManager, host_id: &str, remote_paths: Vec<String>, local_directory: &str, transfer_id: &str, ipc: IpcChannel<StreamEnvelope<TransferProgress>>, mut cancel: watch::Receiver<bool>) -> AppResult<()> {
    tokio::fs::create_dir_all(local_directory).await.map_err(AppError::Io)?;
    let sftp = open_sftp(manager, host_id).await?;
    let mut plan = RemoteDownloadPlan::default();
    for path in &remote_paths { collect_remote_download(&sftp, path, PathBuf::new(), &mut plan).await?; }
    let total = plan.files.iter().map(|(_, _, size)| *size).sum::<u64>();
    for directory in &plan.directories {
        tokio::fs::create_dir_all(PathBuf::from(local_directory).join(directory)).await.map_err(AppError::Io)?;
    }
    let mut transferred = 0u64;
    for (index, (remote_path, relative, file_total)) in plan.files.iter().enumerate() {
        if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); let _ = sftp.close().await; return Ok(()); }
        let local = PathBuf::from(local_directory).join(relative);
        if let Some(parent) = local.parent() { tokio::fs::create_dir_all(parent).await.map_err(AppError::Io)?; }
        let part = PathBuf::from(format!("{}.part", local.display()));
        let mut input = sftp.open(remote_path).await.map_err(|e| AppError::Ssh(e.to_string()))?; let output = tokio::fs::File::create(&part).await.map_err(AppError::Io); let mut output = match output { Ok(v) => v, Err(e) => { let _ = sftp.close().await; return Err(e); } };
        let mut current = 0u64; let mut buffer = vec![0u8; 64 * 1024]; let mut last_emit = Instant::now() - Duration::from_secs(1);
        loop {
            if cancelled(&cancel) { output.flush().await.map_err(AppError::Io)?; drop(output); let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
            let n = tokio::select! {
                _ = cancel.changed() => { output.flush().await.map_err(AppError::Io)?; drop(output); let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
                result = input.read(&mut buffer) => result.map_err(|e| AppError::Ssh(e.to_string()))?,
            };
            if n == 0 { break; }
            tokio::select! {
                _ = cancel.changed() => { output.flush().await.map_err(AppError::Io)?; drop(output); let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
                result = output.write_all(&buffer[..n]) => result.map_err(AppError::Io)?,
            }
            current += n as u64; transferred += n as u64;
            if last_emit.elapsed() >= Duration::from_millis(120) || current == *file_total { last_emit = Instant::now(); let _ = ipc.send(StreamEnvelope { seq: manager.sequence.fetch_add(1, Ordering::Relaxed), timestamp: chrono::Utc::now().to_rfc3339(), host_id: host_id.into(), session_id: None, payload: TransferProgress { transfer_id: transfer_id.into(), host_id: host_id.into(), direction: "download".into(), current_path: remote_path.clone(), transferred, total, status: "running".into(), error: None, file_index: index as u32 + 1, file_count: plan.files.len() as u32, current_file_transferred: current, current_file_total: *file_total } }); }
        }
        output.flush().await.map_err(AppError::Io)?; drop(output);
        if tokio::fs::try_exists(&local).await.map_err(AppError::Io)? { tokio::fs::remove_file(&local).await.map_err(AppError::Io)?; }
        tokio::fs::rename(&part, &local).await.map_err(AppError::Io)?;
    }
    let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "completed", None); Ok(())
}

async fn bridge_tcp(
    connection: Arc<ManagedConnection>,
    local: &mut TcpStream,
    host: &str,
    port: u16,
) -> AppResult<()> {
    let handle = connection.handle.lock().await;
    let channel = handle
        .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
        .await
        .map_err(|e| AppError::Ssh(e.to_string()))?;
    drop(handle);
    let mut remote = channel.into_stream();
    tokio::io::copy_bidirectional(local, &mut remote)
        .await
        .map_err(AppError::Io)?;
    Ok(())
}

async fn socks5_connect(stream: &mut TcpStream) -> AppResult<(String, u16)> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.map_err(AppError::Io)?;
    if header[0] != 5 {
        return Err(AppError::Validation("仅支持 SOCKS5".into()));
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(AppError::Io)?;
    stream.write_all(&[5, 0]).await.map_err(AppError::Io)?;
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await.map_err(AppError::Io)?;
    if req[0] != 5 || req[1] != 1 {
        return Err(AppError::Validation("仅支持 SOCKS5 CONNECT".into()));
    }
    let host = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await.map_err(AppError::Io)?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).await.map_err(AppError::Io)?;
            let mut b = vec![0; n[0] as usize];
            stream.read_exact(&mut b).await.map_err(AppError::Io)?;
            String::from_utf8(b).map_err(|_| AppError::Validation("域名无效".into()))?
        }
        _ => return Err(AppError::Validation("不支持的 SOCKS5 地址类型".into())),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await.map_err(AppError::Io)?;
    Ok((host, u16::from_be_bytes(port)))
}

#[cfg(test)]
mod terminal_audit_tests {
    use super::*;

    fn marker(status: i32, command: &str) -> Vec<u8> {
        format!("\x1b]777;sshops;{};{}\x07", status, BASE64_STANDARD.encode(command)).into_bytes()
    }

    #[test]
    fn parses_marker_split_across_ssh_packets_and_preserves_visible_output() {
        let frame = marker(0, "sudo apt update");
        let split = frame.len() / 2;
        let mut parser = TerminalAuditParser::default();
        let (first_visible, first_audits) = parser.push(&[b"prompt> ".as_slice(), &frame[..split]].concat());
        assert_eq!(first_visible, b"prompt> ");
        assert!(first_audits.is_empty());
        let (second_visible, second_audits) = parser.push(&[&frame[split..], b"next prompt".as_slice()].concat());
        assert_eq!(second_visible, b"next prompt");
        assert_eq!(second_audits, vec![ParsedTerminalAudit { command: "sudo apt update".into(), exit_code: 0 }]);
    }

    #[test]
    fn preserves_the_first_command_field_and_unicode() {
        let mut parser = TerminalAuditParser::default();
        let (_, audits) = parser.push(&marker(7, "printf '中文参数' | sed s/参数/命令/"));
        assert_eq!(audits[0].command, "printf '中文参数' | sed s/参数/命令/");
        assert_eq!(audits[0].exit_code, 7);
    }

    #[test]
    fn leaves_unrelated_osc_sequences_visible() {
        let mut parser = TerminalAuditParser::default();
        let input = b"\x1b]0;window title\x07hello";
        let (visible, audits) = parser.push(input);
        assert_eq!(visible, input);
        assert!(audits.is_empty());
    }

    #[test]
    fn audit_bootstrap_does_not_clear_the_login_banner_or_replay_sudo_history() {
        assert!(!SHELL_AUDIT_BOOTSTRAP.contains("[2J"));
        assert!(!SHELL_AUDIT_BOOTSTRAP.contains("sudo su"));
        assert!(SHELL_AUDIT_BOOTSTRAP.contains("__sshops_ready"));
    }

    #[test]
    fn local_upload_plan_keeps_nested_and_empty_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("folder");
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::create_dir_all(root.join("empty")).unwrap();
        std::fs::write(root.join("nested").join("file.txt"), b"data").unwrap();
        let plan = collect_local_files(&[root.display().to_string()], "/remote").unwrap();
        assert!(plan.directories.contains(&"/remote/folder".to_string()));
        assert!(plan.directories.contains(&"/remote/folder/empty".to_string()));
        assert!(plan.directories.contains(&"/remote/folder/nested".to_string()));
        assert!(plan.files.iter().any(|(_, remote)| remote == "/remote/folder/nested/file.txt"));
    }

    #[test]
    fn remote_copy_rejects_the_same_path_and_descendants() {
        assert!(validate_remote_copy_target("/srv/data", "/srv").is_err());
        assert!(validate_remote_copy_target("/srv/data", "/srv/data/subdir").is_err());
        assert!(validate_remote_copy_target("/srv/data", "/backup").is_ok());
    }
}
