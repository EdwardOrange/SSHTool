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
    keys::{self, PrivateKeyWithHashAlg, ssh_key, agent::client::AgentClient},
};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tauri::ipc::Channel as IpcChannel;
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch, Semaphore},
    time::timeout,
};
use std::io::SeekFrom;
use uuid::Uuid;

#[cfg(test)]
#[path = "ssh_review_tests.rs"]
mod review_tests;

#[derive(Clone)]
struct ClientHandler {
    expected: Option<String>,
    accept_unknown: bool,
    observed: Arc<Mutex<Option<String>>>,
    remote_sender: mpsc::UnboundedSender<RemoteForwardChannel>,
}

struct RemoteForwardChannel {
    channel: russh::Channel<client::Msg>,
    connected_port: u32,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;
    async fn check_server_key(&mut self, key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        let fingerprint = key.fingerprint(ssh_key::HashAlg::Sha256).to_string();
        *self.observed.lock().await = Some(fingerprint.clone());
        Ok(self.expected.as_ref().map(|known| known == &fingerprint).unwrap_or(self.accept_unknown))
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<client::Msg>,
        _connected_address: &str,
        connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        reply: client::ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.remote_sender.send(RemoteForwardChannel { channel, connected_port }).map_err(|_| russh::Error::SendError)
    }
}

type SshHandle = client::Handle<ClientHandler>;
struct ManagedConnection {
    handle: Arc<Mutex<SshHandle>>,
    profile: HostProfile,
    verification_password: Option<zeroize::Zeroizing<String>>,
    remote_receiver: Arc<Mutex<mpsc::UnboundedReceiver<RemoteForwardChannel>>>,
}

enum TerminalCommand {
    Input(Vec<u8>),
    Resize(u32, u32),
}
struct ManagedTerminal {
    host_id: String,
    sender: mpsc::Sender<TerminalCommand>,
    cancel: watch::Sender<bool>,
    audit_enabled: Arc<AtomicBool>,
    audit_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalAuditEvent {
    pub session_id: String,
    pub host_id: String,
    pub sequence: u64,
    pub kind: TerminalAuditEventKind,
    pub timestamp: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalAuditEventKind {
    Ready { shell: String },
    Command { command: String, exit_code: i32 },
    Unavailable { reason: String },
}

const AUDIT_PREFIX: &[u8] = b"\x1b]777;sshops;";
const AUDIT_VERSION: &str = "v1";
const SHELL_AUDIT_BOOTSTRAP_TEMPLATE: &str = r#"__sshops_nonce='__NONCE__'; __sshops_notice=''; __sshops_seq=0; __sshops_pending=''; __sshops_last_line=''; __sshops_executed=0; __sshops_ready=0; __sshops_internal=1; if command -v base64 >/dev/null 2>&1; then __sshops_emit(){ local __sshops_kind="$1" __sshops_status="$2" __sshops_data="$3" __sshops_payload; __sshops_seq=$((__sshops_seq+1)); __sshops_payload=$(printf '%s' "$__sshops_data" | base64 | tr -d '\r\n'); printf '\033]777;sshops;v1;%s;%s;%s;%s;%s\007' "$__sshops_nonce" "$__sshops_kind" "$__sshops_seq" "$__sshops_status" "$__sshops_payload"; }; __sshops_ignored(){ local __sshops_line="$1" __sshops_pattern; case ":${HISTCONTROL:-}:" in *:ignorespace:*|*:ignoreboth:*) case "$__sshops_line" in ' '*) return 0;; esac;; esac; if [ -n "${HISTIGNORE:-}" ]; then local IFS=':'; for __sshops_pattern in $HISTIGNORE; do if [ "$__sshops_pattern" = '&' ]; then [ "$__sshops_line" = "$__sshops_last_line" ] && return 0; elif [ -n "$__sshops_pattern" ] && [[ "$__sshops_line" == $__sshops_pattern ]]; then return 0; fi; done; fi; return 1; }; __sshops_clean_history(){ local __sshops_entry __sshops_number; __sshops_entry=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null) || return 0; case "$__sshops_entry" in *"$__sshops_nonce"*'__sshops_nonce='*) __sshops_entry="${__sshops_entry#"${__sshops_entry%%[![:space:]]*}"}"; __sshops_number="${__sshops_entry%%[!0-9]*}"; [ -n "$__sshops_number" ] && builtin history -d "$__sshops_number" 2>/dev/null || true;; esac; }; if [ -n "${BASH_VERSION:-}" ]; then __sshops_capture(){ local __sshops_line="${READLINE_LINE:-}" __sshops_expanded; __sshops_clean_history; __sshops_expanded=$(builtin history -p "$__sshops_line" 2>/dev/null) && [ -n "$__sshops_expanded" ] && __sshops_line="$__sshops_expanded"; if [ -n "$__sshops_line" ] && ! __sshops_ignored "$__sshops_line"; then __sshops_last_line="$__sshops_line"; if [ -n "$__sshops_pending" ]; then __sshops_pending="$__sshops_pending
$__sshops_line"; else __sshops_pending="$__sshops_line"; fi; fi; }; __sshops_debug(){ local __sshops_command="$1"; if [ "$__sshops_internal" = 0 ] && [ -n "$__sshops_pending" ]; then case "$__sshops_command" in __sshops_*|'builtin history'*|'bind '*) ;; *) __sshops_executed=1;; esac; fi; if [ -n "${__sshops_previous_debug:-}" ]; then eval -- "$__sshops_previous_debug"; fi; }; __sshops_precmd(){ local __sshops_status=$?; __sshops_internal=1; __sshops_clean_history; if [ "$__sshops_ready" = 0 ]; then __sshops_ready=1; __sshops_emit ready 0 bash; elif [ "$__sshops_executed" = 1 ] && [ -n "$__sshops_pending" ]; then __sshops_emit command "$__sshops_status" "$__sshops_pending"; fi; __sshops_pending=''; __sshops_executed=0; __sshops_internal=0; return "$__sshops_status"; }; __sshops_previous_debug=$(trap -p DEBUG); __sshops_previous_debug="${__sshops_previous_debug#trap -- \'}"; __sshops_previous_debug="${__sshops_previous_debug%\' DEBUG}"; bind -x '"\C-x\C-a":__sshops_capture' 2>/dev/null && bind '"\C-x\C-z":accept-line' 2>/dev/null && bind '"\C-j":"\C-x\C-a\C-x\C-z"' 2>/dev/null && bind '"\C-m":"\C-x\C-a\C-x\C-z"' 2>/dev/null || __sshops_notice='[SSH Ops] Bash command audit is unavailable'; if [ -z "$__sshops_notice" ]; then trap '__sshops_debug "$BASH_COMMAND"' DEBUG; if [[ $(declare -p PROMPT_COMMAND 2>/dev/null) == 'declare -a'* ]]; then PROMPT_COMMAND+=(__sshops_precmd); else PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }__sshops_precmd"; fi; fi; elif [ -n "${ZSH_VERSION:-}" ]; then autoload -Uz add-zsh-hook 2>/dev/null; __sshops_preexec(){ __sshops_pending="$1"; __sshops_executed=1; }; __sshops_precmd(){ local __sshops_status=$?; if [ "$__sshops_ready" = 0 ]; then __sshops_ready=1; __sshops_emit ready 0 zsh; elif [ "$__sshops_executed" = 1 ] && [ -n "$__sshops_pending" ]; then __sshops_emit command "$__sshops_status" "$__sshops_pending"; fi; __sshops_pending=''; __sshops_executed=0; return "$__sshops_status"; }; if ! add-zsh-hook preexec __sshops_preexec 2>/dev/null || ! add-zsh-hook precmd __sshops_precmd 2>/dev/null; then __sshops_notice='[SSH Ops] Zsh command audit is unavailable'; fi; else __sshops_notice='[SSH Ops] Command audit supports Bash and Zsh only'; fi; if [ -n "$__sshops_notice" ]; then __sshops_emit unavailable 0 "$__sshops_notice"; fi; else __sshops_notice='[SSH Ops] Command audit requires base64'; __sshops_seq=1; printf '\033]777;sshops;v1;%s;unavailable;1;0;W1NTSCBPcHNdIENvbW1hbmQgYXVkaXQgcmVxdWlyZXMgYmFzZTY0\007' "$__sshops_nonce"; fi; __sshops_internal=0; stty echo 2>/dev/null; [ -n "$__sshops_notice" ] && printf '\033[33m%s\033[0m\r\n' "$__sshops_notice""#;

fn shell_audit_bootstrap(nonce: &str) -> String {
    SHELL_AUDIT_BOOTSTRAP_TEMPLATE.replace("__NONCE__", nonce)
}

struct TerminalAuditParser {
    pending: Vec<u8>,
    expected_nonce: String,
    ready: bool,
    settled: bool,
    last_sequence: u64,
}

impl TerminalAuditParser {
    fn new(expected_nonce: String) -> Self {
        Self { pending: Vec::new(), expected_nonce, ready: false, settled: false, last_sequence: 0 }
    }

    fn push(&mut self, data: &[u8]) -> (Vec<u8>, Vec<(u64, TerminalAuditEventKind)>) {
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
            let Some((nonce, sequence, kind)) = parse_audit_frame(&frame) else { continue };
            if nonce != self.expected_nonce || sequence <= self.last_sequence { continue; }
            if matches!(&kind, TerminalAuditEventKind::Command { .. }) && !self.ready { continue; }
            self.last_sequence = sequence;
            match &kind {
                TerminalAuditEventKind::Ready { .. } => {
                    self.ready = true;
                    self.settled = true;
                }
                TerminalAuditEventKind::Unavailable { .. } => self.settled = true,
                TerminalAuditEventKind::Command { command, .. } if is_internal_audit_command(command, &self.expected_nonce) => continue,
                TerminalAuditEventKind::Command { .. } => {}
            }
            audits.push((sequence, kind));
        }
        (visible, audits)
    }

    fn finish(&mut self) -> Vec<u8> { std::mem::take(&mut self.pending) }

    fn settled(&self) -> bool { self.settled }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> { haystack.windows(needle.len()).position(|window| window == needle) }
fn partial_prefix_len(data: &[u8], prefix: &[u8]) -> usize { (1..prefix.len().min(data.len() + 1)).rev().find(|length| data.ends_with(&prefix[..*length])).unwrap_or(0) }
fn parse_audit_frame(frame: &[u8]) -> Option<(String, u64, TerminalAuditEventKind)> {
    let frame = std::str::from_utf8(frame).ok()?;
    let mut fields = frame.splitn(6, ';');
    if fields.next()? != AUDIT_VERSION { return None; }
    let nonce = fields.next()?.to_string();
    if nonce.len() < 16 || nonce.len() > 64 || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) { return None; }
    let event_kind = fields.next()?;
    let sequence = fields.next()?.parse().ok()?;
    let exit_code = fields.next()?.parse().ok()?;
    let payload = String::from_utf8(BASE64_STANDARD.decode(fields.next()?).ok()?).ok()?;
    if payload.len() > 10_000 { return None; }
    let kind = match event_kind {
        "ready" if !payload.trim().is_empty() => TerminalAuditEventKind::Ready { shell: payload },
        "command" if !payload.trim().is_empty() => TerminalAuditEventKind::Command { command: payload, exit_code },
        "unavailable" if !payload.trim().is_empty() => TerminalAuditEventKind::Unavailable { reason: payload },
        _ => return None,
    };
    Some((nonce, sequence, kind))
}

fn is_internal_audit_command(command: &str, nonce: &str) -> bool {
    command.contains(nonce)
        || command.trim_start().starts_with("__sshops_")
        || (command.contains("__sshops_nonce=") && command.contains("__sshops_emit"))
}

pub struct SshManager {
    sessions: RwLock<HashMap<String, Arc<ManagedConnection>>>,
    pending_host_keys: RwLock<HashMap<String, (String, String)>>,
    connection_locks: RwLock<HashMap<String, Arc<Mutex<()>>>>,
    forward_lock: Mutex<()>,
    terminals: RwLock<HashMap<String, ManagedTerminal>>,
    forwards: RwLock<HashMap<String, ManagedForward>>,
    transfers: RwLock<HashMap<String, (String, watch::Sender<bool>)>>,
    transfer_slots: RwLock<HashMap<String, Arc<Semaphore>>>,
    sequence: Arc<AtomicU64>,
}

struct ManagedForward {
    host_id: String,
    cancel: watch::Sender<bool>,
    remote: Option<(String, u32)>,
    task: tokio::task::JoinHandle<()>,
}

impl Default for SshManager {
    fn default() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            pending_host_keys: RwLock::new(HashMap::new()),
            connection_locks: RwLock::new(HashMap::new()),
            forward_lock: Mutex::new(()),
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
        self.sessions.read().get(host_id).is_some_and(|connection| {
            // A busy handle is in use; an idle, closed handle must not make a
            // later connect request incorrectly return success without reconnecting.
            connection.handle.try_lock().map_or(true, |handle| !handle.is_closed())
        })
    }

    pub fn pending_host_key(&self, host_id: &str) -> Option<String> {
        self.pending_host_keys.read().get(host_id).map(|(_, fingerprint)| fingerprint.clone())
    }

    pub fn trust_host_key(&self, db: &Database, host_id: &str, fingerprint: &str) -> AppResult<()> {
        let pending = self.pending_host_keys.read().get(host_id).cloned().ok_or_else(|| AppError::NotFound("待确认的主机指纹".into()))?;
        if pending.1 != fingerprint {
            return Err(AppError::Validation("主机指纹已变化，请重新连接确认".into()));
        }
        let mut host = db.host_get(host_id)?;
        let endpoint = format!("{}:{}", host.hostname, host.port);
        if pending.0 != endpoint {
            return Err(AppError::Validation("服务器地址已变化，请重新连接确认主机指纹".into()));
        }
        db.set_fingerprint(host_id, &endpoint, fingerprint)?;
        {
            host.host_key_fingerprint = Some(fingerprint.to_owned());
            host.updated_at = chrono::Utc::now().to_rfc3339();
            db.host_upsert(&host)?;
        }
        self.pending_host_keys.write().remove(host_id);
        Ok(())
    }
    pub async fn connect(
        &self,
        db: &Database,
        profile: HostProfile,
        supplied_password: Option<String>,
    ) -> AppResult<()> {
        // Validate before taking a per-host lock, including recursive jump connections.
        validate_jump_chain(db, &profile, &mut HashSet::new())?;
        let lock = self.connection_lock(&profile.id);
        let _guard = lock.lock().await;
        // A recursive jump connection may have waited behind an edit or delete.
        // Reload under the same lock used by those operations before using the
        // endpoint, credentials or route captured by its caller.
        let profile = db.host_get(&profile.id)?;
        validate_jump_chain(db, &profile, &mut HashSet::new())?;
        timeout(Duration::from_secs(60), self.connect_inner(db, profile, supplied_password))
            .await.map_err(|_| AppError::Ssh("SSH 连接或认证超时".into()))?
    }

    pub(crate) fn connection_lock(&self, host_id: &str) -> Arc<Mutex<()>> {
        self.connection_locks.write().entry(host_id.into())
            .or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }

    async fn connect_inner(&self, db: &Database, profile: HostProfile, supplied_password: Option<String>) -> AppResult<()> {
        if self.is_connected(&profile.id) {
            return Ok(());
        }
        self.disconnect_inner(&profile.id).await?;
        self.pending_host_keys.write().remove(&profile.id);
        let observed = Arc::new(Mutex::new(None));
        let endpoint = format!("{}:{}", profile.hostname, profile.port);
        // Profile data (including imported JSON) is not a trust decision.
        let expected = db.known_fingerprint(&profile.id, &endpoint)?;
        let (remote_sender, remote_receiver) = mpsc::unbounded_channel();
        let handler = ClientHandler {
            expected: expected.clone(),
            accept_unknown: false,
            observed: observed.clone(),
            remote_sender,
        };
        let config = Arc::new(client::Config {
            inactivity_timeout: Some(Duration::from_secs(90)),
            keepalive_interval: Some(Duration::from_secs(15)),
            keepalive_max: 3,
            ..Default::default()
        });
        let connection_result = if profile.jump_hosts.is_empty() {
            client::connect(config.clone(), (profile.hostname.as_str(), profile.port), handler).await
        } else {
            let stream = self.open_jump_stream(db, &profile).await?;
            client::connect_stream(config, stream, handler).await
        };
        let mut handle = match connection_result {
            Ok(handle) => handle,
            Err(error) => {
                if let Some(fingerprint) = observed.lock().await.clone() {
                    if expected.as_ref() == Some(&fingerprint) {
                        return Err(AppError::Ssh(error.to_string()));
                    }
                    self.pending_host_keys.write().insert(profile.id.clone(), (endpoint, fingerprint.clone()));
                    if expected.is_none() {
                        return Err(AppError::Permission(format!("首次连接需要确认主机指纹：{fingerprint}")));
                    }
                    return Err(AppError::Permission(format!("主机指纹不匹配，当前指纹：{fingerprint}")));
                }
                return Err(AppError::Ssh(error.to_string()));
            }
        };
        let verification_password = supplied_password.clone().map(zeroize::Zeroizing::new);
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
                let passphrase = supplied_password.or_else(|| profile
                    .credential_id
                    .as_deref()
                    .and_then(|id| security::read_secret(id).ok()));
                let key = keys::load_secret_key(Path::new(path), passphrase.as_deref())
                    .map_err(|error| match error {
                        keys::Error::KeyIsEncrypted if passphrase.is_none() => AppError::KeyPassphraseRequired,
                        keys::Error::SshKey(ssh_key::Error::Crypto) | keys::Error::KeyIsCorrupt
                            if passphrase.is_some() => AppError::Permission("私钥口令错误或私钥文件已损坏，请检查后重试".into()),
                        error => AppError::Ssh(format!("无法读取私钥：{error}")),
                    })?;
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
                #[cfg(windows)]
                {
                    let pipe = std::env::var_os("SSH_AUTH_SOCK").unwrap_or_else(|| std::ffi::OsString::from(r"\\.\pipe\openssh-ssh-agent"));
                    let mut agent = AgentClient::connect_named_pipe(pipe).await.map_err(|e| AppError::Permission(format!("无法连接 Windows SSH Agent：{e}")))?;
                    let identities = agent.request_identities().await.map_err(|e| AppError::Permission(format!("无法读取 SSH Agent 密钥：{e}")))?;
                    let mut success = false;
                    for identity in identities {
                        let key = identity.public_key().into_owned();
                        let result = handle.authenticate_publickey_with(profile.username.clone(), key, None, &mut agent).await.map_err(|e| AppError::Ssh(e.to_string()))?;
                        if result.success() { success = true; break; }
                    }
                    success
                }
                #[cfg(not(windows))]
                { return Err(AppError::Other("当前平台未实现 SSH Agent 认证".into())); }
            }
            other => return Err(AppError::Validation(format!("未知认证方式：{other}"))),
        };
        if !auth_ok {
            return Err(AppError::Permission("SSH 认证失败".into()));
        }
        self.pending_host_keys.write().remove(&profile.id);
        self.sessions.write().insert(
            profile.id.clone(),
            Arc::new(ManagedConnection {
                handle: Arc::new(Mutex::new(handle)),
                profile,
                verification_password,
                remote_receiver: Arc::new(Mutex::new(remote_receiver)),
            }),
        );
        Ok(())
    }

    pub async fn disconnect(&self, host_id: &str) -> AppResult<()> {
        let lock = self.connection_lock(host_id);
        let _guard = lock.lock().await;
        self.disconnect_inner(host_id).await
    }

    // The caller must hold this host's connection_lock for the entire call.
    pub(crate) async fn disconnect_inner(&self, host_id: &str) -> AppResult<()> {
        let forward_ids = self.forwards.read().iter().filter(|(_, forward)| forward.host_id == host_id).map(|(id, _)| id.clone()).collect::<Vec<_>>();
        // A failed remote cancellation must not prevent disconnecting the transport.
        for id in &forward_ids { let _ = self.forward_stop(id).await; }
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
        for id in forward_ids {
            if let Some(forward) = self.forwards.write().remove(&id) { let _ = forward.cancel.send(true); }
        }
        if let Some(session) = session {
            let handle = session.handle.lock().await;
            if !handle.is_closed() {
                handle.disconnect(Disconnect::ByApplication, "", "en").await
                    .map_err(|e| AppError::Ssh(e.to_string()))?;
            }
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
        let mut slots = self.transfer_slots.write();
        // A host-wide single writer prevents two transfers from racing on the
        // same remote destination while still allowing terminal/monitor work.
        slots.entry(host_id.into()).or_insert_with(|| Arc::new(Semaphore::new(1))).clone()
    }
    fn connection(&self, host_id: &str) -> AppResult<Arc<ManagedConnection>> {
        self.sessions
            .read()
            .get(host_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound(format!("服务器 {host_id} 尚未连接")))
    }

    async fn open_jump_stream(&self, db: &Database, profile: &HostProfile) -> AppResult<russh::ChannelStream<client::Msg>> {
        validate_jump_chain(db, profile, &mut HashSet::new())?;
        let jump = profile.jump_hosts.iter().min_by_key(|jump| jump.order).ok_or_else(|| AppError::Validation("跳板配置为空".into()))?;
        let jump_profile = db.host_get(&jump.host_id)?;
        Box::pin(self.connect(db, jump_profile, None)).await?;
        let connection = self.connection(&jump.host_id)?;
        let handle = connection.handle.lock().await;
        let channel = handle.channel_open_direct_tcpip(profile.hostname.clone(), profile.port as u32, "127.0.0.1", 0).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        Ok(channel.into_stream())
    }

    pub async fn exec(&self, host_id: &str, command: &str) -> AppResult<ExecOutput> {
        self.exec_with_input(host_id, command, None).await
    }

    pub async fn exec_with_input(&self, host_id: &str, command: &str, input: Option<&str>) -> AppResult<ExecOutput> {
        let connection = self.connection(host_id)?;
        let started = Instant::now();
        let mut channel = timeout(Duration::from_secs(30), async {
            let handle = connection.handle.lock().await;
            handle.channel_open_session().await.map_err(|e| AppError::Ssh(e.to_string()))
        }).await.map_err(|_| AppError::Ssh("打开命令通道超时".into()))??;
        let mut stdout = Vec::new(); let mut stderr = Vec::new(); let mut code = None;
        let received = timeout(Duration::from_secs(120), async {
            channel.exec(true, command).await.map_err(|e| AppError::Ssh(e.to_string()))?;
            let mut pending = wait_channel_success(&mut channel, "执行命令").await?;
            if let Some(value) = input { channel.data_bytes(format!("{value}\n")).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
            channel.eof().await.map_err(|e| AppError::Ssh(e.to_string()))?;
            while let Some(message) = next_channel_message(&mut channel, &mut pending).await { match message {
                ChannelMsg::Data { data } if stdout.len() < 8 * 1024 * 1024 => stdout.extend_from_slice(&data[..data.len().min(8 * 1024 * 1024 - stdout.len())]),
                ChannelMsg::ExtendedData { data, .. } if stderr.len() < 8 * 1024 * 1024 => stderr.extend_from_slice(&data[..data.len().min(8 * 1024 * 1024 - stderr.len())]),
                ChannelMsg::ExitStatus { exit_status } => { code = Some(exit_status as i32); },
                ChannelMsg::ExitSignal { .. } => { code = Some(128); },
                ChannelMsg::Close => break,
                _ => {}
            } }
            Ok::<(), AppError>(())
        }).await;
        let _ = timeout(Duration::from_secs(2), channel.close()).await;
        received.map_err(|_| AppError::Ssh("远程命令超时".into()))??;
        // Channel failure does not invalidate other terminals/forwards on this transport.
        if code.is_none() { return Err(AppError::Ssh("远程命令通道异常关闭，未收到退出状态".into())); }
        Ok(ExecOutput { stdout: String::from_utf8_lossy(&stdout).into_owned(), stderr: String::from_utf8_lossy(&stderr).into_owned(), exit_code: code.unwrap_or(128), duration_ms: started.elapsed().as_millis() as u64 })
    }

    pub async fn sftp_list(&self, host_id: &str, path: &str) -> AppResult<Vec<SftpEntry>> {
        validate_remote_path(path)?;
        let sftp = open_sftp(self, host_id).await?;
        let entries = sftp
            .read_dir(path)
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?
            .map(|entry| {
                validate_remote_entry_name(&entry.file_name())?;
                let metadata = entry.metadata();
                let kind = if metadata.file_type().is_dir() {
                    "directory"
                } else if metadata.file_type().is_symlink() {
                    "symlink"
                } else {
                    "file"
                };
                Ok(SftpEntry {
                    name: entry.file_name(),
                    path: entry.path(),
                    kind: kind.into(),
                    size: metadata.len(),
                    modified_at: metadata.mtime
                        .and_then(|timestamp| chrono::DateTime::<chrono::Utc>::from_timestamp(timestamp as i64, 0))
                        .map(|timestamp| timestamp.to_rfc3339()),
                    permissions: Some(metadata.permissions().to_string()),
                })
            })
            .collect::<AppResult<Vec<_>>>();
        let _ = sftp.close().await;
        entries
    }

    pub async fn sftp_upload(
        self: &Arc<Self>,
        host_id: &str,
        local_paths: Vec<String>,
        remote_directory: &str,
        conflict_policy: &str,
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
        let conflict_policy = conflict_policy.to_string();
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
            let result = run_upload_transfer(&manager, &hid, local_paths, &remote_dir, &conflict_policy, &id, ipc.clone(), receiver).await;
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
        conflict_policy: &str,
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
        let conflict_policy = conflict_policy.to_string();
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
            let result = run_download_transfer(&manager, &hid, remote_paths, &local_dir, &conflict_policy, &id, ipc.clone(), receiver).await;
            if let Err(error) = result {
                send_transfer_state(&manager.sequence, &ipc, &hid, &id, "error", Some(error.to_string()));
            }
            manager.transfers.write().remove(&id);
        });
        Ok(transfer_id)
    }

    pub async fn sftp_delete(&self, host_id: &str, paths: &[String]) -> AppResult<()> {
        for path in paths { validate_delete_target(path)?; }
        let sftp = open_sftp(self, host_id).await?;
        for path in paths {
            validate_remote_path(path)?;
            let metadata = sftp.symlink_metadata(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
            if metadata.file_type().is_dir() { remove_remote_tree(&sftp, path).await?; }
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

    pub async fn sftp_copy(self: &Arc<Self>, host_id: &str, sources: Vec<String>, destination: String, conflict_policy: &str, ipc: IpcChannel<StreamEnvelope<TransferProgress>>) -> AppResult<String> {
        if !self.is_connected(host_id) { return Err(AppError::Validation("SSH 尚未连接".into())); }
        validate_remote_path(&destination)?;
        if sources.is_empty() { return Err(AppError::Validation("没有选择要复制的远程项目".into())); }
        let destination_normalized = destination.trim_end_matches('/');
        for source in &sources {
            validate_remote_copy_target(source, if destination_normalized.is_empty() { "/" } else { destination_normalized })?;
        }
        let id = Uuid::new_v4().to_string(); let (cancel, mut receiver) = watch::channel(false);
        self.transfers.write().insert(id.clone(), (host_id.into(), cancel));
        let manager = Arc::clone(self); let hid = host_id.to_string(); let tid = id.clone(); let conflict_policy = conflict_policy.to_string();
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
                if cancelled(&receiver) { send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "cancelled", None); return Ok::<(), AppError>(()); }
                let sftp = open_sftp(&manager, &hid).await?;
                ensure_remote_directory(&sftp, &destination).await?;
                let destination = sftp.canonicalize(&destination).await.map_err(|error| AppError::Ssh(error.to_string()))?;
                // Compare server-resolved paths before creating any target tree.
                // Relative paths and symlinked ancestors can otherwise alias the source.
                let mut canonical_sources = Vec::new();
                for source in &sources {
                    if sftp.symlink_metadata(source).await.map_err(|error| AppError::Ssh(error.to_string()))?.file_type().is_symlink() { continue; }
                    let source = sftp.canonicalize(source).await.map_err(|error| AppError::Ssh(error.to_string()))?;
                    validate_remote_copy_target(&source, &destination)?;
                    canonical_sources.push(source);
                }
                let mut files = Vec::new(); for source in &canonical_sources { collect_remote_files(&sftp, source, &destination, &mut files).await?; }
                let total = files.iter().map(|(_,_,size)| *size).sum::<u64>(); let mut transferred = 0u64;
                for (index, (source, target, size)) in files.iter().enumerate() {
                    if cancelled(&receiver) { let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "cancelled", None); return Ok::<(), AppError>(()); }
                    let Some(target) = resolve_remote_target(&sftp, target, &conflict_policy).await? else { continue; };
                    let temporary = format!("{target}.sshopstmp-{tid}");
                    let prepare = async {
                        let _ = sftp.remove_file(&temporary).await;
                        let mut input = sftp.open(source).await.map_err(|e| AppError::Ssh(e.to_string()))?; let mut output = sftp.create(&temporary).await.map_err(|e| AppError::Ssh(e.to_string()))?; let mut buf = vec![0u8; 64 * 1024]; let mut current = 0u64; let mut last_emit = Instant::now() - Duration::from_secs(1);
                        loop { let n = input.read(&mut buf).await.map_err(|e| AppError::Ssh(e.to_string()))?; if n == 0 { break; } output.write_all(&buf[..n]).await.map_err(|e| AppError::Ssh(e.to_string()))?; current += n as u64; transferred += n as u64; if last_emit.elapsed() >= Duration::from_millis(120) || current == *size { last_emit = Instant::now(); let _ = ipc.send(StreamEnvelope { seq: manager.sequence.fetch_add(1, Ordering::Relaxed), timestamp: chrono::Utc::now().to_rfc3339(), host_id: hid.clone(), session_id: None, payload: TransferProgress { transfer_id: tid.clone(), host_id: hid.clone(), direction: "transfer".into(), current_path: source.clone(), transferred, total, status: "running".into(), error: None, file_index: index as u32 + 1, file_count: files.len() as u32, current_file_transferred: current, current_file_total: *size } }); } }
                        output.flush().await.map_err(|e| AppError::Ssh(e.to_string()))?; output.close().await.map_err(|e| AppError::Ssh(e.to_string()))?;
                        validate_transfer_size(*size, current)
                    };
                    if store_remote_transfer_file(&sftp, &temporary, &target, &tid, &mut receiver, prepare).await? {
                        let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "cancelled", None); return Ok(());
                    }
                }
                let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "completed", None); Ok(())
            }.await;
            if let Err(error) = result { send_transfer_state(&manager.sequence, &ipc, &hid, &tid, "error", Some(error.to_string())); }
            manager.transfers.write().remove(&tid);
        });
        Ok(id)
    }

    pub async fn terminal_open(
        self: &Arc<Self>,
        host_id: &str,
        cols: u32,
        rows: u32,
        ipc: IpcChannel<StreamEnvelope<Vec<u8>>>,
        command_logging: bool,
        audit_sender: mpsc::UnboundedSender<TerminalAuditEvent>,
    ) -> AppResult<String> {
        let connection = self.connection(host_id)?;
        let mut channel = open_session_channel(&connection).await?;
        let initialized = timeout(Duration::from_secs(30), async {
            channel
            .request_pty(
                true,
                "xterm-256color",
                cols,
                rows,
                0,
                0,
                if command_logging { &[(Pty::ECHO, 0)] } else { &[] },
            )
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
            let mut pending = wait_channel_success(&mut channel, "分配终端").await?;
            channel
            .request_shell(true)
            .await
            .map_err(|e| AppError::Ssh(e.to_string()))?;
            pending.extend(wait_channel_success(&mut channel, "启动 Shell").await?);
            Ok::<_, AppError>(pending)
        }).await.map_err(|_| AppError::Ssh("终端初始化超时".into())).and_then(|result| result);
        let mut pending = match initialized {
            Ok(pending) => pending,
            Err(error) => { let _ = timeout(Duration::from_secs(2), channel.close()).await; return Err(error); }
        };
        let session_id = Uuid::new_v4().to_string();
        let (sender, mut receiver) = mpsc::channel::<TerminalCommand>(256);
        let (cancel, mut cancelled) = watch::channel(false);
        let audit_enabled = Arc::new(AtomicBool::new(command_logging));
        let id = session_id.clone();
        let hid = host_id.to_string();
        let sequence = self.sequence.clone();
        let manager = Arc::clone(self);
        let audit_enabled_for_task = audit_enabled.clone();
        let mut writer = channel.make_writer();
        let audit_nonce = Uuid::new_v4().simple().to_string();
        if command_logging {
            let bootstrap = shell_audit_bootstrap(&audit_nonce);
            writer.write_all(bootstrap.as_bytes()).await.map_err(AppError::Io)?;
            // The bootstrap is an interactive shell command and must be submitted.
            writer.write_all(b"\n").await.map_err(AppError::Io)?;
            writer.flush().await.map_err(AppError::Io)?;
        }
        self.terminals.write().insert(session_id.clone(), ManagedTerminal {
            host_id: host_id.to_string(), sender, cancel, audit_enabled,
            audit_configured: command_logging,
        });
        tokio::spawn(async move {
            let mut audit_parser = TerminalAuditParser::new(audit_nonce);
            let audit_timeout = tokio::time::sleep(Duration::from_secs(8));
            tokio::pin!(audit_timeout);
            let mut audit_timeout_pending = command_logging;
            // Cancellation must interrupt a blocked SSH write as well as the
            // command queue; a full queue must never prevent closing a terminal.
            let work = async {
                loop {
                    tokio::select! {
                        command=receiver.recv()=>match command {
                            Some(TerminalCommand::Input(data))=>{ if writer.write_all(&data).await.is_err(){break;} let _=writer.flush().await; },
                            Some(TerminalCommand::Resize(cols, rows))=>{ let _=channel.window_change(cols, rows, 0, 0).await; },
                            None=>break
                        },
                        message=next_channel_message(&mut channel, &mut pending)=>match message {
                            Some(ChannelMsg::Data{data})|Some(ChannelMsg::ExtendedData{data,..})=>{
                                let (visible, audits) = if command_logging { audit_parser.push(&data) } else { (data.to_vec(), Vec::new()) };
                                if !visible.is_empty() { let _=ipc.send(StreamEnvelope{seq:sequence.fetch_add(1,Ordering::Relaxed),timestamp:chrono::Utc::now().to_rfc3339(),host_id:hid.clone(),session_id:Some(id.clone()),payload:visible}); }
                                if audit_parser.settled() { audit_timeout_pending = false; }
                                if audit_enabled_for_task.load(Ordering::Relaxed) {
                                    for (audit_sequence, kind) in audits { let _ = audit_sender.send(TerminalAuditEvent { session_id: id.clone(), host_id: hid.clone(), sequence: audit_sequence, kind, timestamp: chrono::Utc::now().to_rfc3339() }); }
                                }
                            },
                            Some(ChannelMsg::Close)|None=>break,
                            _=>{}
                        },
                        _=&mut audit_timeout, if audit_timeout_pending=>{
                            audit_timeout_pending=false;
                            let notice=b"\r\n\x1b[33m[SSH Ops] Command audit did not initialize; terminal input is not being recorded.\x1b[0m\r\n".to_vec();
                            let _=ipc.send(StreamEnvelope{seq:sequence.fetch_add(1,Ordering::Relaxed),timestamp:chrono::Utc::now().to_rfc3339(),host_id:hid.clone(),session_id:Some(id.clone()),payload:notice});
                        },
                    }
                }
            };
            tokio::select! { _ = cancelled.changed() => {}, _ = work => {} }
            if command_logging { let remaining = audit_parser.finish(); if !remaining.is_empty() { let _=ipc.send(StreamEnvelope{seq:sequence.fetch_add(1,Ordering::Relaxed),timestamp:chrono::Utc::now().to_rfc3339(),host_id:hid.clone(),session_id:Some(id.clone()),payload:remaining}); } }
            let _ = timeout(Duration::from_secs(2), channel.close()).await;
            let _ = manager.terminals.write().remove(&id);
        });
        Ok(session_id)
    }

    pub fn terminal_set_audit(&self, session_id: &str, enabled: bool) -> AppResult<()> {
        let terminals = self.terminals.read();
        let terminal = terminals.get(session_id).ok_or_else(|| AppError::NotFound("终端会话".into()))?;
        if enabled && !terminal.audit_configured {
            return Err(AppError::Validation("当前终端未安装审计钩子，请重新连接后启用命令记录".into()));
        }
        terminal.audit_enabled.store(enabled, Ordering::Relaxed);
        Ok(())
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
            let _ = terminal.cancel.send(true);
        }
        Ok(())
    }
    pub fn profile(&self, host_id: &str) -> AppResult<HostProfile> {
        Ok(self.connection(host_id)?.profile.clone())
    }

    pub async fn verify_new_connection(&self, db: &Database, host_id: &str) -> AppResult<()> {
        let connection = self.connection(host_id)?;
        let profile = connection.profile.clone();
        let password = connection.verification_password.as_ref().map(|value| value.to_string());
        let verifier = SshManager::default();
        verifier.connect(db, profile, password).await?;
        verifier.disconnect(host_id).await
    }

    pub async fn forward_start(&self, profile: &crate::models::ForwardingProfile) -> AppResult<()> {
        let _guard = self.forward_lock.lock().await;
        self.forward_stop_inner(&profile.id).await?;
        let connection = self.connection(&profile.host_id)?;
        let (cancel, mut cancelled) = watch::channel(false);
        let target_host = profile.target_host.clone().unwrap_or_default();
        let target_port = profile.target_port.unwrap_or(0);
        if profile.kind == "remote" {
            if self.forwards.read().values().any(|forward| forward.host_id == profile.host_id && forward.remote.is_some()) {
                return Err(AppError::Validation("同一 SSH 连接暂时只允许一个远程监听转发".into()));
            }
            let handle = connection.handle.lock().await;
            let remote_bind_port = profile.bind_port as u32;
            handle.tcpip_forward(profile.bind_address.clone(), remote_bind_port).await.map_err(|e| AppError::Ssh(e.to_string()))?;
            drop(handle);
            let receiver = connection.remote_receiver.clone();
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancelled.changed() => break,
                        incoming = async { receiver.lock().await.recv().await } => {
                            let Some(incoming) = incoming else { break; };
                            if incoming.connected_port != remote_bind_port { continue; }
                            let target_host = target_host.clone();
                            let mut child_cancelled = cancelled.clone();
                            tokio::spawn(async move {
                                let work = async move {
                                    let Ok(mut local) = TcpStream::connect((target_host.as_str(), target_port)).await else { return; };
                                    let mut remote = incoming.channel.into_stream();
                                    let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
                                };
                                let cancel_wait = child_cancelled.changed();
                                tokio::pin!(cancel_wait);
                                tokio::select! { _ = &mut cancel_wait => {}, _ = work => {} }
                            });
                        }
                    }
                }
            });
            self.forwards.write().insert(profile.id.clone(), ManagedForward { host_id: profile.host_id.clone(), cancel, remote: Some((profile.bind_address.clone(), remote_bind_port)), task });
            return Ok(());
        }
        let listener = TcpListener::bind((profile.bind_address.as_str(), profile.bind_port)).await.map_err(AppError::Io)?;
        let kind = profile.kind.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancelled.changed() => break,
                    accepted = listener.accept() => {
                        let Ok((mut local, _)) = accepted else { break; };
                        let connection = connection.clone();
                        let target_host = target_host.clone();
                        let kind = kind.clone();
                        let mut child_cancelled = cancelled.clone();
                        tokio::spawn(async move {
                            let work = async move {
                                if kind == "dynamic" {
                                    if let Ok((host, port)) = socks5_connect(&mut local).await {
                                        match open_direct_tcpip(connection, &host, port).await {
                                            Ok(channel) => {
                                                let _ = local.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                                                let mut remote = channel.into_stream();
                                                let _ = tokio::io::copy_bidirectional(&mut local, &mut remote).await;
                                            }
                                            Err(_) => { let _ = local.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await; }
                                        }
                                    }
                                } else {
                                    let _ = bridge_tcp(connection, &mut local, &target_host, target_port).await;
                                }
                            };
                            let cancel_wait = child_cancelled.changed();
                            tokio::pin!(cancel_wait);
                            tokio::select! { _ = &mut cancel_wait => {}, _ = work => {} }
                        });
                    }
                }
            }
        });
        self.forwards.write().insert(profile.id.clone(), ManagedForward { host_id: profile.host_id.clone(), cancel, remote: None, task });
        Ok(())
    }

    pub async fn forward_stop(&self, id: &str) -> AppResult<()> {
        let _guard = self.forward_lock.lock().await;
        self.forward_stop_inner(id).await
    }

    pub fn is_forward_active(&self, id: &str) -> bool {
        self.forwards.read().get(id).is_some_and(|forward| {
            !forward.task.is_finished() && self.is_connected(&forward.host_id)
        })
    }

    async fn forward_stop_inner(&self, id: &str) -> AppResult<()> {
        let forward = { self.forwards.read().get(id).map(|forward| (forward.host_id.clone(), forward.remote.clone())) };
        if let Some((host_id, remote)) = forward {
            let connection = { self.sessions.read().get(&host_id).cloned() };
            if let Some((address, port)) = remote
                && let Some(connection) = connection
            {
                let handle = connection.handle.lock().await;
                if !handle.is_closed() {
                    handle.cancel_tcpip_forward(address, port).await.map_err(|error| AppError::Ssh(error.to_string()))?;
                }
            }
            let forward = { self.forwards.write().remove(id) };
            if let Some(forward) = forward {
                let _ = forward.cancel.send(true);
                // Wait for the listener to release its port before reporting stopped.
                let _ = forward.task.await;
            }
        }
        Ok(())
    }
}

async fn open_session_channel(connection: &ManagedConnection) -> AppResult<russh::Channel<client::Msg>> {
    timeout(Duration::from_secs(30), async {
        let handle = connection.handle.lock().await;
        handle.channel_open_session().await.map_err(|error| AppError::Ssh(error.to_string()))
    }).await.map_err(|_| AppError::Ssh("打开 SSH 通道超时".into()))?
}

async fn next_channel_message(channel: &mut russh::Channel<client::Msg>, pending: &mut VecDeque<ChannelMsg>) -> Option<ChannelMsg> {
    match pending.pop_front() { Some(message) => Some(message), None => channel.wait().await }
}

async fn wait_channel_success(channel: &mut russh::Channel<client::Msg>, operation: &str) -> AppResult<VecDeque<ChannelMsg>> {
    // Sending a want_reply request only queues the packet in russh. The peer
    // must acknowledge it before stdin or an audit bootstrap is sent.
    timeout(Duration::from_secs(30), async {
        let mut pending = VecDeque::new();
        let mut buffered_bytes = 0usize;
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return Ok(pending),
                Some(ChannelMsg::Failure) => return Err(AppError::Ssh(format!("服务器拒绝{operation}"))),
                Some(ChannelMsg::Close) | None => return Err(AppError::Ssh(format!("{operation}确认前 SSH 通道已关闭"))),
                Some(message) => {
                    if let ChannelMsg::Data { ref data } | ChannelMsg::ExtendedData { ref data, .. } = message {
                        buffered_bytes = buffered_bytes.saturating_add(data.len());
                    }
                    if buffered_bytes > 1024 * 1024 || pending.len() >= 1024 {
                        return Err(AppError::Ssh(format!("{operation}确认前收到过多数据")));
                    }
                    // Shell banners and early output must not disappear while
                    // waiting for the request acknowledgement.
                    pending.push_back(message);
                }
            }
        }
    }).await.map_err(|_| AppError::Ssh(format!("{operation}确认超时")))?
}

async fn open_sftp(manager: &SshManager, host_id: &str) -> AppResult<SftpSession> {
    let connection = manager.connection(host_id)?;
    let mut channel = open_session_channel(&connection).await?;
    let initialized = async {
        channel.request_subsystem(true, "sftp").await.map_err(|error| AppError::Ssh(error.to_string()))?;
        let pending = wait_channel_success(&mut channel, "启动 SFTP").await?;
        if pending.iter().any(|message| matches!(message, ChannelMsg::Data { .. } | ChannelMsg::ExtendedData { .. })) {
            return Err(AppError::Ssh("SFTP 初始化前收到意外数据".into()));
        }
        Ok::<(), AppError>(())
    }.await;
    if let Err(error) = initialized {
        let _ = timeout(Duration::from_secs(2), channel.close()).await;
        return Err(error);
    }
    timeout(Duration::from_secs(30), SftpSession::new(channel.into_stream()))
        .await.map_err(|_| AppError::Ssh("SFTP 初始化超时".into()))?
        .map_err(|error| AppError::Ssh(error.to_string()))
}

fn validate_remote_path(path: &str) -> AppResult<()> {
    if path.is_empty() || path.contains('\0') || path.contains('\n') || path.contains('\r') || path.split('/').any(|part| part == "..") { return Err(AppError::Validation("远程路径无效".into())); }
    Ok(())
}

fn validate_remote_entry_name(name: &str) -> AppResult<()> {
    // READDIR names are untrusted single path components, never paths. In
    // particular, joining "../sibling" must not expand a recursive operation.
    validate_remote_path(name)?;
    if name == "." || name.contains('/') {
        return Err(AppError::Validation("远程目录返回了无效的文件名".into()));
    }
    Ok(())
}

fn validate_delete_target(path: &str) -> AppResult<()> {
    validate_remote_path(path)?;
    if path.split('/').all(|part| part.is_empty() || part == ".") {
        return Err(AppError::Validation("不能删除远程根目录或当前目录".into()));
    }
    Ok(())
}

fn validate_jump_chain(db: &Database, profile: &HostProfile, visiting: &mut HashSet<String>) -> AppResult<()> {
    if !visiting.insert(profile.id.clone()) {
        return Err(AppError::Validation("跳板配置存在循环引用".into()));
    }
    for jump in &profile.jump_hosts {
        let next = db.host_get(&jump.host_id)?;
        validate_jump_chain(db, &next, visiting)?;
    }
    visiting.remove(&profile.id);
    Ok(())
}

async fn remove_remote_tree(sftp: &SftpSession, path: &str) -> AppResult<()> {
    let metadata = sftp.symlink_metadata(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    if metadata.file_type().is_symlink() {
        sftp.remove_file(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        return Ok(());
    }
    if metadata.file_type().is_dir() {
        let entries = sftp.read_dir(path).await.map_err(|e| AppError::Ssh(e.to_string()))?.collect::<Vec<_>>();
        for entry in &entries { validate_remote_entry_name(&entry.file_name())?; }
        for entry in entries { let child = entry.path(); let child_meta = entry.metadata(); if child_meta.file_type().is_dir() { Box::pin(remove_remote_tree(sftp, &child)).await?; } else { sftp.remove_file(&child).await.map_err(|e| AppError::Ssh(e.to_string()))?; } }
        sftp.remove_dir(path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    } else { sftp.remove_file(path).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
    Ok(())
}

async fn collect_remote_files(sftp: &SftpSession, source: &str, destination: &str, files: &mut Vec<(String, String, u64)>) -> AppResult<()> {
    validate_remote_path(source)?; validate_remote_path(destination)?;
    let metadata = sftp.symlink_metadata(source).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    let name = source.rsplit('/').find(|v| !v.is_empty()).unwrap_or("item"); let target_root = format!("{}/{}", destination.trim_end_matches('/'), name);
    if metadata.file_type().is_symlink() { return Ok(()); }
    if metadata.file_type().is_dir() {
        ensure_remote_directory(sftp, &target_root).await?;
        let entries = sftp.read_dir(source).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        for entry in entries {
            validate_remote_entry_name(&entry.file_name())?;
            let child = entry.path();
            let child_target = join_remote_path(&target_root, &entry.file_name());
            let metadata = entry.metadata();
            if metadata.file_type().is_symlink() { continue; }
            if metadata.file_type().is_dir() { Box::pin(collect_remote_files(sftp, &child, &target_root, files)).await?; }
            else { validate_remote_regular_file(&metadata, &child)?; files.push((child, child_target, metadata.len())); }
        }
    } else { validate_remote_regular_file(&metadata, source)?; files.push((source.into(), target_root, metadata.len())); }
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
        if is_link_or_reparse_point(&path)? { continue; }
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
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => return Err(AppError::Validation(format!("远程路径不是目录：{current}"))),
            Err(error) if sftp_not_found(&error) => sftp.create_dir(&current).await.map_err(|error| AppError::Ssh(error.to_string()))?,
            Err(error) => return Err(AppError::Ssh(error.to_string())),
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

async fn prepare_transfer_file<F>(cancel: &mut watch::Receiver<bool>, prepare: F) -> AppResult<bool>
where F: std::future::Future<Output = AppResult<()>> {
    if cancelled(cancel) { return Ok(true); }
    // Drop all open file handles before the caller removes the temporary file.
    // Cancellation also covers prefix verification, flush and a stalled peer.
    tokio::select! {
        biased;
        _ = cancel.changed() => Ok(true),
        result = prepare => result.map(|_| false),
    }
}

async fn store_remote_transfer_file<F>(sftp: &SftpSession, temporary: &str, target: &str, transfer_id: &str, cancel: &mut watch::Receiver<bool>, prepare: F) -> AppResult<bool>
where F: std::future::Future<Output = AppResult<()>> {
    let result = match prepare_transfer_file(cancel, prepare).await {
        Ok(false) if !cancelled(cancel) => {
            // Once replacement starts, finish it (including rollback) without
            // interruption so cancellation cannot strand the original backup.
            replace_remote_file(sftp, temporary, target, transfer_id).await.map(|_| false)
        }
        Ok(_) => Ok(true),
        Err(error) => Err(error),
    };
    if !matches!(result, Ok(false))
        && let Err(error) = sftp.remove_file(temporary).await
        && !sftp_not_found(&error)
    {
        let reason = result.as_ref().err().map(ToString::to_string).unwrap_or_else(|| "传输已取消".into());
        return Err(AppError::Ssh(format!("{reason}；无法清理临时文件 {temporary}：{error}")));
    }
    result
}

async fn store_local_transfer_file<F>(temporary: &Path, target: &Path, transfer_id: &str, cancel: &mut watch::Receiver<bool>, prepare: F) -> AppResult<bool>
where F: std::future::Future<Output = AppResult<()>> {
    let result = match prepare_transfer_file(cancel, prepare).await {
        Ok(false) if !cancelled(cancel) => replace_local_file(temporary, target, transfer_id).await.map(|_| false),
        Ok(_) => Ok(true),
        Err(error) => Err(error),
    };
    if !matches!(result, Ok(false))
        && let Err(error) = tokio::fs::remove_file(temporary).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        let reason = result.as_ref().err().map(ToString::to_string).unwrap_or_else(|| "传输已取消".into());
        return Err(AppError::Other(format!("{reason}；无法清理临时文件 {}：{error}", temporary.display())));
    }
    result
}

async fn resolve_remote_target(sftp: &SftpSession, requested: &str, policy: &str) -> AppResult<Option<String>> {
    if !remote_exists(sftp, requested).await? {
        return Ok(Some(requested.to_owned()));
    }
    match policy {
        "overwrite" | "resume" => {
            let metadata = sftp.symlink_metadata(requested).await.map_err(|error| AppError::Ssh(error.to_string()))?;
            validate_remote_regular_file(&metadata, requested)?;
            Ok(Some(requested.to_owned()))
        }
        "skip" => Ok(None),
        "rename" => {
            for index in 1..=10_000u32 {
                let candidate = renamed_remote_path(requested, index);
                if !remote_exists(sftp, &candidate).await? { return Ok(Some(candidate)); }
            }
            Err(AppError::Validation("无法为远程目标生成不冲突的文件名".into()))
        }
        _ => Err(AppError::Validation("目标文件已存在，请选择覆盖、跳过或重命名".into())),
    }
}

fn renamed_remote_path(requested: &str, index: u32) -> String {
    let (directory, name) = requested.rsplit_once('/').map_or(("", requested), |(dir, name)| (&requested[..dir.len() + 1], name));
    let (stem, extension) = name.rsplit_once('.').filter(|(stem, _)| !stem.is_empty())
        .map_or((name, String::new()), |(stem, ext)| (stem, format!(".{ext}")));
    format!("{directory}{stem} ({index}){extension}")
}

fn renamed_local_path(requested: &Path, index: u32) -> AppResult<PathBuf> {
    let name = requested.file_name().and_then(|name| name.to_str())
        .ok_or_else(|| AppError::Validation("下载目标文件名无效".into()))?;
    // Keep the extension in its usual position, matching upload conflict names.
    Ok(requested.with_file_name(renamed_remote_path(name, index)))
}

async fn remote_exists(sftp: &SftpSession, path: &str) -> AppResult<bool> {
    match sftp.symlink_metadata(path).await {
        Ok(_) => Ok(true),
        Err(error) if sftp_not_found(&error) => Ok(false),
        Err(error) => Err(AppError::Ssh(format!("无法检查远程目标 {path}：{error}"))),
    }
}

fn sftp_not_found(error: &russh_sftp::client::error::Error) -> bool {
    matches!(error, russh_sftp::client::error::Error::Status(status) if status.status_code == russh_sftp::protocol::StatusCode::NoSuchFile)
}

async fn copy_remote_prefix(sftp: &SftpSession, source: &str, destination: &str, length: u64) -> AppResult<()> {
    let mut input = sftp.open(source).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    let mut output = sftp.create(destination).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    let mut remaining = length;
    let mut buffer = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = input.read(&mut buffer[..wanted]).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        if read == 0 { break; }
        output.write_all(&buffer[..read]).await.map_err(|e| AppError::Ssh(e.to_string()))?;
        remaining -= read as u64;
    }
    if remaining != 0 {
        let _ = output.close().await;
        return Err(AppError::Ssh("远程续传源文件在读取时发生变化".into()));
    }
    output.close().await.map_err(|e| AppError::Ssh(e.to_string()))?;
    Ok(())
}

async fn remote_prefix_matches(sftp: &SftpSession, remote: &str, local: &Path, length: u64) -> AppResult<bool> {
    let mut remote_file = sftp.open(remote).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    let mut local_file = tokio::fs::File::open(local).await.map_err(AppError::Io)?;
    prefixes_match(&mut remote_file, &mut local_file, length).await
}

async fn prefixes_match<A: tokio::io::AsyncRead + Unpin, B: tokio::io::AsyncRead + Unpin>(left: &mut A, right: &mut B, mut remaining: u64) -> AppResult<bool> {
    let mut a = vec![0; 64 * 1024];
    let mut b = vec![0; 64 * 1024];
    while remaining > 0 {
        let wanted = remaining.min(a.len() as u64) as usize;
        for result in [left.read_exact(&mut a[..wanted]).await, right.read_exact(&mut b[..wanted]).await] {
            match result {
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
                Err(error) => return Err(AppError::Io(error)),
                Ok(_) => {}
            }
        }
        if a[..wanted] != b[..wanted] { return Ok(false); }
        remaining -= wanted as u64;
    }
    Ok(true)
}

async fn replace_remote_file(sftp: &SftpSession, temporary: &str, target: &str, transfer_id: &str) -> AppResult<()> {
    let backup = format!("{target}.sshopstmp-backup-{transfer_id}");
    let existing = match sftp.symlink_metadata(target).await {
        Ok(metadata) => {
            validate_remote_regular_file(&metadata, target)?;
            true
        }
        Err(error) if sftp_not_found(&error) => false,
        Err(error) => return Err(AppError::Ssh(format!("无法检查远程目标 {target}：{error}"))),
    };
    if existing {
        sftp.rename(target, &backup).await.map_err(|e| AppError::Ssh(e.to_string()))?;
    }
    if let Err(error) = sftp.rename(temporary, target).await {
        if existing && let Err(restore_error) = sftp.rename(&backup, target).await {
            return Err(AppError::Ssh(format!("安装目标文件失败：{error}；恢复原文件失败：{restore_error}；原文件备份路径：{backup}")));
        }
        return Err(AppError::Ssh(error.to_string()));
    }
    if existing { let _ = sftp.remove_file(&backup).await; }
    Ok(())
}

async fn run_upload_transfer(manager: &SshManager, host_id: &str, local_paths: Vec<String>, remote_directory: &str, conflict_policy: &str, transfer_id: &str, ipc: IpcChannel<StreamEnvelope<TransferProgress>>, mut cancel: watch::Receiver<bool>) -> AppResult<()> {
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
        let Some(remote) = resolve_remote_target(&sftp, remote, conflict_policy).await? else { continue; };
        let was_cancelled = upload_file_cancelled(&sftp, local, &remote, conflict_policy, host_id, transfer_id, total, &mut transferred, file_total, index as u32 + 1, plan.files.len() as u32, &ipc, &mut cancel, &manager.sequence).await?;
        if was_cancelled { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); let _ = sftp.close().await; return Ok(()); }
    }
    let _ = sftp.close().await;
    send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "completed", None);
    Ok(())
}

async fn upload_file_cancelled(sftp: &SftpSession, local: &Path, remote: &str, conflict_policy: &str, host_id: &str, transfer_id: &str, total: u64, transferred: &mut u64, file_total: u64, file_index: u32, file_count: u32, ipc: &IpcChannel<StreamEnvelope<TransferProgress>>, cancel: &mut watch::Receiver<bool>, sequence: &Arc<AtomicU64>) -> AppResult<bool> {
    let temporary = format!("{remote}.sshopstmp-{transfer_id}");
    let prepare = async {
        let mut input = tokio::fs::File::open(local).await.map_err(AppError::Io)?;
        let _ = sftp.remove_file(&temporary).await;
        let resume_offset = if conflict_policy == "resume" {
            match sftp.symlink_metadata(remote).await {
                Ok(metadata) if metadata.len() > file_total => return Err(AppError::Validation("远程目标比本地源文件更长，不能安全续传".into())),
                Ok(metadata) => {
                    validate_remote_regular_file(&metadata, remote)?;
                    let offset = metadata.len();
                    if offset > 0 && !remote_prefix_matches(sftp, remote, local, offset).await? { return Err(AppError::Validation("远程目标前缀与本地源文件不一致，已拒绝续传".into())); }
                    offset
                }
                Err(error) if sftp_not_found(&error) => 0,
                Err(error) => return Err(AppError::Ssh(format!("无法检查远程目标：{error}"))),
            }
        } else { 0 };
        if resume_offset > 0 {
            copy_remote_prefix(sftp, remote, &temporary, resume_offset).await?;
            input.seek(SeekFrom::Start(resume_offset)).await.map_err(AppError::Io)?;
            *transferred += resume_offset;
        }
        let mut output = if resume_offset > 0 { sftp.open_with_flags(&temporary, OpenFlags::WRITE).await.map_err(|e| AppError::Ssh(e.to_string()))? } else { sftp.create(&temporary).await.map_err(|e| AppError::Ssh(e.to_string()))? };
        if resume_offset > 0 { output.seek(SeekFrom::Start(resume_offset)).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
        let mut buffer = vec![0u8; 64 * 1024]; let mut current = resume_offset; let mut last_emit = Instant::now() - Duration::from_secs(1);
        loop {
            let n = input.read(&mut buffer).await.map_err(AppError::Io)?;
            if n == 0 { break; }
            output.write_all(&buffer[..n]).await.map_err(|e| AppError::Ssh(e.to_string()))?;
            current += n as u64; *transferred += n as u64;
            if last_emit.elapsed() >= Duration::from_millis(120) || current == file_total { last_emit = Instant::now(); let _ = ipc.send(StreamEnvelope { seq: sequence.fetch_add(1, Ordering::Relaxed), timestamp: chrono::Utc::now().to_rfc3339(), host_id: host_id.into(), session_id: None, payload: TransferProgress { transfer_id: transfer_id.into(), host_id: host_id.into(), direction: "upload".into(), current_path: local.display().to_string(), transferred: *transferred, total, status: "running".into(), error: None, file_index, file_count, current_file_transferred: current, current_file_total: file_total } }); }
        }
        output.flush().await.map_err(|e| AppError::Ssh(e.to_string()))?;
        output.close().await.map_err(|e| AppError::Ssh(e.to_string()))?;
        validate_transfer_size(file_total, current)
    };
    store_remote_transfer_file(sftp, &temporary, remote, transfer_id, cancel, prepare).await
}

#[derive(Debug, Default)]
struct RemoteDownloadPlan {
    directories: Vec<PathBuf>,
    files: Vec<(String, PathBuf, u64)>,
}

fn safe_remote_name(path: &str) -> AppResult<&str> {
    let name = path.rsplit('/').find(|part| !part.is_empty()).unwrap_or("download");
    let upper = name.trim_end_matches(['.', ' ']).to_ascii_uppercase();
    let device = upper.split('.').next().unwrap_or(upper.as_str());
    let reserved = matches!(device, "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9");
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\\') || name.contains('\0') || name.contains(':') || name.chars().any(|c| c.is_control() || "*:?[\"<>|".contains(c)) || name.ends_with(['.', ' ']) || reserved {
        return Err(AppError::Validation("远程文件名无法安全保存到本地".into()));
    }
    Ok(name)
}

fn validate_local_download_path(root: &Path, relative: &Path) -> AppResult<PathBuf> {
    if is_link_or_reparse_point(root)? {
        return Err(AppError::Validation("下载根目录不能是符号链接或重解析点".into()));
    }
    if relative.is_absolute() || relative.components().any(|component| matches!(component, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_))) {
        return Err(AppError::Validation("下载目标路径越出选择的目录".into()));
    }
    let target = root.join(relative);
    let mut current = root.to_path_buf();
    for component in relative.components() {
        current.push(component.as_os_str());
        if is_link_or_reparse_point(&current)? {
            return Err(AppError::Validation("下载路径包含符号链接或重解析点".into()));
        }
    }
    Ok(target)
}

fn is_link_or_reparse_point(path: &Path) -> AppResult<bool> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(AppError::Io(error)),
    };
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // Junctions are reparse points but are not necessarily reported as symlinks.
        Ok(metadata.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    { Ok(metadata.file_type().is_symlink()) }
}

async fn copy_local_prefix(source: &Path, output: &mut tokio::fs::File, length: u64) -> AppResult<()> {
    let mut input = tokio::fs::File::open(source).await.map_err(AppError::Io)?;
    let mut remaining = length;
    let mut buffer = vec![0u8; 64 * 1024];
    while remaining > 0 {
        let wanted = remaining.min(buffer.len() as u64) as usize;
        let read = input.read(&mut buffer[..wanted]).await.map_err(AppError::Io)?;
        if read == 0 { break; }
        output.write_all(&buffer[..read]).await.map_err(AppError::Io)?;
        remaining -= read as u64;
    }
    if remaining != 0 { return Err(AppError::Io(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "本地续传源文件在读取时发生变化"))); }
    output.flush().await.map_err(AppError::Io)?;
    Ok(())
}

async fn local_prefix_matches(sftp: &SftpSession, remote: &str, local: &Path, length: u64) -> AppResult<bool> {
    remote_prefix_matches(sftp, remote, local, length).await
}

fn validate_transfer_size(expected: u64, actual: u64) -> AppResult<()> {
    if expected != actual { return Err(AppError::Validation("源文件大小在传输期间发生变化，已保留原目标文件，请重试".into())); }
    Ok(())
}

fn validate_local_file_target(target: &Path) -> AppResult<()> {
    if is_link_or_reparse_point(target)? { return Err(AppError::Validation("下载目标不能是符号链接或重解析点".into())); }
    match std::fs::symlink_metadata(target) {
        Ok(metadata) if !metadata.is_file() => Err(AppError::Validation("下载目标不是普通文件，不能覆盖或续传".into())),
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(AppError::Io(error)),
        _ => Ok(()),
    }
}

async fn replace_local_file(temporary: &Path, target: &Path, transfer_id: &str) -> AppResult<()> {
    validate_local_file_target(target)?;
    let backup = PathBuf::from(format!("{}.sshopstmp-backup-{transfer_id}", target.display()));
    let existing = tokio::fs::try_exists(target).await.map_err(AppError::Io)?;
    if existing {
        let _ = tokio::fs::remove_file(&backup).await;
        tokio::fs::rename(target, &backup).await.map_err(AppError::Io)?;
    }
    if let Err(error) = tokio::fs::rename(temporary, target).await {
        if existing && let Err(restore_error) = tokio::fs::rename(&backup, target).await {
            return Err(AppError::Other(format!("安装目标文件失败：{error}；恢复原文件失败：{restore_error}；原文件备份路径：{}", backup.display())));
        }
        return Err(AppError::Io(error));
    }
    if existing { let _ = tokio::fs::remove_file(&backup).await; }
    Ok(())
}

fn validate_remote_copy_target(source: &str, destination: &str) -> AppResult<()> {
    validate_remote_path(source)?;
    validate_remote_path(destination)?;
    let normalize = |path: &str| format!("/{}", path.split('/').filter(|part| !part.is_empty() && *part != ".").collect::<Vec<_>>().join("/"));
    let source_normalized = normalize(source);
    if source_normalized == "/" { return Err(AppError::Validation("不能复制远程根目录".into())); }
    // A remote-to-remote copy must retain POSIX names such as CON or a:b.
    // Windows device-name restrictions belong only to local downloads.
    let name = source_normalized.rsplit('/').next().unwrap_or_default();
    validate_remote_entry_name(name)?;
    let target = join_remote_path(&normalize(destination), name);
    if target == source_normalized || target.starts_with(&format!("{source_normalized}/")) {
        return Err(AppError::Validation("不能将远程文件或目录复制到自身内部".into()));
    }
    Ok(())
}

async fn collect_remote_download(sftp: &SftpSession, source: &str, relative: PathBuf, plan: &mut RemoteDownloadPlan) -> AppResult<()> {
    validate_remote_path(source)?;
    let metadata = sftp.symlink_metadata(source).await.map_err(|error| AppError::Ssh(error.to_string()))?;
    if metadata.file_type().is_symlink() { return Ok(()); }
    let target = relative.join(safe_remote_name(source)?);
    if metadata.file_type().is_dir() {
        plan.directories.push(target.clone());
        let entries = sftp.read_dir(source).await.map_err(|error| AppError::Ssh(error.to_string()))?;
        for entry in entries {
            let name = entry.file_name();
            validate_remote_entry_name(&name)?;
            safe_remote_name(&name)?;
            Box::pin(collect_remote_download(sftp, &entry.path(), target.clone(), plan)).await?;
        }
    } else {
        validate_remote_regular_file(&metadata, source)?;
        plan.files.push((source.to_string(), target, metadata.len()));
    }
    Ok(())
}

fn validate_remote_regular_file(metadata: &russh_sftp::protocol::FileAttributes, path: &str) -> AppResult<()> {
    // The SFTP permission/type field is optional. Reject an explicitly known
    // special type, while retaining interoperability with servers that omit it.
    // Do not use is_regular/is_dir here: those are bitflag containment checks
    // in russh-sftp and incorrectly classify sockets and block devices.
    let has_file_type = metadata.permissions.is_some_and(|mode| mode & 0o170000 != 0);
    if has_file_type && !metadata.file_type().is_file() {
        return Err(AppError::Validation(format!("远程路径不是普通文件，不能传输或覆盖：{path}")));
    }
    Ok(())
}

async fn run_download_transfer(manager: &SshManager, host_id: &str, remote_paths: Vec<String>, local_directory: &str, conflict_policy: &str, transfer_id: &str, ipc: IpcChannel<StreamEnvelope<TransferProgress>>, mut cancel: watch::Receiver<bool>) -> AppResult<()> {
    if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
    let local_root = PathBuf::from(local_directory);
    validate_local_download_path(&local_root, Path::new("."))?;
    let sftp = open_sftp(manager, host_id).await?;
    let mut plan = RemoteDownloadPlan::default();
    for path in &remote_paths {
        if cancelled(&cancel) { let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
        collect_remote_download(&sftp, path, PathBuf::new(), &mut plan).await?;
    }
    let total = plan.files.iter().map(|(_, _, size)| *size).sum::<u64>();
    for directory in &plan.directories {
        validate_local_download_path(&local_root, directory)?;
    }
    if cancelled(&cancel) { let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
    tokio::fs::create_dir_all(&local_root).await.map_err(AppError::Io)?;
    for directory in &plan.directories {
        if cancelled(&cancel) { let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(()); }
        tokio::fs::create_dir_all(local_root.join(directory)).await.map_err(AppError::Io)?;
    }
    let mut transferred = 0u64;
    for (index, (remote_path, relative, file_total)) in plan.files.iter().enumerate() {
        if cancelled(&cancel) { send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); let _ = sftp.close().await; return Ok(()); }
        let mut local = validate_local_download_path(&local_root, relative)?;
        if tokio::fs::try_exists(&local).await.map_err(AppError::Io)? {
            match conflict_policy {
                "overwrite" | "resume" => { validate_local_file_target(&local)?; }
                "skip" => { transferred += *file_total; continue; },
                "rename" => {
                    let original = local.clone();
                    let mut renamed = false;
                    for index in 1..=10_000u32 {
                        let candidate = renamed_local_path(&original, index)?;
                        if !tokio::fs::try_exists(&candidate).await.map_err(AppError::Io)? { local = candidate; renamed = true; break; }
                    }
                    if !renamed { return Err(AppError::Validation("无法为下载目标生成可用的新名称".into())); }
                }
                _ => return Err(AppError::Validation("目标文件已存在，请选择覆盖、跳过或重命名".into())),
            }
        }
        if let Some(parent) = local.parent() { tokio::fs::create_dir_all(parent).await.map_err(AppError::Io)?; }
        let part = PathBuf::from(format!("{}.{}.part", local.display(), transfer_id));
        // Tokio filesystem creation runs on the blocking pool: dropping its
        // future does not stop a delayed create. Finish creation before entering
        // the cancellable section so cleanup can never precede a late create.
        let output = tokio::fs::File::create(&part).await.map_err(AppError::Io)?;
        let prepare = async {
            let mut output = output;
            let mut input = sftp.open(remote_path).await.map_err(|e| AppError::Ssh(e.to_string()))?;
            let resume_offset = if conflict_policy == "resume" && tokio::fs::try_exists(&local).await.map_err(AppError::Io)? {
                let existing_len = tokio::fs::metadata(&local).await.map_err(AppError::Io)?.len();
                if existing_len > *file_total { return Err(AppError::Validation("本地目标比远程源文件更长，不能安全续传".into())); }
                if existing_len > 0 && !local_prefix_matches(&sftp, remote_path, &local, existing_len).await? { return Err(AppError::Validation("本地目标前缀与远程源文件不一致，已拒绝续传".into())); }
                existing_len
            } else { 0 };
            if resume_offset > 0 { copy_local_prefix(&local, &mut output, resume_offset).await?; input.seek(SeekFrom::Start(resume_offset)).await.map_err(|e| AppError::Ssh(e.to_string()))?; }
            let mut current = resume_offset; transferred += resume_offset; let mut buffer = vec![0u8; 64 * 1024]; let mut last_emit = Instant::now() - Duration::from_secs(1);
            loop {
                let n = input.read(&mut buffer).await.map_err(|e| AppError::Ssh(e.to_string()))?;
                if n == 0 { break; }
                output.write_all(&buffer[..n]).await.map_err(AppError::Io)?;
                current += n as u64; transferred += n as u64;
                if last_emit.elapsed() >= Duration::from_millis(120) || current == *file_total { last_emit = Instant::now(); let _ = ipc.send(StreamEnvelope { seq: manager.sequence.fetch_add(1, Ordering::Relaxed), timestamp: chrono::Utc::now().to_rfc3339(), host_id: host_id.into(), session_id: None, payload: TransferProgress { transfer_id: transfer_id.into(), host_id: host_id.into(), direction: "download".into(), current_path: remote_path.clone(), transferred, total, status: "running".into(), error: None, file_index: index as u32 + 1, file_count: plan.files.len() as u32, current_file_transferred: current, current_file_total: *file_total } }); }
            }
            output.flush().await.map_err(AppError::Io)?; drop(output);
            validate_transfer_size(*file_total, current)
        };
        if store_local_transfer_file(&part, &local, transfer_id, &mut cancel, prepare).await? {
            let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "cancelled", None); return Ok(());
        }
    }
    let _ = sftp.close().await; send_transfer_state(&manager.sequence, &ipc, host_id, transfer_id, "completed", None); Ok(())
}

async fn bridge_tcp(
    connection: Arc<ManagedConnection>,
    local: &mut TcpStream,
    host: &str,
    port: u16,
) -> AppResult<()> {
    let channel = open_direct_tcpip(connection, host, port).await?;
    let mut remote = channel.into_stream();
    tokio::io::copy_bidirectional(local, &mut remote).await.map_err(AppError::Io)?;
    Ok(())
}

async fn open_direct_tcpip(
    connection: Arc<ManagedConnection>,
    host: &str,
    port: u16,
) -> AppResult<russh::Channel<client::Msg>> {
    let handle = connection.handle.lock().await;
    handle
        .channel_open_direct_tcpip(host, port as u32, "127.0.0.1", 0)
        .await
        .map_err(|e| AppError::Ssh(e.to_string()))
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
    if !methods.contains(&0) {
        stream.write_all(&[5, 0xff]).await.map_err(AppError::Io)?;
        return Err(AppError::Validation("SOCKS5 客户端未提供无认证方式".into()));
    }
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
        4 => {
            let mut bytes = [0u8; 16];
            stream.read_exact(&mut bytes).await.map_err(AppError::Io)?;
            std::net::Ipv6Addr::from(bytes).to_string()
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

    const NONCE: &str = "0123456789abcdef0123456789abcdef";

    fn marker(sequence: u64, kind: &str, status: i32, payload: &str) -> Vec<u8> {
        format!(
            "\x1b]777;sshops;v1;{NONCE};{kind};{sequence};{status};{}\x07",
            BASE64_STANDARD.encode(payload)
        )
        .into_bytes()
    }

    #[test]
    fn parses_split_frames_and_preserves_visible_output() {
        let ready = marker(1, "ready", 0, "bash");
        let frame = marker(2, "command", 0, "sudo apt update");
        let split = frame.len() / 2;
        let mut parser = TerminalAuditParser::new(NONCE.into());
        assert_eq!(parser.push(&ready).1, vec![(1, TerminalAuditEventKind::Ready { shell: "bash".into() })]);
        let (first_visible, first_events) = parser.push(&[b"prompt> ".as_slice(), &frame[..split]].concat());
        assert_eq!(first_visible, b"prompt> ");
        assert!(first_events.is_empty());
        let (second_visible, second_events) = parser.push(&[&frame[split..], b"next prompt".as_slice()].concat());
        assert_eq!(second_visible, b"next prompt");
        assert_eq!(second_events, vec![(2, TerminalAuditEventKind::Command { command: "sudo apt update".into(), exit_code: 0 })]);
    }

    #[test]
    fn preserves_first_command_field_unicode_and_exit_code() {
        let command = "printf '中文参数' | sed s/参数/命令/";
        let mut parser = TerminalAuditParser::new(NONCE.into());
        parser.push(&marker(1, "ready", 0, "bash"));
        assert_eq!(parser.push(&marker(2, "command", 7, command)).1, vec![(2, TerminalAuditEventKind::Command { command: command.into(), exit_code: 7 })]);
    }

    #[test]
    fn rejects_wrong_nonce_replays_and_commands_before_ready() {
        let mut parser = TerminalAuditParser::new(NONCE.into());
        assert!(parser.push(&marker(1, "command", 0, "whoami")).1.is_empty());
        let wrong = format!(
            "\x1b]777;sshops;v1;ffffffffffffffffffffffffffffffff;ready;2;0;{}\x07",
            BASE64_STANDARD.encode("bash")
        );
        assert!(parser.push(wrong.as_bytes()).1.is_empty());
        assert_eq!(parser.push(&marker(3, "ready", 0, "bash")).1.len(), 1);
        assert!(parser.push(&marker(3, "command", 0, "replayed")).1.is_empty());
    }

    #[test]
    fn filters_internal_bootstrap_after_ready() {
        let mut parser = TerminalAuditParser::new(NONCE.into());
        parser.push(&marker(1, "ready", 0, "bash"));
        assert!(parser.push(&marker(2, "command", 0, &shell_audit_bootstrap(NONCE))).1.is_empty());
    }

    #[test]
    fn leaves_unrelated_osc_sequences_visible() {
        let mut parser = TerminalAuditParser::new(NONCE.into());
        let input = b"\x1b]0;window title\x07hello";
        let (visible, events) = parser.push(input);
        assert_eq!(visible, input);
        assert!(events.is_empty());
    }

    #[test]
    fn bootstrap_preserves_terminal_output_and_installs_safe_hooks() {
        let bootstrap = shell_audit_bootstrap(NONCE);
        assert!(!bootstrap.contains("[2J"));
        assert!(!bootstrap.contains("sudo su"));
        assert!(bootstrap.contains("READLINE_LINE"));
        assert!(bootstrap.contains("PROMPT_COMMAND+=(__sshops_precmd)"));
        assert!(bootstrap.contains("trap -p DEBUG"));
    }

    #[test]
    fn bash_integration_captures_complete_commands_without_the_bootstrap() {
        use std::io::Write as _;
        use std::process::{Command, Stdio};

        let candidates = [
            PathBuf::from(r"C:\msys64\usr\bin\bash.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"),
            PathBuf::from("/bin/bash"),
        ];
        let Some(bash) = candidates.into_iter().find(|path| path.exists()) else { return };
        let mut child = Command::new(bash)
            .args(["--noprofile", "--norc", "-i"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = format!(
            "PATH=/usr/bin:$PATH\nHISTCONTROL=ignoreboth\nPROMPT_COMMAND=('true')\ntrap ':' DEBUG\n{}\nprintf 'first field 中文\\n'\nprintf 'repeat\\n'\nprintf 'repeat\\n'\nprintf 'pipe\\n' | tr a-z A-Z\nfalse\n printf 'hidden\\n'\nexit\n",
            shell_audit_bootstrap(NONCE)
        );
        child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        let mut parser = TerminalAuditParser::new(NONCE.into());
        let (_, events) = parser.push(&output.stdout);
        let commands = events
            .into_iter()
            .filter_map(|(_, event)| match event {
                TerminalAuditEventKind::Command { command, exit_code } => Some((command, exit_code)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(commands, vec![
            ("printf 'first field 中文\\n'".into(), 0),
            ("printf 'repeat\\n'".into(), 0),
            ("printf 'repeat\\n'".into(), 0),
            ("printf 'pipe\\n' | tr a-z A-Z".into(), 0),
            ("false".into(), 1),
        ]);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("__sshops_notice="));
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
    fn rejects_windows_path_escape_names() {
        for name in ["C:escape.txt", "secret.txt:stream", "NUL", "COM1.txt", "folder\\child", "trailing."] {
            assert!(safe_remote_name(name).is_err(), "accepted unsafe name {name}");
        }
        assert!(safe_remote_name("normal.txt").is_ok());
    }

    #[test]
    fn remote_copy_rejects_same_path_and_descendants() {
        assert!(validate_remote_copy_target("/srv/data", "/srv").is_err());
        assert!(validate_remote_copy_target("/srv/data", "/srv/data/subdir").is_err());
        assert!(validate_remote_copy_target("/srv/data", "/backup").is_ok());
    }
}

#[cfg(test)]
mod path_regression_tests {
    use super::*;

    #[test]
    fn sftp_errors_use_status_codes_instead_of_server_message_text() {
        use russh_sftp::{client::error::Error, protocol::{Status, StatusCode}};
        let error = |code, message: &str| Error::Status(Status { id: 0, status_code: code, error_message: message.into(), language_tag: "zh".into() });
        assert!(sftp_not_found(&error(StatusCode::NoSuchFile, "没有此文件")));
        assert!(!sftp_not_found(&error(StatusCode::PermissionDenied, "not found in allowed paths")));
        assert!(!sftp_not_found(&Error::Timeout));
    }

    #[tokio::test]
    async fn file_replacement_preserves_an_existing_directory() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("important");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep.txt"), b"original").unwrap();
        let part = root.path().join("download.part");
        std::fs::write(&part, b"download").unwrap();
        assert!(replace_local_file(&part, &target, "test").await.is_err());
        assert_eq!(std::fs::read(target.join("keep.txt")).unwrap(), b"original");
        assert!(part.exists());
    }

    #[tokio::test]
    async fn file_replacement_restores_original_when_installation_fails() {
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("file");
        std::fs::write(&target, b"original").unwrap();
        assert!(replace_local_file(&root.path().join("missing"), &target, "test").await.is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[tokio::test]
    async fn resume_comparison_accepts_different_read_chunk_sizes() {
        struct ShortReader { data: &'static [u8] }
        impl tokio::io::AsyncRead for ShortReader {
            fn poll_read(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>, buffer: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
                let count = self.data.len().min(buffer.remaining()).min(2);
                buffer.put_slice(&self.data[..count]); self.data = &self.data[count..];
                std::task::Poll::Ready(Ok(()))
            }
        }
        assert!(prefixes_match(&mut ShortReader { data: b"same content" }, &mut &b"same content"[..], 12).await.unwrap());
        assert!(!prefixes_match(&mut ShortReader { data: b"same" }, &mut &b"same content"[..], 12).await.unwrap());
        assert!(!prefixes_match(&mut ShortReader { data: b"other" }, &mut &b"wrong"[..], 5).await.unwrap());
    }

    #[test]
    fn changed_source_size_cannot_replace_a_complete_target() {
        assert!(validate_transfer_size(100, 90).is_err());
        assert!(validate_transfer_size(100, 110).is_err());
        assert!(validate_transfer_size(100, 100).is_ok());
        assert!(validate_transfer_size(0, 0).is_ok());
    }

    #[test]
    fn deletion_rejects_root_and_current_directory_aliases() {
        for path in ["/", "//", "/./", ".", "./", "..", "/safe/../"] {
            assert!(validate_delete_target(path).is_err(), "{path}");
        }
        assert!(validate_delete_target("/srv/data").is_ok());
    }

    #[test]
    fn conflict_rename_only_changes_the_basename() {
        assert_eq!(renamed_remote_path("/srv/releases.v2/README", 1), "/srv/releases.v2/README (1)");
        assert_eq!(renamed_remote_path("/srv/.env", 2), "/srv/.env (2)");
        assert_eq!(renamed_remote_path("/srv/archive.tar.gz", 3), "/srv/archive.tar (3).gz");
    }

    #[test]
    fn copy_rejects_normalized_self_and_descendants() {
        assert!(validate_remote_copy_target("/srv/data", "/srv/./data/sub").is_err());
        assert!(validate_remote_copy_target("/srv//data/", "/srv").is_err());
        assert!(validate_remote_copy_target("/", "/backup").is_err());
        assert!(validate_remote_copy_target("/srv/data", "/srv/database").is_ok());
    }

    #[test]
    fn download_stays_inside_its_root() {
        let directory = tempfile::tempdir().unwrap();
        assert!(validate_local_download_path(directory.path(), Path::new("../escape")).is_err());
        assert_eq!(validate_local_download_path(directory.path(), Path::new("nested/file")).unwrap(), directory.path().join("nested/file"));
    }

    #[cfg(unix)]
    #[test]
    fn download_rejects_dangling_links() {
        let directory = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(directory.path().join("missing"), directory.path().join("link")).unwrap();
        assert!(validate_local_download_path(directory.path(), Path::new("link")).is_err());
    }
}
