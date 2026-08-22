mod db;
mod error;
mod firewall;
mod models;
mod monitor;
mod security;
mod ssh;

use chrono::Utc;
use db::Database;
use error::{AppError, AppResult};
use firewall::FirewallManager;
use models::*;
use monitor::MonitorManager;
use parking_lot::Mutex;
use ssh::{SshManager, TerminalAuditEvent, TerminalAuditEventKind};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tauri::{Manager, State, ipc::Channel};
use uuid::Uuid;

struct AppState {
    db: Arc<Database>,
    ssh: Arc<SshManager>,
    monitor: Arc<MonitorManager>,
    firewall: Arc<FirewallManager>,
    command_channels: Arc<Mutex<Vec<Channel<StreamEnvelope<CommandRecord>>>>>,
    command_sequence: Arc<AtomicU64>,
}

fn emit_command(state: &AppState, record: CommandRecord) {
    persist_and_emit_command(&state.db, &state.command_channels, &state.command_sequence, record);
}

fn persist_and_emit_command(db: &Database, channels: &Mutex<Vec<Channel<StreamEnvelope<CommandRecord>>>>, sequence: &AtomicU64, record: CommandRecord) {
    if db.command_add(&record).is_err() { return; }
    let envelope = StreamEnvelope {
        seq: sequence.fetch_add(1, Ordering::Relaxed),
        timestamp: record.timestamp.clone(),
        host_id: record.host_id.clone().unwrap_or_default(),
        session_id: None,
        payload: record,
    };
    let mut channels = channels.lock();
    channels.retain(|channel| channel.send(envelope.clone()).is_ok());
}

fn operation_record(
    state: &AppState,
    host_id: Option<String>,
    source: &str,
    command: String,
    status: &str,
    stdout: String,
    stderr: String,
) {
    let host_name = host_id
        .as_deref()
        .and_then(|id| state.ssh.profile(id).ok())
        .map(|h| h.name);
    emit_command(
        state,
        CommandRecord {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            host_id,
            host_name,
            source: source.into(),
            command,
            stdout,
            stderr,
            exit_code: Some(if status == "success" { 0 } else { 1 }),
            duration_ms: 0,
            status: status.into(),
            repeat_count: 1,
            equivalent: Some(true),
            operation_kind: Some(source.into()),
        },
    );
}

#[tauri::command]
fn hosts_list(state: State<'_, AppState>) -> AppResult<Vec<HostProfile>> {
    let mut hosts = state.db.hosts_list()?;
    for host in &mut hosts {
        if state.ssh.is_connected(&host.id) {
            host.status = "connected".into()
        }
    }
    Ok(hosts)
}
#[tauri::command]
fn hosts_upsert(state: State<'_, AppState>, draft: HostDraft) -> AppResult<HostProfile> {
    if draft.name.trim().is_empty()
        || draft.hostname.trim().is_empty()
        || draft.username.trim().is_empty()
    {
        return Err(AppError::Validation("名称、主机和用户名不能为空".into()));
    }
    if draft.port == 0 {
        return Err(AppError::Validation("端口必须在 1–65535 之间".into()));
    }
    let now = Utc::now().to_rfc3339();
    let id = draft.id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let existing = state.db.host_get(&id).ok();
    let old_credential_id = existing.as_ref().and_then(|host| host.credential_id.clone());
    let mut credential_id = draft
        .credential_id
        .or_else(|| existing.as_ref().and_then(|h| h.credential_id.clone()));
    if draft.auth_method != "password" || draft.remember_password == Some(false) {
        credential_id = None;
    }
    if draft.remember_password.unwrap_or(false) {
        if let Some(password) = draft.password.as_deref() {
            let cid = credential_id.unwrap_or_else(|| format!("ssh:{id}"));
            security::store_secret(&cid, password)?;
            credential_id = Some(cid)
        }
    }
    let host = HostProfile {
        id: id.clone(),
        name: draft.name.trim().into(),
        hostname: draft.hostname.trim().into(),
        port: draft.port,
        username: draft.username.trim().into(),
        group_name: draft.group_name.trim().into(),
        tags: draft.tags,
        favorite: draft.favorite,
        auth_method: draft.auth_method,
        credential_id,
        private_key_path: draft.private_key_path,
        jump_hosts: draft.jump_hosts.unwrap_or_default(),
        host_key_fingerprint: draft.host_key_fingerprint,
        status: if state.ssh.is_connected(&id) {
            "connected".into()
        } else {
            "disconnected".into()
        },
        last_connected_at: existing.as_ref().and_then(|h| h.last_connected_at.clone()),
        created_at: existing
            .map(|h| h.created_at)
            .unwrap_or_else(|| now.clone()),
        updated_at: now,
    };
    state.db.host_upsert(&host)?;
    if old_credential_id.as_deref() != host.credential_id.as_deref() {
        if let Some(old) = old_credential_id { let _ = security::delete_secret(&old); }
    }
    Ok(host)
}
#[tauri::command]
async fn hosts_delete(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.monitor.stop(&id);
    if let Ok(profiles) = state.db.forward_list(&id) {
        for profile in profiles { state.ssh.forward_stop(&profile.id); }
    }
    let credential_id = state.db.host_get(&id).ok().and_then(|host| host.credential_id);
    let _ = state.ssh.disconnect(&id).await;
    state.db.host_delete(&id)?;
    if let Some(cid) = credential_id { let _ = security::delete_secret(&cid); }
    Ok(())
}
#[tauri::command]
fn credentials_set(id: String, value: String) -> AppResult<()> {
    security::store_secret(&id, &value)
}
#[tauri::command]
fn credentials_delete(id: String) -> AppResult<()> {
    security::delete_secret(&id)
}

#[tauri::command]
async fn ssh_connect(
    state: State<'_, AppState>,
    host_id: String,
    password: Option<String>,
) -> AppResult<()> {
    let mut host = state.db.host_get(&host_id)?;
    let started = std::time::Instant::now();
    let result = state.ssh.connect(&state.db, host.clone(), password).await;
    host.status = if result.is_ok() {
        "connected".into()
    } else {
        "error".into()
    };
    if result.is_ok() {
        host.last_connected_at = Some(Utc::now().to_rfc3339())
    }
    host.updated_at = Utc::now().to_rfc3339();
    let _ = state.db.host_upsert(&host);
    let record = CommandRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        host_id: Some(host_id.clone()),
        host_name: Some(host.name),
        source: "connection".into(),
        command: format!("ssh -p {} {}@{}", host.port, host.username, host.hostname),
        stdout: if result.is_ok() {
            "SSH 连接已建立".into()
        } else {
            "".into()
        },
        stderr: result
            .as_ref()
            .err()
            .map(ToString::to_string)
            .unwrap_or_default(),
        exit_code: Some(if result.is_ok() { 0 } else { 1 }),
        duration_ms: started.elapsed().as_millis() as u64,
        status: if result.is_ok() {
            "success".into()
        } else {
            "error".into()
        },
        repeat_count: 1,
        equivalent: Some(true),
        operation_kind: Some("connection".into()),
    };
    emit_command(&state, record);
    result
}
#[tauri::command]
async fn ssh_disconnect(state: State<'_, AppState>, host_id: String) -> AppResult<()> {
    state.monitor.stop(&host_id);
    state.ssh.disconnect(&host_id).await
}

#[tauri::command]
async fn terminal_open(
    state: State<'_, AppState>,
    host_id: String,
    cols: u32,
    rows: u32,
    channel: Channel<StreamEnvelope<Vec<u8>>>,
    command_logging: Option<bool>,
) -> AppResult<String> {
    let (audit_sender, mut audit_receiver) = tokio::sync::mpsc::unbounded_channel::<TerminalAuditEvent>();
    let session_id = state.ssh.terminal_open(&host_id, cols, rows, channel, command_logging.unwrap_or(true), audit_sender).await?;
    let db = state.db.clone();
    let command_channels = state.command_channels.clone();
    let command_sequence = state.command_sequence.clone();
    tokio::spawn(async move {
        while let Some(event) = audit_receiver.recv().await {
            let TerminalAuditEventKind::Command { command, exit_code } = event.kind else { continue };
            let command = security::redact(&command);
            if command.trim().is_empty() || command.trim_start().starts_with("__sshops_") { continue; }
            let host_name = db.host_get(&event.host_id).ok().map(|host| host.name);
            let record = CommandRecord { id: format!("terminal:{}:{}", event.session_id, event.sequence), timestamp: event.timestamp, host_id: Some(event.host_id), host_name, source: "terminal".into(), command, stdout: String::new(), stderr: String::new(), exit_code: Some(exit_code), duration_ms: 0, status: if exit_code == 0 { "success".into() } else { "error".into() }, repeat_count: 1, equivalent: None, operation_kind: Some("terminal.shell".into()) };
            persist_and_emit_command(&db, &command_channels, &command_sequence, record);
        }
    });
    Ok(session_id)
}
#[tauri::command]
async fn terminal_input(
    state: State<'_, AppState>,
    session_id: String,
    data: Vec<u8>,
) -> AppResult<()> {
    state.ssh.terminal_input(&session_id, data).await
}
#[tauri::command]
async fn terminal_resize(
    state: State<'_, AppState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> AppResult<()> {
    state.ssh.terminal_resize(&session_id, cols, rows).await
}
#[tauri::command]
async fn terminal_close(state: State<'_, AppState>, session_id: String) -> AppResult<()> {
    state.ssh.terminal_close(&session_id).await
}

#[tauri::command]
fn monitor_start(
    state: State<'_, AppState>,
    host_id: String,
    channel: Channel<StreamEnvelope<MetricSnapshot>>,
) -> AppResult<String> {
    if !state.ssh.is_connected(&host_id) {
        return Err(AppError::Validation("服务器尚未建立 SSH 连接".into()));
    }
    state
        .monitor
        .start(host_id, state.ssh.clone(), state.db.clone(), channel)
}
#[tauri::command]
fn monitor_stop(state: State<'_, AppState>, host_id: String) {
    state.monitor.stop(&host_id)
}
#[tauri::command]
fn monitor_query(
    state: State<'_, AppState>,
    host_id: String,
    range: String,
) -> AppResult<Vec<MetricSnapshot>> {
    let duration = match range.as_str() {
        "1h" => chrono::Duration::hours(1),
        "24h" => chrono::Duration::hours(24),
        _ => chrono::Duration::days(7),
    };
    state
        .db
        .metrics(&host_id, &(Utc::now() - duration).to_rfc3339())
}

#[tauri::command]
async fn firewall_read(state: State<'_, AppState>, host_id: String) -> AppResult<FirewallState> {
    state.firewall.read(&state.ssh, &host_id).await
}
#[tauri::command]
async fn firewall_plan(
    state: State<'_, AppState>,
    host_id: String,
    change: FirewallChange,
) -> AppResult<FirewallPlan> {
    state.firewall.plan(&state.ssh, &host_id, change).await
}
#[tauri::command]
async fn firewall_apply(
    state: State<'_, AppState>,
    plan_id: String,
    sudo_password: Option<String>,
    remember_sudo: Option<bool>,
) -> AppResult<serde_json::Value> {
    let host_id = state.firewall.plan_host(&plan_id);
    let remembered = if sudo_password.is_none() { host_id.as_deref().and_then(|id| security::read_secret(&format!("sudo:{id}")).ok()) } else { None };
    let effective_password = sudo_password.or(remembered);
    let result = state.firewall.apply(&state.ssh, &state.db, &plan_id, effective_password.as_deref()).await;
    if result.is_ok() && remember_sudo.unwrap_or(false) {
        if let Some(password) = effective_password.as_deref() {
            if let Some(host_id) = host_id {
                let _ = security::store_secret(&format!("sudo:{host_id}"), password);
            }
        }
    }
    result
}
#[tauri::command]
async fn firewall_commit(state: State<'_, AppState>, plan_id: String) -> AppResult<()> {
    state.firewall.commit(&state.ssh, &plan_id).await
}
#[tauri::command]
async fn firewall_rollback(state: State<'_, AppState>, plan_id: String) -> AppResult<()> {
    state.firewall.rollback(&state.ssh, &plan_id).await
}

#[tauri::command]
fn command_log_query(
    state: State<'_, AppState>,
    host_id: Option<String>,
) -> AppResult<Vec<CommandRecord>> {
    state.db.commands(host_id.as_deref())
}
#[tauri::command]
fn command_log_subscribe(
    state: State<'_, AppState>,
    channel: Channel<StreamEnvelope<CommandRecord>>,
) -> AppResult<()> {
    state.command_channels.lock().push(channel);
    Ok(())
}
#[tauri::command]
fn command_log_export(
    state: State<'_, AppState>,
    path: PathBuf,
    host_id: Option<String>,
    records: Option<Vec<CommandRecord>>,
) -> AppResult<()> {
    let records = match records { Some(records) => records, None => state.db.commands(host_id.as_deref())? };
    let text = records
        .into_iter()
        .map(|r| {
            format!(
                "[{}] {} $ {}\n{}{}",
                r.timestamp,
                r.host_name.unwrap_or_else(|| "local".into()),
                r.command,
                r.stdout,
                r.stderr
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(path, text)?;
    Ok(())
}

#[tauri::command]
fn command_log_clear(state: State<'_, AppState>) -> AppResult<()> {
    state.db.command_clear()
}

fn default_settings() -> AppSettings {
    AppSettings { version: 2, locale: "zh".into(), theme: "system".into(), default_page: "monitor".into(), terminal_font_size: 13, terminal_scrollback: 10000, terminal_paste_protection: true, terminal_command_logging: true, monitor_interval_seconds: 2, transfer_conflict_policy: "ask".into(), command_retention_days: 7, command_retention_mb: 100, suppression_rules: vec![CommandSuppressionRule { id: "monitor-sample".into(), enabled: true, source: Some("monitor".into()), host_id: None, operation_kind: Some("monitor.sample".into()), contains: None }] }
}

fn normalize_settings(mut settings: AppSettings) -> AppSettings {
    if settings.version < 2 {
        for rule in &mut settings.suppression_rules {
            if rule.id == "monitor-sample" && rule.source.as_deref() == Some("monitor") {
                rule.operation_kind = Some("monitor.sample".into());
                rule.contains = None;
            }
        }
        settings.version = 2;
    }
    for rule in &mut settings.suppression_rules {
        rule.source = rule.source.as_ref().map(|value| value.trim().to_lowercase()).filter(|value| !value.is_empty());
        rule.host_id = rule.host_id.as_ref().map(|value| value.trim().to_string()).filter(|value| !value.is_empty());
        rule.operation_kind = rule.operation_kind.as_ref().map(|value| value.trim().to_lowercase()).filter(|value| !value.is_empty());
        rule.contains = rule.contains.as_ref().map(|value| value.trim().to_lowercase()).filter(|value| !value.is_empty());
    }
    settings
}

#[tauri::command]
fn settings_get(state: State<'_, AppState>) -> AppResult<AppSettings> {
    let stored = state.db.setting_get("app")?;
    let settings = stored.as_deref().and_then(|value| serde_json::from_str(value).ok()).unwrap_or_else(default_settings);
    let normalized = normalize_settings(settings);
    // Persist migrations and trimmed rule fields so the same legacy value is not
    // reinterpreted on every startup.
    let serialized = serde_json::to_string(&normalized).map_err(|e| AppError::Other(e.to_string()))?;
    if stored.as_deref() != Some(serialized.as_str()) {
        state.db.setting_set("app", &serialized)?;
    }
    Ok(normalized)
}

#[tauri::command]
fn settings_update(state: State<'_, AppState>, settings: AppSettings) -> AppResult<AppSettings> {
    let settings = normalize_settings(settings);
    let value = serde_json::to_string(&settings).map_err(|e| AppError::Other(e.to_string()))?;
    state.db.setting_set("app", &value)?;
    Ok(settings)
}

#[tauri::command]
fn settings_reset(state: State<'_, AppState>) -> AppResult<AppSettings> {
    let settings = default_settings();
    let value = serde_json::to_string(&settings).map_err(|e| AppError::Other(e.to_string()))?;
    state.db.setting_set("app", &value)?;
    Ok(settings)
}

#[allow(unreachable_code)]
#[tauri::command]
async fn sftp_list(
    state: State<'_, AppState>,
    host_id: String,
    path: String,
) -> AppResult<Vec<SftpEntry>> {
    let started = std::time::Instant::now();
    let entries = state.ssh.sftp_list(&host_id, &path).await?;
    let _ = state.db.command_add(&CommandRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        host_id: Some(host_id.clone()),
        host_name: state.ssh.profile(&host_id).ok().map(|h| h.name),
        source: "sftp".into(),
        command: format!("sftp> ls -la {}", path),
        stdout: format!("列出 {} 个条目", entries.len()),
        stderr: String::new(),
        exit_code: Some(0),
        duration_ms: started.elapsed().as_millis() as u64,
        status: "success".into(),
        repeat_count: 1,
        equivalent: Some(true),
        operation_kind: Some("sftp.list".into()),
    });
    return Ok(entries);

    let quoted = security::shell_quote(&path)?;
    let cmd = format!(
        "LANG=C find {quoted} -mindepth 1 -maxdepth 1 -printf '%y\\t%s\\t%T@\\t%m\\t%f\\n' 2>/dev/null | head -n 1000"
    );
    let output = state.ssh.exec(&host_id, &cmd).await?;
    if output.exit_code != 0 {
        return Err(AppError::Other(output.stderr));
    }
    let base = path.trim_end_matches('/');
    let entries: Vec<SftpEntry> = output
        .stdout
        .lines()
        .filter_map(|line| {
            let p: Vec<&str> = line.splitn(5, '\t').collect();
            if p.len() != 5 {
                return None;
            }
            let name = p[4].to_string();
            Some(SftpEntry {
                name: name.clone(),
                path: format!("{}/{}", if base.is_empty() { "" } else { base }, name),
                kind: match p[0] {
                    "d" => "directory",
                    "l" => "symlink",
                    _ => "file",
                }
                .into(),
                size: p[1].parse().unwrap_or(0),
                modified_at: None,
                permissions: Some(p[3].into()),
            })
        })
        .collect();
    let _ = state.db.command_add(&CommandRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: Utc::now().to_rfc3339(),
        host_id: Some(host_id.clone()),
        host_name: state.ssh.profile(&host_id).ok().map(|h| h.name),
        source: "sftp".into(),
        command: format!("sftp> ls -la {}", path),
        stdout: format!("列出 {} 个条目", entries.len()),
        stderr: output.stderr,
        exit_code: Some(output.exit_code),
        duration_ms: output.duration_ms,
        status: "success".into(),
        repeat_count: 1,
        equivalent: Some(true),
        operation_kind: Some("sftp.list".into()),
    });
    Ok(entries)
}

#[tauri::command]
async fn sftp_upload(
    state: State<'_, AppState>,
    host_id: String,
    local_paths: Vec<String>,
    remote_directory: String,
    channel: Channel<StreamEnvelope<TransferProgress>>,
) -> AppResult<String> {
    state.ssh.sftp_upload(&host_id, local_paths, &remote_directory, channel).await
}

#[tauri::command]
async fn sftp_start_upload(
    state: State<'_, AppState>,
    host_id: String,
    local_paths: Vec<String>,
    remote_directory: String,
    channel: Channel<StreamEnvelope<TransferProgress>>,
) -> AppResult<String> {
    sftp_upload(state, host_id, local_paths, remote_directory, channel).await
}

#[tauri::command]
async fn sftp_download(
    state: State<'_, AppState>,
    host_id: String,
    remote_paths: Vec<String>,
    local_directory: String,
    channel: Channel<StreamEnvelope<TransferProgress>>,
) -> AppResult<String> {
    state.ssh.sftp_download(&host_id, remote_paths, &local_directory, channel).await
}

#[tauri::command]
async fn sftp_start_download(
    state: State<'_, AppState>,
    host_id: String,
    remote_paths: Vec<String>,
    local_directory: String,
    channel: Channel<StreamEnvelope<TransferProgress>>,
) -> AppResult<String> {
    sftp_download(state, host_id, remote_paths, local_directory, channel).await
}

#[tauri::command]
async fn sftp_delete(state: State<'_, AppState>, host_id: String, paths: Vec<String>) -> AppResult<()> {
    state.ssh.sftp_delete(&host_id, &paths).await?;
    operation_record(&state, Some(host_id), "sftp", format!("sftp> rm {}", paths.join(" ")), "success", String::new(), String::new());
    Ok(())
}
#[tauri::command]
async fn sftp_rename(state: State<'_, AppState>, host_id: String, path: String, new_path: String) -> AppResult<()> {
    state.ssh.sftp_rename(&host_id, &path, &new_path).await?;
    operation_record(&state, Some(host_id), "sftp", format!("sftp> rename {} {}", path, new_path), "success", String::new(), String::new());
    Ok(())
}
#[tauri::command]
async fn sftp_mkdir(state: State<'_, AppState>, host_id: String, path: String) -> AppResult<()> {
    state.ssh.sftp_mkdir(&host_id, &path).await?;
    operation_record(&state, Some(host_id), "sftp", format!("sftp> mkdir {}", path), "success", String::new(), String::new());
    Ok(())
}
#[tauri::command]
async fn sftp_start_copy(state: State<'_, AppState>, host_id: String, sources: Vec<String>, destination_directory: String, channel: Channel<StreamEnvelope<TransferProgress>>) -> AppResult<String> {
    state.ssh.sftp_copy(&host_id, sources, destination_directory, channel).await
}

#[tauri::command]
fn sftp_cancel(state: State<'_, AppState>, transfer_id: String) -> AppResult<()> {
    state.ssh.transfer_cancel(&transfer_id);
    Ok(())
}

#[tauri::command]
fn forward_list(state: State<'_, AppState>, host_id: String) -> AppResult<Vec<ForwardingProfile>> {
    state.db.forward_list(&host_id)
}
#[tauri::command]
fn forward_upsert(
    state: State<'_, AppState>,
    mut profile: ForwardingProfile,
) -> AppResult<ForwardingProfile> {
    if profile.bind_port == 0 {
        return Err(AppError::Validation("监听端口无效".into()));
    }
    profile.active = false;
    profile.status = "stopped".into();
    profile.last_error = None;
    state.db.forward_upsert(&profile)?;
    Ok(profile)
}
#[tauri::command]
async fn forward_start(state: State<'_, AppState>, id: String) -> AppResult<ForwardingProfile> {
    let mut profile = state
        .db
        .forward_list("")?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::NotFound("port forward".into()))?;
    profile.status = "starting".into();
    state.db.forward_upsert(&profile)?;
    match state.ssh.forward_start(&profile).await {
        Ok(()) => {
            profile.active = true;
            profile.status = "active".into();
            profile.last_error = None;
            state.db.forward_upsert(&profile)?;
            operation_record(
                &state,
                Some(profile.host_id.clone()),
                "forward",
                format!("ssh -{} {}", profile.kind, profile.bind_port),
                "success",
                String::new(),
                String::new(),
            );
            Ok(profile)
        }
        Err(err) => {
            profile.active = false;
            profile.status = "error".into();
            profile.last_error = Some(err.to_string());
            state.db.forward_upsert(&profile)?;
            operation_record(
                &state,
                Some(profile.host_id.clone()),
                "forward",
                format!("ssh -{} {}", profile.kind, profile.bind_port),
                "error",
                String::new(),
                err.to_string(),
            );
            Err(err)
        }
    }
}
#[tauri::command]
fn forward_stop(state: State<'_, AppState>, id: String) -> AppResult<ForwardingProfile> {
    state.ssh.forward_stop(&id);
    let mut profile = state
        .db
        .forward_list("")?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::NotFound("port forward".into()))?;
    profile.active = false;
    profile.status = "stopped".into();
    profile.last_error = None;
    state.db.forward_upsert(&profile)?;
    operation_record(
        &state,
        Some(profile.host_id.clone()),
        "forward",
        format!("ssh -stop {}", id),
        "success",
        String::new(),
        String::new(),
    );
    Ok(profile)
}
#[allow(dead_code)]
fn toggle_forward(state: &State<'_, AppState>, id: &str, active: bool) -> AppResult<()> {
    let mut profile = state
        .db
        .forward_list("")?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| AppError::NotFound("端口转发".into()))?;
    profile.active = active;
    state.db.forward_upsert(&profile)
}

#[tauri::command]
fn forward_delete(state: State<'_, AppState>, id: String) -> AppResult<()> {
    state.ssh.forward_stop(&id);
    state.db.forward_delete(&id)
}

#[tauri::command]
fn config_export(state: State<'_, AppState>, path: PathBuf, host_id: Option<String>) -> AppResult<()> {
    let hosts = if let Some(id) = host_id {
        vec![state.db.host_get(&id)?]
    } else {
        state.db.hosts_list()?
    };
    let hosts = hosts.into_iter().map(|host| {
        let mut value = serde_json::to_value(host).map_err(|error| AppError::Other(error.to_string()))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("credentialId");
            object.insert("status".into(), serde_json::Value::String("disconnected".into()));
        }
        Ok::<_, AppError>(value)
    }).collect::<AppResult<Vec<_>>>()?;
    std::fs::write(
        path,
        serde_json::to_vec_pretty(
            &serde_json::json!({"version":2,"exportedAt":Utc::now(),"hosts":hosts}),
        )
        .map_err(|e| AppError::Other(e.to_string()))?,
    )?;
    Ok(())
}
#[tauri::command]
fn config_import(state: State<'_, AppState>, path: PathBuf) -> AppResult<Vec<HostProfile>> {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|e| AppError::Validation(e.to_string()))?;
    let hosts: Vec<HostProfile> =
        serde_json::from_value(value.get("hosts").cloned().unwrap_or_default())
            .map_err(|e| AppError::Validation(e.to_string()))?;
    let existing = state
        .db
        .hosts_list()?
        .into_iter()
        .map(|h| h.id)
        .collect::<std::collections::HashSet<_>>();
    for host in &hosts {
        if !existing.contains(&host.id) {
            state.db.host_upsert(host)?
        }
    }
    Ok(hosts)
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let db = Arc::new(
                Database::open(&dir.join("ssh-operations.db"))
                    .map_err(|e| Box::<dyn std::error::Error>::from(e.to_string()))?,
            );
            if db.setting_get("migration.terminal-audit-v1-cleanup")?.is_none() {
                match db.command_cleanup_legacy_terminal_bootstrap() {
                    Ok(_) => { db.setting_set("migration.terminal-audit-v1-cleanup", "1")?; }
                    Err(error) => eprintln!("Unable to clean legacy terminal audit records: {error}"),
                }
            }
            if let Ok(mut profiles) = db.forward_list("") {
                for profile in &mut profiles {
                    profile.active = false;
                    profile.status = "stopped".into();
                    profile.last_error = None;
                    let _ = db.forward_upsert(profile);
                }
            }
            app.manage(AppState {
                db,
                ssh: Arc::new(SshManager::default()),
                monitor: Arc::new(MonitorManager::default()),
                firewall: Arc::new(FirewallManager::default()),
                command_channels: Arc::new(Mutex::new(Vec::new())),
                command_sequence: Arc::new(AtomicU64::new(1)),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            hosts_list,
            hosts_upsert,
            hosts_delete,
            credentials_set,
            credentials_delete,
            ssh_connect,
            ssh_disconnect,
            terminal_open,
            terminal_input,
            terminal_resize,
            terminal_close,
            monitor_start,
            monitor_stop,
            monitor_query,
            firewall_read,
            firewall_plan,
            firewall_apply,
            firewall_commit,
            firewall_rollback,
            command_log_query,
            command_log_subscribe,
            command_log_export,
            command_log_clear,
            settings_get,
            settings_update,
            settings_reset,
            sftp_list,
            sftp_upload,
            sftp_start_upload,
            sftp_download,
            sftp_start_download,
            sftp_cancel,
            sftp_delete,
            sftp_rename,
            sftp_mkdir,
            sftp_start_copy,
            forward_list,
            forward_upsert,
            forward_start,
            forward_stop,
            forward_delete,
            config_export,
            config_import
        ])
        .run(tauri::generate_context!())
        .expect("failed to run SSH Operations Terminal")
}
