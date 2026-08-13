use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JumpHost {
    pub host_id: String,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostProfile {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub group_name: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub auth_method: String,
    pub credential_id: Option<String>,
    pub private_key_path: Option<String>,
    pub jump_hosts: Vec<JumpHost>,
    pub host_key_fingerprint: Option<String>,
    pub status: String,
    pub last_connected_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostDraft {
    pub id: Option<String>,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub group_name: String,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub auth_method: String,
    pub credential_id: Option<String>,
    pub private_key_path: Option<String>,
    pub jump_hosts: Option<Vec<JumpHost>>,
    pub password: Option<String>,
    pub remember_password: Option<bool>,
    pub host_key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkConnection {
    pub protocol: String,
    pub state: String,
    pub local_address: String,
    pub remote_address: String,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessUsage {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricSnapshot {
    pub host_id: String,
    pub timestamp: String,
    pub cpu_percent: f64,
    pub memory_percent: f64,
    pub disk_percent: f64,
    pub load1: f64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub connection_count: u32,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub uptime_seconds: u64,
    pub connections: Vec<NetworkConnection>,
    pub top_processes: Vec<ProcessUsage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedFirewallRule {
    pub id: String,
    pub backend_ref: Option<String>,
    pub direction: String,
    pub family: String,
    pub protocol: String,
    pub ports: String,
    pub source: String,
    pub destination: String,
    pub action: String,
    pub enabled: bool,
    pub comment: String,
    pub zone: Option<String>,
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRuleInput {
    pub id: Option<String>,
    pub backend_ref: Option<String>,
    pub direction: String,
    pub family: String,
    pub protocol: String,
    pub ports: String,
    pub source: String,
    pub destination: String,
    pub action: String,
    pub enabled: bool,
    pub comment: String,
    pub zone: Option<String>,
    pub read_only: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallState {
    pub host_id: String,
    pub backend: String,
    pub enabled: bool,
    pub default_inbound: String,
    pub default_outbound: String,
    pub state_hash: String,
    pub rollback_available: bool,
    pub rules: Vec<UnifiedFirewallRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallChange {
    pub operation: String,
    pub rule: FirewallRuleInput,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallPlan {
    pub id: String,
    pub host_id: String,
    pub state_hash: String,
    pub summary: String,
    pub commands: Vec<String>,
    pub warnings: Vec<String>,
    pub risk: String,
    pub rollback_available: bool,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallApplyProgress {
    pub plan_id: String,
    pub phase: String,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallApplyResult {
    pub rollback_deadline: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandRecord {
    pub id: String,
    pub timestamp: String,
    pub host_id: Option<String>,
    pub host_name: Option<String>,
    pub source: String,
    pub command: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub status: String,
    pub repeat_count: u32,
    pub equivalent: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SftpEntry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub modified_at: Option<String>,
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferProgress {
    pub transfer_id: String,
    pub host_id: String,
    pub direction: String,
    pub current_path: String,
    pub transferred: u64,
    pub total: u64,
    pub status: String,
    pub error: Option<String>,
    pub file_index: u32,
    pub file_count: u32,
    pub current_file_transferred: u64,
    pub current_file_total: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardingProfile {
    pub id: String,
    pub host_id: String,
    pub name: String,
    pub kind: String,
    pub bind_address: String,
    pub bind_port: u16,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub active: bool,
    #[serde(default = "default_forward_status")]
    pub status: String,
    #[serde(default)]
    pub last_error: Option<String>,
}

fn default_forward_status() -> String {
    "stopped".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StreamEnvelope<T> {
    pub seq: u64,
    pub timestamp: String,
    pub host_id: String,
    pub session_id: Option<String>,
    pub payload: T,
}

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
}
