use crate::{
    db::Database,
    error::{AppError, AppResult},
    models::*,
    security::redact,
    ssh::SshManager,
};
use parking_lot::RwLock;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tauri::ipc::Channel;
use tokio::sync::watch;

const SAMPLE_COMMAND: &str = "LANG=C sh -c 'echo __STAT__; head -n1 /proc/stat; echo __MEM__; grep -E \"^(MemTotal|MemAvailable):\" /proc/meminfo; echo __LOAD__; cat /proc/loadavg; echo __UPTIME__; cut -d\" \" -f1 /proc/uptime; echo __DISK__; df -B1 -P / | tail -n1; echo __NET__; cat /proc/net/dev; echo __CONN__; (ss -Htunap 2>/dev/null || true) | head -n200; echo __PROC__; ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu | head -n10'";

#[derive(Clone, Default)]
struct Previous {
    total: u64,
    idle: u64,
    rx: u64,
    tx: u64,
    timestamp_ms: i64,
}

pub struct MonitorManager {
    tasks: Arc<RwLock<HashMap<String, watch::Sender<bool>>>>,
    host_tasks: Arc<RwLock<HashMap<String, String>>>,
    previous: Arc<RwLock<HashMap<String, Previous>>>,
    sequence: Arc<AtomicU64>,
}
impl Default for MonitorManager {
    fn default() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(HashMap::new())),
            host_tasks: Arc::new(RwLock::new(HashMap::new())),
            previous: Arc::new(RwLock::new(HashMap::new())),
            sequence: Arc::new(AtomicU64::new(1)),
        }
    }
}

impl MonitorManager {
    pub fn start(
        &self,
        host_id: String,
        ssh: Arc<SshManager>,
        db: Arc<Database>,
        channel: Channel<StreamEnvelope<MetricSnapshot>>,
        interval_seconds: u64,
    ) -> AppResult<String> {
        self.stop_host(&host_id);
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let task_id = uuid::Uuid::new_v4().to_string();
        self.tasks.write().insert(task_id.clone(), cancel_tx);
        self.host_tasks.write().insert(host_id.clone(), task_id.clone());
        let previous = self.previous.clone();
        let sequence = self.sequence.clone();
        let tasks = self.tasks.clone();
        let host_tasks = self.host_tasks.clone();
        let cleanup_task_id = task_id.clone();
        // `monitor_start` can be invoked by Tauri on the WebView/main thread,
        // where no Tokio reactor is entered. Always schedule long-running work
        // through Tauri's global async runtime so opening the monitor page can
        // never panic the desktop process.
        tauri::async_runtime::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds.clamp(1, 300)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { _=ticker.tick()=>{
                    let started=chrono::Utc::now(); let output = tokio::select! { result = ssh.exec(&host_id, SAMPLE_COMMAND) => result, _ = cancel_rx.changed() => break }; match output { Ok(output)=>{ if let Ok(snapshot)=parse_snapshot(&host_id,&output.stdout,&previous){ let _=db.metric_add(&snapshot,interval_seconds as u32); let _=db.command_add(&CommandRecord{id:uuid::Uuid::new_v4().to_string(),timestamp:started.to_rfc3339(),host_id:Some(host_id.clone()),host_name:ssh.profile(&host_id).ok().map(|h|h.name),source:"monitor".into(),command:redact(SAMPLE_COMMAND),stdout:"采样完成".into(),stderr:redact(&output.stderr),exit_code:Some(output.exit_code),duration_ms:output.duration_ms,status:if output.exit_code==0{"success".into()}else{"error".into()},repeat_count:1,equivalent:None,operation_kind:Some("monitor.sample".into())}); let _=channel.send(StreamEnvelope{seq:sequence.fetch_add(1,Ordering::Relaxed),timestamp:snapshot.timestamp.clone(),host_id:host_id.clone(),session_id:None,payload:snapshot}); } }, Err(error)=>{ let _=db.command_add(&CommandRecord{id:uuid::Uuid::new_v4().to_string(),timestamp:started.to_rfc3339(),host_id:Some(host_id.clone()),host_name:ssh.profile(&host_id).ok().map(|h|h.name),source:"monitor".into(),command:redact(SAMPLE_COMMAND),stdout:String::new(),stderr:redact(&error.to_string()),exit_code:None,duration_ms:0,status:"error".into(),repeat_count:1,equivalent:None,operation_kind:Some("monitor.sample".into())}); } }
                }, _=cancel_rx.changed()=>break }
            }
            tasks.write().remove(&cleanup_task_id);
            let mut current_tasks = host_tasks.write();
            if current_tasks.get(&host_id).is_some_and(|current| current == &cleanup_task_id) { current_tasks.remove(&host_id); previous.write().remove(&host_id); }
        });
        Ok(task_id)
    }
    pub fn stop(&self, task_id: &str) {
        if let Some(tx) = self.tasks.write().remove(task_id) {
            let _ = tx.send(true);
        }
    }
    pub fn stop_host(&self, host_id: &str) {
        let task_id = self.host_tasks.write().remove(host_id);
        if let Some(task_id) = task_id { self.stop(&task_id); }
    }
}

fn parse_snapshot(
    host_id: &str,
    output: &str,
    previous: &Arc<RwLock<HashMap<String, Previous>>>,
) -> AppResult<MetricSnapshot> {
    let section = |name: &str| -> String {
        let marker = format!("__{name}__\n");
        output
            .split(&marker)
            .nth(1)
            .unwrap_or("")
            .split("\n__")
            .next()
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let stat = section("STAT");
    let cpu: Vec<u64> = stat
        .split_whitespace()
        .skip(1)
        .filter_map(|v| v.parse().ok())
        .collect();
    if cpu.len() < 4 {
        return Err(AppError::Other("无法解析 /proc/stat".into()));
    }
    // guest and guest_nice are already included in user and nice.
    let total: u64 = cpu.iter().take(8).sum();
    let idle = cpu.get(3).copied().unwrap_or(0) + cpu.get(4).copied().unwrap_or(0);
    let mem = section("MEM");
    let mut mem_total = 0u64;
    let mut mem_available = 0u64;
    for line in mem.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let bytes = parts[1].parse::<u64>().unwrap_or(0) * 1024;
            if line.starts_with("MemTotal") {
                mem_total = bytes
            } else if line.starts_with("MemAvailable") {
                mem_available = bytes
            }
        }
    }
    let load1 = section("LOAD")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    let uptime = section("UPTIME").parse::<f64>().unwrap_or(0.0) as u64;
    let disk = section("DISK");
    let d: Vec<&str> = disk.split_whitespace().collect();
    let disk_total = d.get(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    let disk_used = d.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);
    let net = section("NET");
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in net.lines().skip(2) {
        if let Some((iface, data)) = line.split_once(':') {
            if iface.trim() == "lo" {
                continue;
            }
            let v: Vec<&str> = data.split_whitespace().collect();
            rx += v.first().and_then(|x| x.parse().ok()).unwrap_or(0);
            tx += v.get(8).and_then(|x| x.parse().ok()).unwrap_or(0);
        }
    }
    let now = chrono::Utc::now();
    let now_ms = now.timestamp_millis();
    let mut previous_map = previous.write();
    let old = previous_map
        .insert(
            host_id.into(),
            Previous {
                total,
                idle,
                rx,
                tx,
                timestamp_ms: now_ms,
            },
        )
        .unwrap_or_default();
    let total_delta = total.saturating_sub(old.total);
    let idle_delta = idle.saturating_sub(old.idle);
    let cpu_percent = if old.total == 0 || total_delta == 0 {
        0.0
    } else {
        100.0 * total_delta.saturating_sub(idle_delta) as f64 / total_delta as f64
    };
    let seconds = ((now_ms - old.timestamp_ms) as f64 / 1000.0).max(0.1);
    let rx_rate = if old.timestamp_ms == 0 {
        0.0
    } else {
        rx.saturating_sub(old.rx) as f64 / seconds
    };
    let tx_rate = if old.timestamp_ms == 0 {
        0.0
    } else {
        tx.saturating_sub(old.tx) as f64 / seconds
    };
    let connections = parse_connections(&section("CONN"));
    let top_processes = parse_processes(&section("PROC"));
    Ok(MetricSnapshot {
        host_id: host_id.into(),
        timestamp: now.to_rfc3339(),
        cpu_percent,
        memory_percent: if mem_total > 0 {
            100.0 * mem_total.saturating_sub(mem_available) as f64 / mem_total as f64
        } else {
            0.0
        },
        disk_percent: if disk_total > 0 {
            100.0 * disk_used as f64 / disk_total as f64
        } else {
            0.0
        },
        load1,
        rx_bytes_per_sec: rx_rate,
        tx_bytes_per_sec: tx_rate,
        connection_count: connections.len().min(u32::MAX as usize) as u32,
        memory_used_bytes: mem_total.saturating_sub(mem_available),
        memory_total_bytes: mem_total,
        disk_used_bytes: disk_used,
        disk_total_bytes: disk_total,
        uptime_seconds: uptime,
        connections,
        top_processes,
    })
}
fn parse_connections(input: &str) -> Vec<NetworkConnection> {
    input
        .lines()
        .filter_map(|line| {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() < 6 {
                return None;
            }
            Some(NetworkConnection {
                protocol: p[0].into(),
                state: p[1].into(),
                local_address: p[4].into(),
                remote_address: p[5].into(),
                process: p.get(6).map(|x| x.to_string()),
            })
        })
        .collect()
}
fn parse_processes(input: &str) -> Vec<ProcessUsage> {
    input
        .lines()
        .filter_map(|line| {
            let p: Vec<&str> = line.split_whitespace().collect();
            if p.len() < 4 {
                return None;
            }
            Some(ProcessUsage {
                pid: p[0].parse().ok()?,
                name: p[1].into(),
                cpu_percent: p[2].parse().ok()?,
                memory_percent: p[3].parse().ok()?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cpu_guest_time_is_not_counted_twice() {
        let previous = Arc::new(RwLock::new(HashMap::new()));
        parse_snapshot("host", "__STAT__\ncpu 100 0 0 100 0 0 0 0 50 0\n", &previous).unwrap();
        let snapshot = parse_snapshot("host", "__STAT__\ncpu 200 0 0 200 0 0 0 0 150 0\n", &previous).unwrap();
        assert!((snapshot.cpu_percent - 50.0).abs() < 0.001);
    }
    #[test]
    fn parses_connections() {
        let v = parse_connections("tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:sshd");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].state, "ESTAB");
    }
    #[test]
    fn parses_processes() {
        let v = parse_processes("12 nginx 3.2 1.4");
        assert_eq!(v[0].pid, 12);
    }

    #[test]
    fn tauri_runtime_can_spawn_monitor_work_from_a_sync_context() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1)).await;
            sender
                .send(())
                .expect("test receiver must remain available");
        });
        receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("monitor work should run without a caller Tokio reactor");
    }
}
