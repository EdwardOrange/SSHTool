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
    time::{Duration, Instant},
};
use tauri::ipc::Channel;
use tokio::sync::watch;

const SAMPLE_COMMAND: &str = "LANG=C sh -c 'echo __STAT__; head -n1 /proc/stat; echo __MEM__; grep -E \"^(MemTotal|MemAvailable):\" /proc/meminfo; echo __LOAD__; cat /proc/loadavg; echo __UPTIME__; cut -d\" \" -f1 /proc/uptime; echo __DISK__; df -B1 -P / | tail -n1; echo __NET__; cat /proc/net/dev; connections=$(ss -Htunap 2>/dev/null) || exit 1; echo __CONN__; printf \"%s\\n\" \"$connections\" | head -n200; echo __CONN_COUNT__; printf \"%s\\n\" \"$connections\" | grep -c .; echo __PROC__; ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu | head -n10'";

struct Previous {
    total: u64,
    idle: u64,
    rx: u64,
    tx: u64,
    sampled_at: Instant,
}

struct MonitorTask {
    host_id: String,
    cancel: watch::Sender<bool>,
}

#[derive(Default)]
struct MonitorTasks {
    tasks: HashMap<String, MonitorTask>,
    hosts: HashMap<String, String>,
}

impl MonitorTasks {
    fn register(&mut self, host_id: String, task_id: String, cancel: watch::Sender<bool>) {
        if let Some(old_id) = self.hosts.get(&host_id).cloned() {
            self.remove(&old_id);
        }
        self.hosts.insert(host_id.clone(), task_id.clone());
        self.tasks.insert(task_id, MonitorTask { host_id, cancel });
    }

    fn remove(&mut self, task_id: &str) {
        if let Some(task) = self.tasks.remove(task_id) {
            let _ = task.cancel.send(true);
            if self.hosts.get(&task.host_id).is_some_and(|current| current == task_id) {
                self.hosts.remove(&task.host_id);
            }
        }
    }
}

pub struct MonitorManager {
    tasks: Arc<RwLock<MonitorTasks>>,
    sequence: Arc<AtomicU64>,
}
impl Default for MonitorManager {
    fn default() -> Self {
        Self {
            tasks: Arc::new(RwLock::new(MonitorTasks::default())),
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
        let interval_seconds = normalize_interval(interval_seconds);
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let task_id = uuid::Uuid::new_v4().to_string();
        self.tasks.write().register(host_id.clone(), task_id.clone(), cancel_tx);
        let sequence = self.sequence.clone();
        let tasks = self.tasks.clone();
        let cleanup_task_id = task_id.clone();
        // `monitor_start` can be invoked by Tauri on the WebView/main thread,
        // where no Tokio reactor is entered. Always schedule long-running work
        // through Tauri's global async runtime so opening the monitor page can
        // never panic the desktop process.
        tauri::async_runtime::spawn(async move {
            // A restarted task must never share its CPU/network baseline with
            // a cancelled task that is still finishing its current sample.
            let mut previous = None;
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_seconds));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    _ = ticker.tick() => {}
                }
                let started = chrono::Utc::now();
                let output = tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    result = ssh.exec(&host_id, SAMPLE_COMMAND) => result
                };
                if *cancel_rx.borrow() { break; }
                let (snapshot, stderr, exit_code, duration_ms) = match output {
                    Ok(output) => {
                        let snapshot = if output.exit_code == 0 {
                            parse_snapshot(&host_id, &output.stdout, &mut previous)
                        } else {
                            Err(AppError::Other(format!("监控命令退出码 {}", output.exit_code)))
                        };
                        (snapshot, output.stderr, Some(output.exit_code), output.duration_ms)
                    }
                    Err(error) => (Err(error), String::new(), None, 0),
                };
                let error = snapshot.as_ref().err().map(ToString::to_string);
                let stderr = match error.as_deref() {
                    Some(error) => format!("{stderr}\n{error}"),
                    None => stderr,
                };
                let _ = db.command_add(&CommandRecord {
                    id: uuid::Uuid::new_v4().to_string(), timestamp: started.to_rfc3339(),
                    host_id: Some(host_id.clone()), host_name: ssh.profile(&host_id).ok().map(|h| h.name),
                    source: "monitor".into(), command: redact(SAMPLE_COMMAND),
                    stdout: if error.is_none() { "采样完成".into() } else { String::new() },
                    stderr: redact(stderr.trim()), exit_code, duration_ms,
                    status: if error.is_none() { "success".into() } else { "error".into() },
                    repeat_count: 1, equivalent: None, operation_kind: Some("monitor.sample".into()),
                });
                if let Ok(snapshot) = snapshot {
                    let _ = db.metric_add(&snapshot, interval_seconds as u32);
                    if channel.send(StreamEnvelope {
                        seq: sequence.fetch_add(1, Ordering::Relaxed), timestamp: snapshot.timestamp.clone(),
                        host_id: host_id.clone(), session_id: None, payload: snapshot,
                    }).is_err() { break; }
                }
            }
            tasks.write().remove(&cleanup_task_id);
        });
        Ok(task_id)
    }
    pub fn stop(&self, task_id: &str) {
        self.tasks.write().remove(task_id);
    }
    pub fn stop_host(&self, host_id: &str) {
        let mut tasks = self.tasks.write();
        if let Some(task_id) = tasks.hosts.get(host_id).cloned() { tasks.remove(&task_id); }
    }
}

fn normalize_interval(interval_seconds: u64) -> u64 {
    if matches!(interval_seconds, 2 | 5 | 10 | 30) { interval_seconds } else { 2 }
}

fn parse_snapshot(
    host_id: &str,
    output: &str,
    previous: &mut Option<Previous>,
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
    let mut fields = stat.split_whitespace();
    if fields.next() != Some("cpu") { return Err(AppError::Other("无法解析 /proc/stat".into())); }
    let cpu: Vec<u64> = fields.map(|value| value.parse::<u64>())
        .collect::<Result<_, _>>().map_err(|_| AppError::Other("无法解析 /proc/stat".into()))?;
    if cpu.len() < 4 {
        return Err(AppError::Other("无法解析 /proc/stat".into()));
    }
    // guest and guest_nice are already included in user and nice.
    let total = cpu.iter().take(8).try_fold(0u64, |total, value| total.checked_add(*value))
        .ok_or_else(|| AppError::Other("CPU 计数超出范围".into()))?;
    let idle = cpu.get(3).copied().unwrap_or(0) + cpu.get(4).copied().unwrap_or(0);
    let mem = section("MEM");
    let mut mem_total = None;
    let mut mem_available = None;
    for line in mem.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() >= 2 && matches!(parts[0], "MemTotal:" | "MemAvailable:") {
            let bytes = parts[1].parse::<u64>().ok().and_then(|value| value.checked_mul(1024))
                .ok_or_else(|| AppError::Other("内存计数无效".into()))?;
            if parts[0] == "MemTotal:" {
                mem_total = Some(bytes)
            } else {
                mem_available = Some(bytes)
            }
        }
    }
    let (mem_total, mem_available) = match (mem_total, mem_available) {
        (Some(total), Some(available)) if total > 0 && available <= total => (total, available),
        _ => return Err(AppError::Other("无法解析 /proc/meminfo".into())),
    };
    let load1 = section("LOAD")
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| AppError::Other("无法解析系统负载".into()))?;
    let uptime = section("UPTIME").parse::<f64>().ok()
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or_else(|| AppError::Other("无法解析系统运行时间".into()))? as u64;
    let disk = section("DISK");
    let d: Vec<&str> = disk.split_whitespace().collect();
    let disk_total = d.get(1).and_then(|v| v.parse::<u64>().ok()).filter(|value| *value > 0)
        .ok_or_else(|| AppError::Other("无法解析磁盘容量".into()))?;
    let disk_used = d.get(2).and_then(|v| v.parse::<u64>().ok()).filter(|value| *value <= disk_total)
        .ok_or_else(|| AppError::Other("无法解析磁盘用量".into()))?;
    let net = section("NET");
    let mut rx = 0u64;
    let mut tx = 0u64;
    if net.lines().count() < 2 { return Err(AppError::Other("无法解析 /proc/net/dev".into())); }
    for line in net.lines().skip(2) {
        if let Some((iface, data)) = line.split_once(':') {
            if iface.trim() == "lo" {
                continue;
            }
            let v: Vec<&str> = data.split_whitespace().collect();
            let received = v.first().and_then(|x| x.parse::<u64>().ok())
                .ok_or_else(|| AppError::Other("无法解析网络接收计数".into()))?;
            let transmitted = v.get(8).and_then(|x| x.parse::<u64>().ok())
                .ok_or_else(|| AppError::Other("无法解析网络发送计数".into()))?;
            rx = rx.checked_add(received).ok_or_else(|| AppError::Other("网络接收计数超出范围".into()))?;
            tx = tx.checked_add(transmitted).ok_or_else(|| AppError::Other("网络发送计数超出范围".into()))?;
        }
    }
    let connections = parse_connections(&section("CONN"));
    // The table is capped at 200 rows, but the summary must count every
    // socket; otherwise busy hosts misleadingly plateau at exactly 200.
    let connection_count = if output.contains("__CONN_COUNT__") {
        section("CONN_COUNT").parse::<u32>()
            .map_err(|_| AppError::Other("无法解析网络连接总数".into()))?
    } else { connections.len().min(u32::MAX as usize) as u32 };
    let now = chrono::Utc::now();
    let sampled_at = Instant::now();
    let old = previous.replace(Previous { total, idle, rx, tx, sampled_at })
        .unwrap_or(Previous { total, idle, rx, tx, sampled_at });
    let total_delta = total.saturating_sub(old.total);
    let idle_delta = idle.saturating_sub(old.idle);
    let cpu_percent = if old.total == 0 || total_delta == 0 {
        0.0
    } else {
        100.0 * total_delta.saturating_sub(idle_delta) as f64 / total_delta as f64
    };
    let seconds = sampled_at.duration_since(old.sampled_at).as_secs_f64().max(0.1);
    let rx_rate = rx.saturating_sub(old.rx) as f64 / seconds;
    let tx_rate = tx.saturating_sub(old.tx) as f64 / seconds;
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
        connection_count,
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
                name: p[1..p.len() - 2].join(" "),
                cpu_percent: p[p.len() - 2].parse::<f64>().ok().filter(|value| value.is_finite() && *value >= 0.0)?,
                memory_percent: p[p.len() - 1].parse::<f64>().ok().filter(|value| value.is_finite() && *value >= 0.0)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample(stat: &str) -> String {
        format!("__STAT__\n{stat}\n__MEM__\nMemTotal: 1024 kB\nMemAvailable: 512 kB\n__LOAD__\n1.5 0.5 0.2\n__UPTIME__\n600.0\n__DISK__\n/dev/root 1000 400 500 40% /\n__NET__\nInter-| Receive | Transmit\nface |bytes packets errs drop fifo frame compressed multicast|bytes\neth0: 1024 0 0 0 0 0 0 0 2048 0 0 0 0 0 0 0\n")
    }
    #[test]
    fn cpu_guest_time_is_not_counted_twice() {
        let mut previous = None;
        parse_snapshot("host", &sample("cpu 100 0 0 100 0 0 0 0 50 0"), &mut previous).unwrap();
        let snapshot = parse_snapshot("host", &sample("cpu 200 0 0 200 0 0 0 0 150 0"), &mut previous).unwrap();
        assert!((snapshot.cpu_percent - 50.0).abs() < 0.001);
    }
    #[test]
    fn malformed_samples_do_not_panic_or_update_the_baseline() {
        let valid = sample("cpu 100 0 0 100 0 0 0 0");
        let mut previous = None;
        parse_snapshot("host", &valid, &mut previous).unwrap();
        for invalid in [
            sample("cpu 18446744073709551615 0 0 1"),
            sample("cpu 100 invalid 100 0 0"),
            valid.replace("MemTotal: 1024", "MemTotal: 18446744073709551615"),
            valid.replace("MemAvailable: 512 kB", ""),
            valid.replace("1.5 0.5 0.2", "NaN 0.5 0.2"),
            valid.replace("/dev/root 1000 400 500 40% /", ""),
        ] {
            assert!(parse_snapshot("host", &invalid, &mut previous).is_err());
            assert_eq!(previous.as_ref().unwrap().total, 200);
        }
    }

    #[test]
    fn replacing_a_task_cancels_only_its_old_registration() {
        let mut tasks = MonitorTasks::default();
        let (old_tx, old_rx) = watch::channel(false);
        let (new_tx, new_rx) = watch::channel(false);
        tasks.register("host".into(), "old".into(), old_tx);
        tasks.register("host".into(), "new".into(), new_tx);
        assert!(*old_rx.borrow());
        assert!(!*new_rx.borrow());
        tasks.remove("old");
        assert_eq!(tasks.hosts.get("host").map(String::as_str), Some("new"));
        assert_eq!(tasks.tasks.len(), 1);
        tasks.remove("new");
        assert!(*new_rx.borrow());
        assert!(tasks.hosts.is_empty() && tasks.tasks.is_empty());
    }

    #[test]
    fn sampling_intervals_match_database_retention_buckets() {
        for interval in [2, 5, 10, 30] { assert_eq!(normalize_interval(interval), interval); }
        for interval in [0, 1, 3, 300, u64::MAX] { assert_eq!(normalize_interval(interval), 2); }
    }

    #[test]
    fn new_sampling_tasks_start_with_independent_baselines() {
        let mut old = None;
        let mut new = None;
        parse_snapshot("host", &sample("cpu 100 0 0 100"), &mut old).unwrap();
        let first = parse_snapshot("host", &sample("cpu 150 0 0 200"), &mut new).unwrap();
        assert_eq!(first.cpu_percent, 0.0);
        assert_eq!(first.rx_bytes_per_sec, 0.0);
        let second = parse_snapshot("host", &sample("cpu 200 0 0 200"), &mut old).unwrap();
        assert_eq!(second.cpu_percent, 50.0);
    }
    #[test]
    fn parses_connections() {
        let v = parse_connections("tcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000 users:sshd");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].state, "ESTAB");
    }
    #[test]
    fn connection_summary_is_not_truncated_to_table_length() {
        let output = format!("{}__CONN__\ntcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5000\n__CONN_COUNT__\n450\n", sample("cpu 100 0 0 100"));
        let snapshot = parse_snapshot("host", &output, &mut None).unwrap();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connection_count, 450);
        assert!(parse_snapshot("host", &output.replace("\n450\n", "\ninvalid\n"), &mut None).is_err());
    }
    #[test]
    fn parses_processes() {
        let v = parse_processes("12 nginx 3.2 1.4");
        assert_eq!(v[0].pid, 12);
        let v = parse_processes("15 worker pool 3.2 1.4\n16 invalid NaN 2.5");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "worker pool");
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
