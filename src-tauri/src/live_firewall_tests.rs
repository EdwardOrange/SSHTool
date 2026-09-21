//! Opt-in live checks. Normal `cargo test` never contacts the configured host.
use crate::{db::Database, firewall::FirewallManager, models::*, monitor::MonitorManager, security::shell_quote, ssh::SshManager};
use futures::FutureExt;
use rusqlite::{Connection, OpenFlags};
use std::{path::PathBuf, sync::Arc, time::Duration};

fn live_database() -> (tempfile::TempDir, Arc<Database>, HostProfile) {
    assert_eq!(std::env::var("SSHOPS_LIVE_TEST").as_deref(), Ok("1"), "Live tests require SSHOPS_LIVE_TEST=1");
    let appdata = std::env::var_os("APPDATA").expect("APPDATA");
    let source = Connection::open_with_flags(PathBuf::from(appdata).join("com.sshoperations.terminal/ssh-operations.db"), OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut statement = source.prepare("SELECT data FROM hosts").unwrap();
    let hosts = statement.query_map([], |row| row.get::<_, String>(0)).unwrap()
        .map(|value| serde_json::from_str::<HostProfile>(&value.unwrap()).unwrap())
        .filter(|host| host.name == "111" && host.hostname == "47.251.14.139" && host.username == "root" && host.port == 22)
        .collect::<Vec<_>>();
    assert_eq!(hosts.len(), 1, "Expected the explicitly authorized test host");
    let host = hosts.into_iter().next().unwrap();
    assert_eq!(host.auth_method, "key");
    assert!(host.jump_hosts.is_empty());
    let (fingerprint, endpoint): (String, String) = source.query_row("SELECT fingerprint,endpoint FROM known_hosts WHERE host_id=?1", [&host.id], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
    assert_eq!(endpoint, format!("{}:{}", host.hostname, host.port));
    let directory = tempfile::tempdir().unwrap();
    let db = Arc::new(Database::open(&directory.path().join("live.db")).unwrap());
    db.host_upsert(&host).unwrap();
    db.set_fingerprint(&host.id, &endpoint, &fingerprint).unwrap();
    (directory, db, host)
}

#[tokio::test]
#[ignore = "requires SSHOPS_LIVE_TEST=1 and the explicitly authorized test server"]
async fn live_firewall_environment_and_monitor() {
    let (_directory, db, host) = live_database();
    let ssh = Arc::new(SshManager::default());
    ssh.connect(&db, host.clone(), None).await.unwrap();
    let output = ssh.exec(&host.id, "LANG=C; export LANG; printf 'OS='; . /etc/os-release; echo \"$PRETTY_NAME\"; for name in ufw firewall-cmd nft systemd-run systemctl at flock sudo; do command -v \"$name\" || true; done; printf 'UFW='; if command -v ufw >/dev/null; then ufw status; else echo unavailable; fi; printf 'FIREWALLD='; if command -v firewall-cmd >/dev/null; then firewall-cmd --state; else echo unavailable; fi; printf 'SYSTEMD='; systemctl is-system-running || true; printf 'SUDO='; sudo -n true && echo usable; printf 'TCP_LISTEN='; ss -Htlpn").await.unwrap();
    assert_eq!(output.exit_code, 0, "{}", output.stderr);
    println!("{}", output.stdout);
    let state = FirewallManager::default().read(&ssh, &host.id).await.unwrap();
    println!("Firewall backend={} enabled={} rollback={} rule_count={}", state.backend, state.enabled, state.rollback_available, state.rules.len());
    ssh.verify_new_connection(&db, &host.id).await.unwrap();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<MetricSnapshot>();
    let channel = tauri::ipc::Channel::new(move |message| {
        if let tauri::ipc::InvokeResponseBody::Json(json) = message {
            let envelope: StreamEnvelope<MetricSnapshot> = serde_json::from_str(&json).unwrap();
            let _ = sender.send(envelope.payload);
        }
        Ok(())
    });
    let monitor = MonitorManager::default();
    let task = monitor.start(host.id.clone(), ssh.clone(), db.clone(), channel, 2).unwrap();
    let first = tokio::time::timeout(Duration::from_secs(15), receiver.recv()).await.unwrap().unwrap();
    let second = tokio::time::timeout(Duration::from_secs(15), receiver.recv()).await.unwrap().unwrap();
    monitor.stop(&task);
    assert_eq!(first.cpu_percent, 0.0);
    assert_eq!(first.rx_bytes_per_sec, 0.0);
    assert!(second.cpu_percent.is_finite() && (0.0..=100.0).contains(&second.cpu_percent));
    assert!(second.memory_percent.is_finite() && (0.0..=100.0).contains(&second.memory_percent));
    assert!(second.disk_percent.is_finite() && (0.0..=100.0).contains(&second.disk_percent));
    assert!(second.rx_bytes_per_sec.is_finite() && second.rx_bytes_per_sec >= 0.0);
    assert!(second.connection_count >= second.connections.len() as u32);
    assert!(!second.top_processes.is_empty());
    let reference = ssh.exec(&host.id, "awk '/^MemTotal:/ { printf \"%.0f\\n\", $2 * 1024 }' /proc/meminfo; df -B1 -P / | tail -n1 | awk '{print $2}'; cut -d. -f1 /proc/uptime").await.unwrap();
    let values = reference.stdout.lines().map(|line| line.trim().parse::<u64>().unwrap()).collect::<Vec<_>>();
    assert_eq!(second.memory_total_bytes, values[0]);
    assert_eq!(second.disk_total_bytes, values[1]);
    assert!(values[2].abs_diff(second.uptime_seconds) < 10);
    assert!(db.metrics(&host.id, "2000").unwrap().len() >= 2);
    println!("Monitor PASS: two real samples, first baseline, finite CPU/memory/disk/network, socket/process parsing, memory/disk/uptime cross-check and metric persistence");
    ssh.disconnect(&host.id).await.unwrap();
}

fn change(port: u16, marker: &str) -> FirewallChange {
    FirewallChange { operation: "add".into(), rule: FirewallRuleInput {
        id: None, backend_ref: None, direction: "in".into(), family: "both".into(), protocol: "tcp".into(), ports: port.to_string(),
        source: "192.0.2.1/32".into(), destination: "any".into(), action: "allow".into(), enabled: true,
        comment: marker.into(), zone: None, read_only: None,
    }}
}

fn record_unit(manager: &FirewallManager, plan: &FirewallPlan, units: &mut Vec<(String, String)>) {
    if let Some(unit) = manager.live_test_rollback_unit(&plan.id) { units.push((plan.id.clone(), unit)); }
}

#[tokio::test]
#[ignore = "requires SSHOPS_LIVE_TEST=1; adds only a UUID-tagged documentation-source high-port UFW rule and restores it"]
async fn live_ufw_apply_commit_manual_and_disconnected_automatic_rollback() {
    exercise_ufw("systemd", true).await;
}

#[tokio::test]
#[ignore = "requires SSHOPS_LIVE_TEST=1; tests the at fallback using one isolated UFW rule and restores it"]
async fn live_ufw_at_fallback_disconnected_automatic_rollback() {
    exercise_ufw("at", false).await;
}

async fn exercise_ufw(scheduler: &str, full_transaction_suite: bool) {
    let (_directory, db, host) = live_database();
    let primary = Arc::new(SshManager::default());
    let recovery = Arc::new(SshManager::default());
    primary.connect(&db, host.clone(), None).await.unwrap();
    recovery.connect(&db, host.clone(), None).await.unwrap();
    primary.verify_new_connection(&db, &host.id).await.unwrap();
    if scheduler == "at" {
        let daemon = recovery.exec(&host.id, "command -v at >/dev/null && pgrep -x atd >/dev/null").await.unwrap();
        assert_eq!(daemon.exit_code, 0, "at daemon must already be running; tests never install or start firewall/scheduler services");
    }
    let firewall = FirewallManager::default();
    let baseline = firewall.read(&recovery, &host.id).await.unwrap();
    assert_eq!(baseline.backend, "ufw", "This test intentionally does not install or enable firewall services");
    assert!(baseline.enabled && baseline.rollback_available);
    let uuid = uuid::Uuid::new_v4();
    let marker = format!("sshops-qa-fw-{uuid}");
    let remote = format!("/tmp/{marker}");
    let port = 61000 + (u16::from_le_bytes([uuid.as_bytes()[0], uuid.as_bytes()[1]]) % 1000);
    assert!(!baseline.rules.iter().any(|rule| rule.ports == port.to_string()));
    let listening = recovery.exec(&host.id, &format!("ss -Htlpn 'sport = :{port}'")).await.unwrap();
    assert!(listening.stdout.trim().is_empty(), "Generated test port is in use");
    let snapshot = recovery.exec(&host.id, &format!("umask 077; mkdir -m 700 {remote} && tar -C / -czf {remote}/ufw-before.tar.gz etc/ufw && ufw status verbose > {remote}/status-before && sha256sum /etc/ufw/user.rules /etc/ufw/user6.rules")).await.unwrap();
    assert_eq!(snapshot.exit_code, 0, "{}", snapshot.stderr);
    let mut units = Vec::new();
    let work = std::panic::AssertUnwindSafe(async {
        if full_transaction_suite {
        let plan = firewall.plan(&primary, &host.id, change(port, &marker)).await.unwrap();
        let applied = firewall.apply(&primary, &db, &plan.id, None).await;
        record_unit(&firewall, &plan, &mut units);
        assert!(applied.unwrap().verified);
        assert!(firewall.read(&recovery, &host.id).await.unwrap().rules.iter().any(|rule| rule.comment == marker));
        firewall.rollback(&primary, &plan.id, None).await.unwrap();
        assert_eq!(firewall.read(&recovery, &host.id).await.unwrap().state_hash, baseline.state_hash);
        println!("UFW PASS: plan, protected apply, independent new SSH verification and manual rollback");

        let stale = firewall.plan(&primary, &host.id, change(port + 1000, &marker)).await.unwrap();
        let plan = firewall.plan(&primary, &host.id, change(port, &marker)).await.unwrap();
        let applied = firewall.apply(&primary, &db, &plan.id, None).await;
        record_unit(&firewall, &plan, &mut units);
        applied.unwrap();
        firewall.commit(&primary, &plan.id, None).await.unwrap();
        assert!(matches!(firewall.apply(&primary, &db, &stale.id, None).await, Err(crate::error::AppError::StalePlan)));
        firewall.rollback(&primary, &stale.id, None).await.unwrap();
        let persisted = recovery.exec(&host.id, &format!("grep -F -- {} /etc/ufw/user.rules", shell_quote(&hex::encode(marker.as_bytes())).unwrap())).await.unwrap();
        assert_eq!(persisted.exit_code, 0, "Committed test rule must be persisted in UFW configuration");
        let current = firewall.read(&recovery, &host.id).await.unwrap();
        let target = current.rules.into_iter().find(|rule| rule.comment == marker).unwrap();
        let rule: FirewallRuleInput = serde_json::from_value(serde_json::to_value(target).unwrap()).unwrap();
        let delete = firewall.plan(&primary, &host.id, FirewallChange { operation: "delete".into(), rule }).await.unwrap();
        let applied = firewall.apply(&primary, &db, &delete.id, None).await;
        record_unit(&firewall, &delete, &mut units);
        applied.unwrap();
        firewall.commit(&primary, &delete.id, None).await.unwrap();
        assert_eq!(firewall.read(&recovery, &host.id).await.unwrap().state_hash, baseline.state_hash);
        println!("UFW PASS: commit persists rule, stale plan rejected, exact numbered delete committed");

        let plan = firewall.plan(&primary, &host.id, change(port, &marker)).await.unwrap();
        firewall.live_test_fail_after_mutation(&plan.id);
        let result = firewall.apply(&primary, &db, &plan.id, None).await;
        record_unit(&firewall, &plan, &mut units);
        assert!(result.is_err(), "Injected post-mutation failure must be surfaced");
        assert_eq!(firewall.read(&recovery, &host.id).await.unwrap().state_hash, baseline.state_hash);
        firewall.rollback(&primary, &plan.id, None).await.unwrap();
        println!("UFW PASS: failure after real mutation restores baseline synchronously");
        }

        let plan = firewall.plan(&primary, &host.id, change(port, &marker)).await.unwrap();
        firewall.live_test_use_scheduler(&plan.id, scheduler);
        let applied = firewall.apply(&primary, &db, &plan.id, None).await;
        record_unit(&firewall, &plan, &mut units);
        applied.unwrap();
        let started = std::time::Instant::now();
        primary.disconnect(&host.id).await.unwrap();
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            let state = firewall.read(&recovery, &host.id).await.unwrap();
            if state.state_hash == baseline.state_hash { break; }
            assert!(started.elapsed() < Duration::from_secs(80), "Server-side 60-second rollback did not restore baseline");
        }
        assert!(started.elapsed() >= Duration::from_secs(40), "Timer should not fire immediately");
        primary.connect(&db, host.clone(), None).await.unwrap();
        assert!(firewall.commit(&primary, &plan.id, None).await.is_err(), "Expired changes cannot be committed");
        firewall.rollback(&primary, &plan.id, None).await.unwrap();
        println!("UFW PASS: {scheduler} automatic rollback after client disconnect observed after {:.1}s; reconnect and expired commit rejection", started.elapsed().as_secs_f64());
    }).catch_unwind().await;

    // Restore any unfinished transaction before deleting its exact test rule.
    // In particular a pending delete rollback could otherwise re-add the test
    // rule after cleanup has already checked the baseline.
    for (plan_id, _) in &units {
        if firewall.plan_host(plan_id).is_some() {
            firewall.rollback(&recovery, plan_id, None).await.unwrap();
        }
    }
    // Cleanup also runs after any assertion above. Remove only this test's
    // exact tagged high-port rule; snapshots remain until baseline is checked.
    let cleanup_rule = format!("ufw --force delete allow proto tcp from 192.0.2.1/32 to any port {port} comment {}", shell_quote(&marker).unwrap());
    let cleanup = recovery.exec(&host.id, &cleanup_rule).await.unwrap();
    assert_eq!(cleanup.exit_code, 0, "{}", cleanup.stderr);
    let final_state = firewall.read(&recovery, &host.id).await.unwrap();
    assert_eq!(final_state.state_hash, baseline.state_hash, "Original UFW rules must be identical; restore snapshot remains at {remote}");
    let hashes = recovery.exec(&host.id, "sha256sum /etc/ufw/user.rules /etc/ufw/user6.rules").await.unwrap();
    assert_eq!(hashes.stdout, snapshot.stdout, "Original persistent rule files must be byte-identical; snapshot remains at {remote}");
    for (_, unit) in units {
        assert!(unit.starts_with("sshops-rollback-") && uuid::Uuid::parse_str(&unit[16..]).is_ok());
        let result = recovery.exec(&host.id, &format!("systemctl stop {unit}.timer {unit}.service; systemctl reset-failed {unit}.service 2>/dev/null || true; find /run/{unit} -maxdepth 1 -type f -delete && rmdir /run/{unit}")).await.unwrap();
        assert_eq!(result.exit_code, 0, "{}", result.stderr);
    }
    let result = recovery.exec(&host.id, &format!("rm -- {remote}/ufw-before.tar.gz {remote}/status-before && rmdir {remote}")).await.unwrap();
    assert_eq!(result.exit_code, 0, "{}", result.stderr);
    primary.disconnect(&host.id).await.unwrap();
    recovery.disconnect(&host.id).await.unwrap();
    println!("UFW CLEANUP PASS: original runtime rules and persistent rule files identical; all test timers, snapshots and directories removed");
    if let Err(panic) = work { std::panic::resume_unwind(panic); }
}
