//! Explicitly opted-in integration tests against an already trusted saved host.
//! Run: SSHOPS_LIVE_TEST=1 cargo test live_ssh_tests -- --ignored --nocapture.
//! The real application database is opened read-only; no secrets are logged.
//! Optional SSHOPS_LIVE_HOST_NAME selects one saved host. SSHOPS_LIVE_SCOPE
//! defaults to all; forwarding and disconnect allow focused fault retests.
use crate::{db::Database, models::{ForwardingProfile, HostProfile, StreamEnvelope, TransferProgress}, ssh::{SshManager, TerminalAuditEventKind}};
use futures::FutureExt;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::{error::Error, io, panic::AssertUnwindSafe, path::{Path, PathBuf}, sync::Arc, time::Duration};
use tauri::ipc::{Channel, InvokeResponseBody};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, sync::mpsc, time::timeout};
use uuid::Uuid;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
fn check(ok: bool, reason: &str) -> TestResult { if ok { Ok(()) } else { Err(io::Error::other(reason).into()) } }
fn digest(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

fn saved_fixture(directory: &Path) -> TestResult<(Database, HostProfile)> {
    let path = std::env::var_os("SSHOPS_LIVE_DB").map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(std::env::var_os("APPDATA").expect("APPDATA or SSHOPS_LIVE_DB is required"))
            .join("com.sshoperations.terminal").join("ssh-operations.db")
    });
    let source = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = source.prepare("SELECT data FROM hosts")?;
    let records = statement.query_map([], |row| row.get::<_, String>(0))?;
    let name = std::env::var("SSHOPS_LIVE_HOST_NAME").ok();
    let mut hosts = Vec::new();
    for row in records {
        let host: HostProfile = serde_json::from_str(&row?)?;
        if name.as_ref().is_none_or(|name| name == &host.name) { hosts.push(host); }
    }
    check(hosts.len() == 1, "Select exactly one saved host with SSHOPS_LIVE_HOST_NAME")?;
    let host = hosts.remove(0);
    check(host.auth_method == "key" && host.jump_hosts.is_empty(), "Live fixture requires a direct saved key-auth host")?;
    let endpoint = format!("{}:{}", host.hostname, host.port);
    let fingerprint: String = source.query_row("SELECT fingerprint FROM known_hosts WHERE host_id=?1 AND endpoint=?2", [&host.id, &endpoint], |row| row.get(0))?;
    check(!fingerprint.is_empty(), "The saved endpoint must already be trusted")?;
    let db = Database::open(&directory.join("isolated.db"))?;
    db.host_upsert(&host)?;
    db.set_fingerprint(&host.id, &endpoint, &fingerprint)?;
    Ok((db, host))
}

fn events<T: serde::de::DeserializeOwned + Send + 'static>() -> (Channel<T>, mpsc::UnboundedReceiver<T>) {
    let (send, receive) = mpsc::unbounded_channel();
    let channel = Channel::new(move |body| {
        if let InvokeResponseBody::Json(json) = body {
            let value: T = serde_json::from_str(&json).expect("valid IPC JSON");
            let _ = send.send(value);
        }
        Ok(())
    });
    (channel, receive)
}

async fn transfer_end(receive: &mut mpsc::UnboundedReceiver<StreamEnvelope<TransferProgress>>) -> TestResult<TransferProgress> {
    timeout(Duration::from_secs(120), async {
        while let Some(event) = receive.recv().await {
            if matches!(event.payload.status.as_str(), "completed" | "error" | "cancelled") { return Ok(event.payload); }
        }
        Err(io::Error::other("Transfer ended without terminal progress").into())
    }).await?
}

async fn upload(manager: &Arc<SshManager>, host: &str, path: &Path, target: &str, policy: &str, expected: &str) -> TestResult {
    println!("CHECK upload {policy} -> {expected}");
    let (ipc, mut receive) = events();
    manager.sftp_upload(host, vec![path.display().to_string()], target, policy, ipc).await?;
    let end = transfer_end(&mut receive).await?;
    check(end.status == expected, &format!("Upload {policy}: {} {:?}", end.status, end.error))
}

async fn download(manager: &Arc<SshManager>, host: &str, path: &str, target: &Path, policy: &str, expected: &str) -> TestResult {
    println!("CHECK download {policy} -> {expected}");
    let (ipc, mut receive) = events();
    manager.sftp_download(host, vec![path.to_owned()], &target.display().to_string(), policy, ipc).await?;
    let end = transfer_end(&mut receive).await?;
    check(end.status == expected, &format!("Download {policy}: {} {:?}", end.status, end.error))
}

async fn remote_digest(manager: &SshManager, host: &str, path: &str) -> TestResult<String> {
    // Every caller supplies a path under this run's generated isolation directory.
    let result = manager.exec(host, &format!("sha256sum -- '{}'", path.replace('\'', "'\\''"))).await?;
    check(result.exit_code == 0, "Remote SHA-256 failed")?;
    Ok(result.stdout.split_whitespace().next().unwrap_or_default().to_owned())
}

async fn terminal_checks(manager: &Arc<SshManager>, host: &str) -> TestResult {
    let (ipc, mut output) = events::<StreamEnvelope<Vec<u8>>>();
    let (audit_send, mut audits) = mpsc::unbounded_channel();
    let session = manager.terminal_open(host, 83, 27, ipc, true, audit_send).await?;
    timeout(Duration::from_secs(20), async {
        loop {
            let event = audits.recv().await.ok_or_else(|| io::Error::other("No audit readiness event"))?;
            match event.kind {
                TerminalAuditEventKind::Ready { shell } => { check(shell == "bash" || shell == "zsh", "Unexpected audited shell")?; return Ok::<(), Box<dyn Error + Send + Sync>>(()); }
                TerminalAuditEventKind::Unavailable { reason } => return Err(io::Error::other(reason).into()),
                _ => {}
            }
        }
    }).await??;
    // Avoid saving test commands into the user's persistent shell history.
    manager.terminal_input(&session, b"unset HISTFILE; stty size\r".to_vec()).await?;
    wait_output(&mut output, "27 83").await?;
    manager.terminal_resize(&session, 101, 37).await?;
    manager.terminal_input(&session, b"stty size\r".to_vec()).await?;
    wait_output(&mut output, "37 101").await?;
    let command = "printf '\\nSSHOPS_AUDIT_OK\\n'; (exit 7)";
    manager.terminal_input(&session, format!("{command}\r").into_bytes()).await?;
    timeout(Duration::from_secs(15), async {
        loop {
            let event = audits.recv().await.ok_or_else(|| io::Error::other("Missing executed-command audit"))?;
            if let TerminalAuditEventKind::Command { command: actual, exit_code } = event.kind
                && actual == command
            {
                return check(exit_code == 7, "Incorrect terminal audit exit code");
            }
        }
    }).await??;
    manager.terminal_set_audit(&session, false)?;
    manager.terminal_input(&session, b"printf '\\nSSHOPS_QUIET_%s\\n' ok\r".to_vec()).await?;
    wait_output(&mut output, "SSHOPS_QUIET_ok").await?;
    manager.terminal_set_audit(&session, true)?;
    manager.terminal_input(&session, b"printf '\\nSSHOPS_TAIL_%s\\n' complete; exit\r".to_vec()).await?;
    wait_output(&mut output, "SSHOPS_TAIL_complete").await?;
    manager.terminal_close(&session).await?;
    check(manager.terminal_input(&session, vec![b'x']).await.is_err(), "Closed terminal still accepts input")?;
    check(manager.is_connected(host), "Closing a PTY closed the shared SSH transport")?;
    println!("PASS PTY initial size, resize, audited exit status, audit toggles, tail output, close");
    Ok(())
}

async fn wait_output(receive: &mut mpsc::UnboundedReceiver<StreamEnvelope<Vec<u8>>>, expected: &str) -> TestResult {
    timeout(Duration::from_secs(20), async {
        let mut buffer = Vec::new();
        while let Some(event) = receive.recv().await {
            buffer.extend(event.payload);
            if String::from_utf8_lossy(&buffer).contains(expected) { return Ok(()); }
        }
        Err(io::Error::other(format!("Missing PTY output {expected}")).into())
    }).await?
}

async fn sftp_checks(manager: &Arc<SshManager>, host: &str, root: &str, local: &Path) -> TestResult {
    let inputs = local.join("inputs");
    let downloads = local.join("downloads");
    std::fs::create_dir_all(&inputs)?;
    std::fs::create_dir_all(&downloads)?;
    let file = inputs.join("数据 sample.bin");
    let original: Vec<u8> = (0..(256 * 1024 + 17)).map(|value| (value % 251) as u8).collect();
    std::fs::write(&file, &original)?;
    let remote = format!("{root}/数据 sample.bin");
    upload(manager, host, &file, root, "ask", "completed").await?;
    check(remote_digest(manager, host, &remote).await? == digest(&original), "Upload SHA-256 mismatch")?;
    let entries = manager.sftp_list(host, root).await?;
    check(entries.iter().any(|entry| entry.name == "数据 sample.bin" && entry.size == original.len() as u64), "Unicode list metadata mismatch")?;
    let modified_at = entries.iter().find(|entry| entry.name == "数据 sample.bin").and_then(|entry| entry.modified_at.as_deref()).ok_or_else(|| io::Error::other("SFTP listing omitted modification time"))?;
    check((chrono::Utc::now() - chrono::DateTime::parse_from_rfc3339(modified_at)?.with_timezone(&chrono::Utc)).num_minutes().abs() < 5, "SFTP modification timestamp does not reflect the new upload")?;
    download(manager, host, &remote, &downloads, "ask", "completed").await?;
    let local_file = downloads.join("数据 sample.bin");
    check(digest(&std::fs::read(&local_file)?) == digest(&original), "Download SHA-256 mismatch")?;
    let changed = b"replacement payload, not the original";
    std::fs::write(&file, changed)?;
    upload(manager, host, &file, root, "skip", "completed").await?;
    upload(manager, host, &file, root, "ask", "error").await?;
    upload(manager, host, &file, root, "resume", "error").await?;
    check(remote_digest(manager, host, &remote).await? == digest(&original), "Rejected/skipped upload changed destination")?;
    upload(manager, host, &file, root, "rename", "completed").await?;
    check(remote_digest(manager, host, &format!("{root}/数据 sample (1).bin")).await? == digest(changed), "Renamed upload mismatch")?;
    upload(manager, host, &file, root, "overwrite", "completed").await?;
    check(remote_digest(manager, host, &remote).await? == digest(changed), "Overwrite mismatch")?;
    std::fs::write(&file, &original[..113_321])?;
    upload(manager, host, &file, root, "overwrite", "completed").await?;
    std::fs::write(&file, &original)?;
    upload(manager, host, &file, root, "resume", "completed").await?;
    check(remote_digest(manager, host, &remote).await? == digest(&original), "Resumed upload mismatch")?;
    std::fs::write(&local_file, changed)?;
    download(manager, host, &remote, &downloads, "skip", "completed").await?;
    download(manager, host, &remote, &downloads, "ask", "error").await?;
    download(manager, host, &remote, &downloads, "resume", "error").await?;
    check(std::fs::read(&local_file)? == changed, "Rejected/skipped download changed destination")?;
    download(manager, host, &remote, &downloads, "rename", "completed").await?;
    check(digest(&std::fs::read(downloads.join("数据 sample (1).bin"))?) == digest(&original), "Renamed download mismatch")?;
    download(manager, host, &remote, &downloads, "overwrite", "completed").await?;
    std::fs::write(&local_file, &original[..113_321])?;
    download(manager, host, &remote, &downloads, "resume", "completed").await?;
    check(digest(&std::fs::read(&local_file)?) == digest(&original), "Resumed download mismatch")?;
    println!("PASS SFTP Unicode and binary SHA-256; upload/download ask, skip, rename, overwrite, resume and mismatch rejection");

    let tree = inputs.join("tree-目录");
    std::fs::create_dir_all(tree.join("empty"))?;
    std::fs::write(tree.join("zero.txt"), [])?;
    std::fs::write(tree.join("nested.txt"), b"nested")?;
    upload(manager, host, &tree, root, "ask", "completed").await?;
    download(manager, host, &format!("{root}/tree-目录"), &downloads, "ask", "completed").await?;
    check(downloads.join("tree-目录/empty").is_dir(), "Empty directory lost in transfer")?;
    check(std::fs::metadata(downloads.join("tree-目录/zero.txt"))?.len() == 0, "Zero-byte file lost")?;
    let destination = format!("{root}/copied");
    manager.sftp_mkdir(host, &destination).await?;
    let (ipc, mut receive) = events();
    manager.sftp_copy(host, vec![format!("{root}/tree-目录")], destination.clone(), "ask", ipc).await?;
    let end = transfer_end(&mut receive).await?;
    check(end.status == "completed", &format!("Copy failed {:?}", end.error))?;
    check(manager.sftp_list(host, &format!("{destination}/tree-目录/empty")).await?.is_empty(), "Remote copy lost empty directory")?;
    let renamed = format!("{root}/renamed-目录");
    manager.sftp_rename(host, &format!("{destination}/tree-目录"), &renamed).await?;
    check(remote_digest(manager, host, &format!("{renamed}/nested.txt")).await? == digest(b"nested"), "Copied/renamed content mismatch")?;
    manager.sftp_delete(host, std::slice::from_ref(&renamed)).await?;
    check(manager.sftp_list(host, &renamed).await.is_err(), "Recursive deletion left tree")?;
    let (ipc, _) = events();
    check(manager.sftp_copy(host, vec![format!("{root}/tree-目录")], format!("{root}/tree-目录/empty"), "overwrite", ipc).await.is_err(), "Self-descendant copy accepted")?;
    println!("PASS SFTP empty directories, zero-byte files, recursive copy, rename, delete and descendant rejection");

    // Cancel in response to real progress and preserve an existing destination.
    let large = inputs.join("cancel.bin");
    std::fs::write(&large, b"preserve this destination")?;
    upload(manager, host, &large, root, "ask", "completed").await?;
    std::fs::write(&large, vec![0x5a; 8 * 1024 * 1024])?;
    let (send, mut receive) = mpsc::unbounded_channel();
    let cancelling = manager.clone();
    let ipc = Channel::new(move |body| {
        if let InvokeResponseBody::Json(json) = body {
            let event: StreamEnvelope<TransferProgress> = serde_json::from_str(&json).unwrap();
            if event.payload.status == "running" { cancelling.transfer_cancel(&event.payload.transfer_id); }
            let _ = send.send(event);
        }
        Ok(())
    });
    manager.sftp_upload(host, vec![large.display().to_string()], root, "overwrite", ipc).await?;
    check(transfer_end(&mut receive).await?.status == "cancelled", "Active upload cancellation did not report cancelled")?;
    check(remote_digest(manager, host, &format!("{root}/cancel.bin")).await? == digest(b"preserve this destination"), "Cancellation replaced original destination")?;
    check(manager.sftp_list(host, root).await?.iter().all(|entry| !entry.name.contains(".sshopstmp")), "Cancellation left partial files")?;
    println!("PASS active SFTP cancellation, original destination preservation, temporary-file removal");
    Ok(())
}

fn forward(host: &str, kind: &str, port: u16, target: u16) -> ForwardingProfile {
    ForwardingProfile { id: Uuid::new_v4().to_string(), host_id: host.into(), name: "Isolated QA".into(), kind: kind.into(), bind_address: "127.0.0.1".into(), bind_port: port, target_host: Some("127.0.0.1".into()), target_port: Some(target), active: false, status: "stopped".into(), last_error: None }
}

async fn unused_local_port() -> TestResult<u16> { Ok(TcpListener::bind(("127.0.0.1", 0)).await?.local_addr()?.port()) }
async fn banner(mut stream: TcpStream) -> TestResult {
    let mut data = [0; 256];
    let count = timeout(Duration::from_secs(15), stream.read(&mut data)).await??;
    check(data[..count].starts_with(b"SSH-2.0-"), "Forward did not deliver SSH banner")
}

async fn forwarding_checks(manager: &Arc<SshManager>, host: &HostProfile) -> TestResult {
    let local = forward(&host.id, "local", unused_local_port().await?, host.port);
    manager.forward_start(&local).await?;
    check(manager.is_forward_active(&local.id), "Local forward not active")?;
    banner(TcpStream::connect(("127.0.0.1", local.bind_port)).await?).await?;
    manager.forward_stop(&local.id).await?;
    check(!manager.is_forward_active(&local.id), "Stopped local forward still active")?;
    let _released = TcpListener::bind(("127.0.0.1", local.bind_port)).await?;
    let dynamic = forward(&host.id, "dynamic", unused_local_port().await?, host.port);
    manager.forward_start(&dynamic).await?;
    let mut socks = TcpStream::connect(("127.0.0.1", dynamic.bind_port)).await?;
    socks.write_all(&[5, 1, 0]).await?;
    let mut answer = [0; 2];
    timeout(Duration::from_secs(15), socks.read_exact(&mut answer)).await??;
    check(answer == [5, 0], "SOCKS5 method negotiation failed")?;
    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1]; request.extend(host.port.to_be_bytes());
    socks.write_all(&request).await?;
    let mut reply = [0; 10];
    timeout(Duration::from_secs(15), socks.read_exact(&mut reply)).await??;
    check(reply[1] == 0, "SOCKS5 connection failed")?;
    banner(socks).await?;
    manager.forward_stop(&dynamic.id).await?;
    println!("PASS local forwarding, SOCKS5 dynamic forwarding, SSH banners and listener release");

    // The short remote helper binds only loopback to choose an unused port.
    let probe = manager.exec(&host.id, "python3 -c 'import socket; s=socket.socket(); s.bind((\"127.0.0.1\",0)); print(s.getsockname()[1]); s.close()'").await?;
    check(probe.exit_code == 0, "Remote-forward verification requires python3 on the test host")?;
    let remote_port: u16 = probe.stdout.trim().parse()?;
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let remote = forward(&host.id, "remote", remote_port, listener.local_addr()?.port());
    manager.forward_start(&remote).await?;
    let echo = async {
        let (mut socket, _) = timeout(Duration::from_secs(20), listener.accept()).await??;
        let mut data = [0; 15];
        timeout(Duration::from_secs(20), socket.read_exact(&mut data)).await??;
        check(&data == b"sshops-echo-ok\n", "Remote forward request payload mismatch")?;
        socket.write_all(&data).await?;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    let command = format!("python3 -c 'import socket; s=socket.create_connection((\"127.0.0.1\",{remote_port}),10); s.sendall(b\"sshops-echo-ok\\n\"); print(s.recv(100).decode().strip()); s.close()'");
    let (echo_result, remote_result) = tokio::join!(echo, manager.exec(&host.id, &command));
    echo_result?;
    let remote_result = remote_result?;
    check(remote_result.exit_code == 0 && remote_result.stdout.trim() == "sshops-echo-ok", "Remote forward echo mismatch")?;
    manager.forward_stop(&remote.id).await?;
    check(!manager.is_forward_active(&remote.id), "Remote forward stayed active")?;
    // Completed TCP traffic may leave TIME_WAIT sockets. Match OpenSSH's
    // SO_REUSEADDR behavior so this checks the listener, not connection expiry.
    let port_released = manager.exec(&host.id, &format!("python3 -c 'import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",{remote_port})); s.close()'")).await?;
    check(port_released.exit_code == 0, &format!("Remote forwarding port was not released: {}", port_released.stderr.trim()))?;
    println!("PASS loopback remote forwarding, local echo round-trip and listener release");
    Ok(())
}

struct RelayTask(tokio::task::JoinHandle<()>);
impl Drop for RelayTask { fn drop(&mut self) { self.0.abort(); } }

async fn abrupt_disconnect_checks(db: &Database, host: &HostProfile) -> TestResult {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let relay_port = listener.local_addr()?.port();
    let remote_endpoint = (host.hostname.clone(), host.port);
    let (break_first, receive_break) = tokio::sync::oneshot::channel::<()>();
    let mut relay = RelayTask(tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        let mut receive_break = Some(receive_break);
        while let Ok((mut local, _)) = listener.accept().await {
            let endpoint = remote_endpoint.clone();
            let interruption = receive_break.take();
            connections.spawn(async move {
                let Ok(mut remote) = TcpStream::connect(endpoint).await else { return; };
                let transfer = tokio::io::copy_bidirectional(&mut local, &mut remote);
                if let Some(interruption) = interruption {
                    tokio::select! { _ = transfer => {}, _ = interruption => {} }
                } else {
                    let _ = transfer.await;
                }
            });
        }
    }));
    let mut proxied = host.clone();
    proxied.id = format!("live-relay-{}", Uuid::new_v4());
    proxied.hostname = "127.0.0.1".into();
    proxied.port = relay_port;
    db.host_upsert(&proxied)?;
    // The relay carries raw bytes to the original endpoint. Preserve exactly
    // that endpoint's previously trusted key in this isolated database only.
    let fingerprint = db.known_fingerprint(&host.id, &format!("{}:{}", host.hostname, host.port))?
        .ok_or_else(|| io::Error::other("Original endpoint is not trusted"))?;
    db.set_fingerprint(&proxied.id, &format!("127.0.0.1:{relay_port}"), &fingerprint)?;
    let manager = SshManager::default();
    let outcome = async {
        manager.connect(db, proxied.clone(), None).await?;
        check(manager.exec(&proxied.id, "printf before-drop").await?.stdout == "before-drop", "SSH relay initial command failed")?;
        break_first.send(()).map_err(|_| io::Error::other("Relay closed before fault injection"))?;
        timeout(Duration::from_secs(15), async {
            while manager.is_connected(&proxied.id) { tokio::time::sleep(Duration::from_millis(25)).await; }
        }).await?;
        check(manager.exec(&proxied.id, "printf must-fail").await.is_err(), "Dropped transport still accepts commands")?;
        manager.connect(db, proxied.clone(), None).await?;
        check(manager.is_connected(&proxied.id), "Relay reconnection status remained disconnected")?;
        check(manager.exec(&proxied.id, "printf after-drop").await?.stdout == "after-drop", "SSH did not recover after interrupted network")?;
        println!("PASS abrupt local-relay network interruption, disconnected status, command rejection and authenticated reconnect");
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    }.await;
    let disconnected = manager.disconnect(&proxied.id).await;
    relay.0.abort();
    let _ = (&mut relay.0).await;
    let _released = TcpListener::bind(("127.0.0.1", relay_port)).await?;
    db.host_delete(&proxied.id)?;
    disconnected?;
    outcome
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires SSHOPS_LIVE_TEST=1 and an already trusted saved SSH host"]
async fn trusted_saved_host_full_isolated_round_trip() -> TestResult {
    check(std::env::var("SSHOPS_LIVE_TEST").as_deref() == Ok("1"), "Set SSHOPS_LIVE_TEST=1 explicitly before running live tests")?;
    let scope = std::env::var("SSHOPS_LIVE_SCOPE").unwrap_or_else(|_| "all".into());
    check(matches!(scope.as_str(), "all" | "forwarding" | "disconnect"), "SSHOPS_LIVE_SCOPE must be all, forwarding or disconnect")?;
    let directory = tempfile::tempdir()?;
    let (db, host) = saved_fixture(directory.path())?;
    let manager = Arc::new(SshManager::default());
    timeout(Duration::from_secs(45), manager.connect(&db, host.clone(), None)).await??;
    check(manager.is_connected(&host.id), "Saved key authentication did not establish a connection")?;
    manager.verify_new_connection(&db, &host.id).await?;
    println!("PASS saved key authentication and pinned host-key verification, independent reauthentication");
    let run_id = Uuid::new_v4().to_string();
    let remote_root = format!("/tmp/sshops-qa-{run_id}");
    let create = manager.exec(&host.id, &format!("umask 077; mkdir -- '{remote_root}'")).await?;
    check(create.exit_code == 0, "Could not create private isolated remote directory")?;
    println!("Isolated remote test directory: {remote_root}");
    let outcome = AssertUnwindSafe(timeout(Duration::from_secs(900), async {
        let permissions = manager.exec(&host.id, &format!("test \"$(stat -c %a -- '{remote_root}')\" = 700")).await?;
        check(permissions.exit_code == 0, "Remote isolation directory is not mode 0700")?;
        if scope == "all" {
            let result = manager.exec_with_input(&host.id, "IFS= read -r line; printf 'OUT:%s\\n' \"$line\"; printf 'ERR:ok\\n' >&2; exit 7", Some("Unicode 中文 input")).await?;
            check(result.stdout == "OUT:Unicode 中文 input\n" && result.stderr == "ERR:ok\n" && result.exit_code == 7, "Exec stdin/stdout/stderr/exit status mismatch")?;
            println!("PASS exec stdin, Unicode stdout, stderr and nonzero exit status");
            terminal_checks(&manager, &host.id).await?;
            sftp_checks(&manager, &host.id, &remote_root, directory.path()).await?;
        }
        if scope != "disconnect" { forwarding_checks(&manager, &host).await?; }
        if scope != "forwarding" { abrupt_disconnect_checks(&db, &host).await?; }
        manager.disconnect(&host.id).await?;
        check(!manager.is_connected(&host.id), "Disconnect retained connected status")?;
        manager.connect(&db, host.clone(), None).await?;
        check(manager.exec(&host.id, "printf reconnect-ok").await?.stdout == "reconnect-ok", "Reconnect command failed")?;
        println!("PASS disconnect and reconnect using existing saved trust");
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    })).catch_unwind().await;
    // Finally-style cleanup runs even when an assertion panics or the suite times out.
    check(remote_root == format!("/tmp/sshops-qa-{run_id}") && Uuid::parse_str(&run_id).is_ok(), "Refusing unexpected cleanup path")?;
    let _ = manager.disconnect(&host.id).await;
    let cleanup = async {
        manager.connect(&db, host.clone(), None).await?;
        manager.sftp_delete(&host.id, std::slice::from_ref(&remote_root)).await?;
        let gone = manager.exec(&host.id, &format!("test ! -e '{remote_root}'")).await?;
        check(gone.exit_code == 0, "Remote test directory remained after cleanup")?;
        manager.disconnect(&host.id).await?;
        println!("PASS verified removal of isolated remote test directory");
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    timeout(Duration::from_secs(90), cleanup).await??;
    match outcome {
        Ok(result) => result?,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
