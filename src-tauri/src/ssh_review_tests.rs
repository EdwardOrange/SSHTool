//! Local protocol tests: no saved credentials, external host or remote shell is used.
use super::*;
use russh::{ChannelId, server};

#[derive(Default)]
struct TestServer {
    commands: HashMap<ChannelId, Vec<u8>>,
    channels: HashMap<ChannelId, russh::Channel<server::Msg>>,
}

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn tcpip_forward(&mut self, _: &str, _: &mut u32, _: &mut server::Session) -> Result<bool, Self::Error> { Ok(true) }

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<server::Auth, Self::Error> {
        Ok(if password == "test-only" { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn auth_publickey(&mut self, _: &str, public_key: &ssh_key::PublicKey) -> Result<server::Auth, Self::Error> {
        let expected = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
        Ok(if public_key == expected.public_key() { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn channel_open_session(&mut self, channel: russh::Channel<server::Msg>, reply: server::ChannelOpenHandle, _: &mut server::Session) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(&mut self, channel: ChannelId, name: &str, session: &mut server::Session) -> Result<(), Self::Error> {
        if name == "sftp" {
            session.channel_success(channel)?;
            let channel = self.channels.remove(&channel).unwrap();
            russh_sftp::server::run(channel.into_stream(), UnsafeDirectoryServer {
                entry: "no-time.txt".into(), listed: false, removed: Arc::new(RwLock::new(Vec::new())),
            }).await;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut server::Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.commands.insert(channel, command.to_vec());
        Ok(())
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut server::Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        session.data(channel, b"before ".to_vec())?;
        session.exit_status_request(channel, 0)?;
        session.data(channel, b"after".to_vec())?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn channel_eof(&mut self, channel: ChannelId, session: &mut server::Session) -> Result<(), Self::Error> {
        let command = self.commands.remove(&channel).unwrap_or_default();
        if command != b"missing-status" {
            session.data(channel, b"before ".to_vec())?;
            session.exit_status_request(channel, 0)?;
            // SSH permits data after the exit-status request; read through close.
            session.data(channel, b"after".to_vec())?;
        }
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }
}

async fn fixture() -> (tempfile::TempDir, Database, HostProfile, tokio::task::JoinHandle<()>, Arc<AtomicU64>) {
    let directory = tempfile::tempdir().unwrap();
    let db = Database::open(&directory.path().join("test.db")).unwrap();
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]));
    let fingerprint = key.public_key().fingerprint(ssh_key::HashAlg::Sha256).to_string();
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let profile = HostProfile {
        id: "test-host".into(), name: "Test".into(), hostname: "127.0.0.1".into(), port: listener.local_addr().unwrap().port(),
        username: "test".into(), group_name: String::new(), tags: vec![], favorite: false, auth_method: "password".into(),
        credential_id: None, private_key_path: None, jump_hosts: vec![], host_key_fingerprint: Some(fingerprint.clone()),
        status: "disconnected".into(), last_connected_at: None, created_at: String::new(), updated_at: String::new(),
    };
    db.host_upsert(&profile).unwrap();
    db.set_fingerprint(&profile.id, &format!("{}:{}", profile.hostname, profile.port), &fingerprint).unwrap();
    let config = Arc::new(server::Config { keys: vec![key], auth_rejection_time: Duration::ZERO, ..Default::default() });
    let accepted = Arc::new(AtomicU64::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        let mut sessions = tokio::task::JoinSet::new();
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            let config = config.clone();
            sessions.spawn(async move { if let Ok(session) = server::run_stream(config, socket, TestServer::default()).await { let _ = session.await; } });
        }
    });
    (directory, db, profile, task, accepted)
}

#[tokio::test]
async fn command_failure_preserves_transport_and_output_after_exit_status() {
    let (_directory, db, profile, server, _) = fixture().await;
    let manager = SshManager::default();
    manager.connect(&db, profile.clone(), Some("test-only".into())).await.unwrap();
    assert!(timeout(Duration::from_secs(5), manager.exec(&profile.id, "missing-status")).await.unwrap().is_err());
    assert!(manager.is_connected(&profile.id));
    let output = timeout(Duration::from_secs(5), manager.exec(&profile.id, "success")).await.unwrap().unwrap();
    assert_eq!(output.stdout, "before after");
    assert_eq!(output.exit_code, 0);
    manager.disconnect(&profile.id).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn simultaneous_connects_share_one_transport_and_verification_can_reauthenticate() {
    let (_directory, db, profile, server, accepted) = fixture().await;
    let manager = SshManager::default();
    let (a, b) = tokio::join!(manager.connect(&db, profile.clone(), Some("test-only".into())), manager.connect(&db, profile.clone(), Some("test-only".into())));
    a.unwrap(); b.unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    manager.verify_new_connection(&db, &profile.id).await.unwrap();
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    manager.disconnect(&profile.id).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn encrypted_private_key_prompts_then_accepts_supplied_passphrase_and_reauthenticates() {
    let (directory, db, mut profile, server, _) = fixture().await;
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
    let encrypted = key.encrypt_with(ssh_key::Cipher::Aes256Ctr, ssh_key::Kdf::Bcrypt { salt: vec![11; 16], rounds: 1 }, 123456, "test-passphrase-only").unwrap();
    let path = directory.path().join("encrypted-test-key");
    encrypted.write_openssh_file(&path, Default::default()).unwrap();
    profile.auth_method = "key".into();
    profile.private_key_path = Some(path.display().to_string());
    db.host_upsert(&profile).unwrap();
    let manager = SshManager::default();
    let missing = manager.connect(&db, profile.clone(), None).await.unwrap_err();
    assert!(matches!(missing, AppError::KeyPassphraseRequired));
    assert!(!manager.is_connected(&profile.id));
    let invalid = manager.connect(&db, profile.clone(), Some("incorrect-test-passphrase".into())).await.unwrap_err();
    assert!(matches!(invalid, AppError::Permission(_)), "{invalid}");
    assert!(invalid.to_string().contains("私钥口令错误"));
    assert!(!invalid.to_string().contains("incorrect-test-passphrase"));
    assert!(!manager.is_connected(&profile.id));
    manager.connect(&db, profile.clone(), Some("test-passphrase-only".into())).await.unwrap();
    assert!(manager.is_connected(&profile.id));
    manager.verify_new_connection(&db, &profile.id).await.unwrap();
    manager.disconnect(&profile.id).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn unencrypted_private_key_connects_without_a_passphrase() {
    let (directory, db, mut profile, server, _) = fixture().await;
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]));
    let path = directory.path().join("plain-test-key");
    key.write_openssh_file(&path, Default::default()).unwrap();
    profile.auth_method = "key".into();
    profile.private_key_path = Some(path.display().to_string());
    db.host_upsert(&profile).unwrap();
    let manager = SshManager::default();
    manager.connect(&db, profile.clone(), None).await.unwrap();
    assert!(manager.is_connected(&profile.id));
    manager.disconnect(&profile.id).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn connect_waiting_for_deletion_cannot_recreate_a_session() {
    let (_directory, db, profile, server, accepted) = fixture().await;
    let manager = SshManager::default();
    let operation = manager.connection_lock(&profile.id);
    let guard = operation.lock().await;
    let mut connecting = Box::pin(manager.connect(&db, profile.clone(), Some("test-only".into())));
    assert!(futures::poll!(connecting.as_mut()).is_pending());
    db.host_delete(&profile.id).unwrap();
    drop(guard);
    assert!(matches!(connecting.await, Err(AppError::NotFound(_))));
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    assert!(!manager.is_connected(&profile.id));
    server.abort();
}

#[tokio::test]
async fn connect_uses_endpoint_and_identity_saved_while_waiting_for_the_lock() {
    let (_directory, db, profile, old_server, old_accepted) = fixture().await;
    let (_new_directory, _new_db, new_profile, new_server, new_accepted) = fixture().await;
    let manager = SshManager::default();
    let operation = manager.connection_lock(&profile.id);
    let guard = operation.lock().await;
    let mut connecting = Box::pin(manager.connect(&db, profile.clone(), Some("test-only".into())));
    assert!(futures::poll!(connecting.as_mut()).is_pending());
    let mut edited = profile.clone();
    edited.port = new_profile.port;
    edited.username = "edited-user".into();
    db.host_upsert(&edited).unwrap();
    db.set_fingerprint(&edited.id, &format!("{}:{}", edited.hostname, edited.port), edited.host_key_fingerprint.as_ref().unwrap()).unwrap();
    drop(guard);
    timeout(Duration::from_secs(5), connecting).await.unwrap().unwrap();
    assert_eq!(old_accepted.load(Ordering::SeqCst), 0);
    assert_eq!(new_accepted.load(Ordering::SeqCst), 1);
    assert_eq!(manager.profile(&profile.id).unwrap().username, "edited-user");
    manager.disconnect(&profile.id).await.unwrap();
    old_server.abort();
    new_server.abort();
}

#[tokio::test]
async fn connect_revalidates_jump_routes_edited_while_waiting_for_the_lock() {
    let (_directory, db, mut profile, server, accepted) = fixture().await;
    let manager = SshManager::default();
    let operation = manager.connection_lock(&profile.id);
    let guard = operation.lock().await;
    let mut connecting = Box::pin(manager.connect(&db, profile.clone(), Some("test-only".into())));
    assert!(futures::poll!(connecting.as_mut()).is_pending());
    profile.jump_hosts.push(crate::models::JumpHost { host_id: profile.id.clone(), order: 0 });
    db.host_upsert(&profile).unwrap();
    drop(guard);
    assert!(matches!(timeout(Duration::from_secs(1), connecting).await.unwrap(), Err(AppError::Validation(_))));
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    server.abort();
}

#[tokio::test]
async fn imported_fingerprint_cannot_establish_trust_or_follow_an_endpoint_edit() {
    let (_directory, db, mut profile, server, _) = fixture().await;
    db.0.lock().execute("DELETE FROM known_hosts", []).unwrap();
    let manager = SshManager::default();
    assert!(manager.connect(&db, profile.clone(), Some("test-only".into())).await.is_err());
    let fingerprint = manager.pending_host_key(&profile.id).unwrap();
    profile.hostname = "localhost".into(); db.host_upsert(&profile).unwrap();
    assert!(manager.trust_host_key(&db, &profile.id, &fingerprint).is_err());
    assert!(!manager.is_connected(&profile.id));
    server.abort();
}

fn forward_profile(host: &HostProfile, kind: &str, port: u16) -> crate::models::ForwardingProfile {
    crate::models::ForwardingProfile {
        id: "test-forward".into(), host_id: host.id.clone(), name: "Test".into(), kind: kind.into(),
        bind_address: "127.0.0.1".into(), bind_port: port, target_host: Some("127.0.0.1".into()), target_port: Some(80),
        active: false, status: "stopped".into(), last_error: None,
    }
}

#[tokio::test]
async fn stopping_local_forward_releases_listener_before_returning() {
    let (_directory, db, profile, server, _) = fixture().await;
    let manager = SshManager::default();
    manager.connect(&db, profile.clone(), Some("test-only".into())).await.unwrap();
    let reservation = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = reservation.local_addr().unwrap().port(); drop(reservation);
    let forward = forward_profile(&profile, "local", port);
    manager.forward_start(&forward).await.unwrap();
    assert!(manager.is_forward_active(&forward.id));
    manager.forward_stop(&forward.id).await.unwrap();
    // Immediate rebind used to race the asynchronously cancelled listener.
    let probe = TcpListener::bind(("127.0.0.1", port)).await.unwrap(); drop(probe);
    manager.forward_start(&forward).await.unwrap();
    manager.disconnect(&profile.id).await.unwrap();
    assert!(!manager.is_forward_active(&forward.id));
    server.abort();
}

#[tokio::test]
async fn rejected_remote_cancellation_remains_retryable_and_disconnect_still_works() {
    let (_directory, db, profile, server, _) = fixture().await;
    let manager = SshManager::default();
    manager.connect(&db, profile.clone(), Some("test-only".into())).await.unwrap();
    let forward = forward_profile(&profile, "remote", 12345);
    manager.forward_start(&forward).await.unwrap();
    assert!(manager.forward_stop(&forward.id).await.is_err());
    assert!(manager.is_forward_active(&forward.id));
    assert!(manager.forward_stop(&forward.id).await.is_err());
    manager.disconnect(&profile.id).await.unwrap();
    assert!(!manager.is_connected(&profile.id));
    assert!(!manager.is_forward_active(&forward.id));
    server.abort();
}

#[tokio::test]
async fn recording_connection_preserves_edits_and_does_not_resurrect_deleted_hosts() {
    let (_directory, db, mut profile, server, _) = fixture().await;
    profile.name = "Updated while connecting".into();
    profile.favorite = true;
    db.host_upsert(&profile).unwrap();
    db.host_record_connection(&profile.id, true).unwrap();
    let saved = db.host_get(&profile.id).unwrap();
    assert_eq!(saved.name, profile.name);
    assert!(saved.favorite);
    assert!(saved.last_connected_at.is_some());
    db.host_delete(&profile.id).unwrap();
    assert!(db.host_record_connection(&profile.id, true).is_err());
    assert!(db.host_get(&profile.id).is_err());
    server.abort();
}

#[tokio::test]
async fn terminal_keeps_output_after_exit_status_until_channel_close() {
    let (_directory, db, profile, server, _) = fixture().await;
    let manager = Arc::new(SshManager::default());
    manager.connect(&db, profile.clone(), Some("test-only".into())).await.unwrap();
    let output = Arc::new(RwLock::new(Vec::new()));
    let captured = output.clone();
    let ipc = IpcChannel::new(move |message| {
        if let tauri::ipc::InvokeResponseBody::Json(json) = message {
            let message: StreamEnvelope<Vec<u8>> = serde_json::from_str(&json).unwrap();
            captured.write().extend(message.payload);
        }
        Ok(())
    });
    let (audit, _) = mpsc::unbounded_channel();
    let id = manager.terminal_open(&profile.id, 80, 24, ipc, false, audit).await.unwrap();
    timeout(Duration::from_secs(5), async {
        while manager.terminals.read().contains_key(&id) { tokio::task::yield_now().await; }
    }).await.unwrap();
    assert_eq!(&*output.read(), b"before after");
    manager.disconnect(&profile.id).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn closing_terminal_does_not_wait_for_a_full_input_queue() {
    let manager = SshManager::default();
    let (sender, _receiver) = mpsc::channel(1);
    sender.send(TerminalCommand::Input(vec![1])).await.unwrap();
    let (cancel, mut cancelled) = watch::channel(false);
    manager.terminals.write().insert("blocked-terminal".into(), ManagedTerminal {
        host_id: "host".into(), sender, cancel,
        audit_enabled: Arc::new(AtomicBool::new(false)), audit_configured: false,
    });
    timeout(Duration::from_secs(1), manager.terminal_close("blocked-terminal")).await.unwrap().unwrap();
    assert!(!manager.terminals.read().contains_key("blocked-terminal"));
    cancelled.changed().await.unwrap();
    assert!(*cancelled.borrow());
}

struct UnsafeDirectoryServer {
    entry: String,
    listed: bool,
    removed: Arc<RwLock<Vec<String>>>,
}

impl russh_sftp::server::Handler for UnsafeDirectoryServer {
    type Error = russh_sftp::protocol::StatusCode;

    fn unimplemented(&self) -> Self::Error { Self::Error::OpUnsupported }

    async fn lstat(&mut self, id: u32, _: String) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let mut attrs = russh_sftp::protocol::FileAttributes::default();
        attrs.set_dir(true);
        Ok(russh_sftp::protocol::Attrs { id, attrs })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<russh_sftp::protocol::Handle, Self::Error> {
        Ok(russh_sftp::protocol::Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, _: String) -> Result<russh_sftp::protocol::Name, Self::Error> {
        if self.listed { return Err(Self::Error::Eof); }
        self.listed = true;
        let mut attrs = russh_sftp::protocol::FileAttributes::default();
        attrs.set_regular(true);
        attrs.mtime = Some(1_700_000_000);
        let timed = attrs.clone();
        attrs.mtime = None;
        Ok(russh_sftp::protocol::Name { id, files: vec![
            russh_sftp::protocol::File::new("normal.txt", timed),
            russh_sftp::protocol::File::new(&self.entry, attrs),
        ] })
    }

    async fn close(&mut self, _: u32, _: String) -> Result<russh_sftp::protocol::Status, Self::Error> { Err(Self::Error::Ok) }

    async fn remove(&mut self, _: u32, filename: String) -> Result<russh_sftp::protocol::Status, Self::Error> {
        self.removed.write().push(filename);
        Err(Self::Error::Ok)
    }
}

#[tokio::test]
async fn sftp_list_preserves_server_modification_time_and_missing_metadata() {
    let (_directory, db, profile, server, _) = fixture().await;
    let manager = SshManager::default();
    manager.connect(&db, profile.clone(), Some("test-only".into())).await.unwrap();
    let entries = timeout(Duration::from_secs(5), manager.sftp_list(&profile.id, "/selected")).await.unwrap().unwrap();
    assert_eq!(entries.iter().find(|entry| entry.name == "normal.txt").unwrap().modified_at.as_deref(), Some("2023-11-14T22:13:20+00:00"));
    assert!(entries.iter().find(|entry| entry.name == "no-time.txt").unwrap().modified_at.is_none());
    manager.disconnect(&profile.id).await.unwrap();
    server.abort();
}

#[tokio::test]
async fn recursive_delete_rejects_path_entries_before_removing_any_files() {
    for name in ["../outside.txt", "child/../../outside.txt", "/outside.txt", "nested/file", ""] {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let removed = Arc::new(RwLock::new(Vec::new()));
        russh_sftp::server::run(server, UnsafeDirectoryServer { entry: name.into(), listed: false, removed: removed.clone() }).await;
        let sftp = SftpSession::new(client).await.unwrap();
        assert!(timeout(Duration::from_secs(2), remove_remote_tree(&sftp, "/selected")).await.unwrap().is_err());
        assert!(removed.read().is_empty(), "removed entries for invalid name {name:?}: {:?}", removed.read());
        sftp.close().await.unwrap();
    }
}

#[test]
fn remote_entry_validation_keeps_posix_names_without_accepting_paths() {
    for name in ["hello.txt", "中文.txt", ".hidden", "CON", "back\\slash", "name:with:colon"] {
        assert!(validate_remote_entry_name(name).is_ok(), "{name}");
    }
    for name in [".", "..", "../outside", "sub/child", "nul\0byte"] {
        assert!(validate_remote_entry_name(name).is_err(), "{name}");
    }
}

#[test]
fn renamed_download_preserves_extension_and_parent_directory() {
    let directory = PathBuf::from("downloads.v2").join("中文");
    assert_eq!(renamed_local_path(&directory.join("report.csv"), 1).unwrap(), directory.join("report (1).csv"));
    assert_eq!(renamed_local_path(&directory.join("archive.tar.gz"), 2).unwrap(), directory.join("archive.tar (2).gz"));
    assert_eq!(renamed_local_path(&directory.join(".env"), 3).unwrap(), directory.join(".env (3)"));
    assert_eq!(renamed_local_path(&directory.join("README"), 4).unwrap(), directory.join("README (4)"));
}

#[tokio::test]
async fn socks5_parses_ipv6_destination_and_preserves_following_payload() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let target = socks5_connect(&mut stream).await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        (target, payload)
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut authentication = [0; 2];
    client.read_exact(&mut authentication).await.unwrap();
    assert_eq!(authentication, [5, 0]);
    let destination: std::net::Ipv6Addr = "2001:db8::1234".parse().unwrap();
    let mut request = vec![5, 1, 0, 4];
    request.extend(destination.octets());
    request.extend(443u16.to_be_bytes());
    request.extend(b"data");
    client.write_all(&request).await.unwrap();
    let (target, payload) = timeout(Duration::from_secs(2), server).await.unwrap().unwrap();
    assert_eq!(target, ("2001:db8::1234".into(), 443));
    assert_eq!(&payload, b"data");
}
