//! Local protocol tests: no saved credentials, external host or remote shell is used.
use super::*;
use russh::{ChannelId, server};

#[derive(Default)]
struct TestServer { commands: HashMap<ChannelId, Vec<u8>> }

impl server::Handler for TestServer {
    type Error = russh::Error;

    async fn tcpip_forward(&mut self, _: &str, _: &mut u32, _: &mut server::Session) -> Result<bool, Self::Error> { Ok(true) }

    async fn auth_password(&mut self, _: &str, password: &str) -> Result<server::Auth, Self::Error> {
        Ok(if password == "test-only" { server::Auth::Accept } else { server::Auth::reject() })
    }

    async fn channel_open_session(&mut self, _: russh::Channel<server::Msg>, reply: server::ChannelOpenHandle, _: &mut server::Session) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(&mut self, channel: ChannelId, command: &[u8], session: &mut server::Session) -> Result<(), Self::Error> {
        session.channel_success(channel)?;
        self.commands.insert(channel, command.to_vec());
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
