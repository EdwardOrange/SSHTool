use super::*;

pub(super) fn fixture() -> (tempfile::TempDir, AppState) {
    let directory = tempfile::tempdir().unwrap();
    let state = AppState {
        db: Arc::new(Database::open(&directory.path().join("test.db")).unwrap()),
        ssh: Arc::new(SshManager::default()),
        monitor: Arc::new(MonitorManager::default()),
        firewall: Arc::new(FirewallManager::default()),
        command_channels: Arc::new(Mutex::new(Vec::new())),
        host_operations: Mutex::new(HashMap::new()),
        forward_operations: tokio::sync::Mutex::new(()),
    };
    (directory, state)
}

pub(super) fn draft() -> HostDraft {
    HostDraft {
        id: None, name: "Test".into(), hostname: "example.invalid".into(), port: 22,
        username: "test".into(), group_name: String::new(), tags: vec![], favorite: false,
        auth_method: "password".into(), credential_id: None, private_key_path: None,
        jump_hosts: None, password: None, remember_password: Some(false), host_key_fingerprint: None,
    }
}

#[tokio::test]
async fn a_save_waiting_for_deletion_cannot_recreate_the_host() {
    let (_directory, state) = fixture();
    let host = save_host(&state, draft()).await.unwrap();
    let operation = state.host_operation(&host.id);
    let guard = operation.lock().await;
    let mut edit = draft();
    edit.id = Some(host.id.clone());
    edit.name = "Stale edit".into();
    let mut saving = Box::pin(save_host(&state, edit));
    assert!(futures::poll!(saving.as_mut()).is_pending());
    state.db.host_delete(&host.id).unwrap();
    drop(guard);
    assert!(matches!(saving.await, Err(AppError::NotFound(_))));
    assert!(state.db.hosts_list().unwrap().is_empty());
}

#[tokio::test]
async fn connect_reads_configuration_after_pending_host_operations() {
    let (_directory, state) = fixture();
    let operation = state.host_operation("deleted-host");
    let guard = operation.lock().await;
    let mut connecting = Box::pin(connect_host(&state, "deleted-host", None));
    assert!(futures::poll!(connecting.as_mut()).is_pending());
    drop(guard);
    // No network request or credential access is made for a deleted host.
    assert!(matches!(connecting.await, Err(AppError::NotFound(_))));
}

#[tokio::test]
async fn saving_a_jump_host_waits_for_its_recursive_connection() {
    let (_directory, state) = fixture();
    let host = save_host(&state, draft()).await.unwrap();
    let connection_operation = state.ssh.connection_lock(&host.id);
    let guard = connection_operation.lock().await;
    let mut edit = draft();
    edit.id = Some(host.id.clone());
    edit.hostname = "new-address.invalid".into();
    let mut saving = Box::pin(save_host(&state, edit));
    assert!(futures::poll!(saving.as_mut()).is_pending());
    assert_eq!(state.db.host_get(&host.id).unwrap().hostname, host.hostname);
    drop(guard);
    assert_eq!(saving.await.unwrap().hostname, "new-address.invalid");
}

#[tokio::test]
async fn connection_settings_include_authentication_and_jump_route() {
    let (_directory, state) = fixture();
    let host = save_host(&state, draft()).await.unwrap();
    let mut cosmetic = draft();
    cosmetic.name = "Rename".into();
    cosmetic.favorite = true;
    assert!(!connection_settings_changed(&host, &cosmetic));
    let mut edited = draft();
    edited.username = "root".into();
    assert!(connection_settings_changed(&host, &edited));
    let mut edited = draft();
    edited.auth_method = "agent".into();
    assert!(connection_settings_changed(&host, &edited));
    let mut edited = draft();
    edited.jump_hosts = Some(vec![JumpHost { host_id: "jump".into(), order: 0 }]);
    assert!(connection_settings_changed(&host, &edited));
}

#[tokio::test]
async fn import_skips_existing_hosts_atomically_and_reports_only_insertions() {
    let (_directory, state) = fixture();
    let existing = save_host(&state, draft()).await.unwrap();
    let mut duplicate = existing.clone();
    duplicate.name = "Imported stale name".into();
    duplicate.hostname = "different.invalid".into();
    let mut new_host = duplicate.clone();
    new_host.id = "new-host".into();
    let inserted = state.db.hosts_import(&[duplicate, new_host.clone()]).unwrap();
    assert_eq!(inserted.len(), 1);
    assert_eq!(inserted[0].id, new_host.id);
    let saved = state.db.host_get(&existing.id).unwrap();
    assert_eq!(saved.name, existing.name);
    assert_eq!(saved.hostname, existing.hostname);
    assert!(state.db.hosts_import(&[new_host]).unwrap().is_empty());
}

#[tokio::test]
async fn imported_hosts_cannot_supply_trust_credentials_or_duplicate_ids() {
    let (_directory, state) = fixture();
    let mut host = save_host(&state, draft()).await.unwrap();
    host.credential_id = Some("another-host-secret".into());
    host.host_key_fingerprint = Some("untrusted-key".into());
    host.status = "connected".into();
    let file = serde_json::to_vec(&serde_json::json!({ "hosts": [host.clone()] })).unwrap();
    let imported = parse_imported_hosts(&file).unwrap();
    assert!(imported[0].credential_id.is_none());
    assert!(imported[0].host_key_fingerprint.is_none());
    assert_eq!(imported[0].status, "disconnected");
    let duplicate_file = serde_json::to_vec(&serde_json::json!({ "hosts": [host.clone(), host] })).unwrap();
    assert!(parse_imported_hosts(&duplicate_file).is_err());
}

#[tokio::test]
async fn saved_secrets_are_scoped_to_the_existing_host_and_authentication() {
    let (_directory, state) = fixture();
    let mut host = save_host(&state, draft()).await.unwrap();
    host.auth_method = "key".into();
    host.private_key_path = Some("test-key".into());
    host.credential_id = Some("existing-passphrase".into());
    let mut edit = draft();
    edit.auth_method = "key".into();
    edit.private_key_path = host.private_key_path.clone();
    edit.remember_password = Some(true);
    edit.password = Some(String::new());
    // A blank form field retains the original passphrase without touching the
    // operating system credential store. A supplied foreign ID is never used.
    edit.credential_id = Some("another-host-secret".into());
    assert_eq!(retained_credential_id(Some(&host), &edit), host.credential_id);
    assert_eq!(retained_credential_id(None, &edit), None);
    edit.private_key_path = Some("different-key".into());
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
    edit.private_key_path = host.private_key_path.clone();
    edit.auth_method = "password".into();
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
    edit.auth_method = "key".into();
    edit.remember_password = Some(false);
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
    edit.remember_password = Some(true);
    edit.auth_method = "agent".into();
    host.auth_method = "agent".into();
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
}

#[tokio::test]
async fn saved_ssh_credentials_are_not_reused_for_another_endpoint_or_user() {
    let (_directory, state) = fixture();
    let mut host = save_host(&state, draft()).await.unwrap();
    host.credential_id = Some("saved-password-reference".into());
    let mut edit = draft();
    edit.remember_password = Some(true);
    assert_eq!(retained_credential_id(Some(&host), &edit), host.credential_id);
    edit.hostname = "other.invalid".into();
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
    edit.hostname = host.hostname.clone();
    edit.port = 2222;
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
    edit.port = host.port;
    edit.username = "other-user".into();
    assert_eq!(retained_credential_id(Some(&host), &edit), None);
    edit.username = format!(" {} ", host.username);
    edit.name = "Cosmetic rename".into();
    assert_eq!(retained_credential_id(Some(&host), &edit), host.credential_id);
}

#[tokio::test]
async fn sudo_credentials_are_scoped_to_host_endpoint_and_user_but_not_display_fields() {
    let (_directory, state) = fixture();
    let host = save_host(&state, draft()).await.unwrap();
    let original = sudo_credential_id(&host);
    let mut edited = host.clone();
    edited.name = "Cosmetic rename".into();
    edited.favorite = true;
    edited.updated_at = "later".into();
    assert_eq!(sudo_credential_id(&edited), original);
    for field in ["id", "hostname", "port", "username"] {
        let mut edited = host.clone();
        match field {
            "id" => edited.id.push_str("-new"),
            "hostname" => edited.hostname = "another.invalid".into(),
            "port" => edited.port = 2222,
            "username" => edited.username = "another-user".into(),
            _ => unreachable!(),
        }
        assert_ne!(sudo_credential_id(&edited), original, "{field}");
    }
    assert_ne!(original, format!("sudo:{}", host.id), "unscoped legacy secrets are never implicitly trusted");
}

#[test]
fn encrypted_key_challenge_has_a_stable_frontend_error_kind() {
    let error = serde_json::to_value(AppError::KeyPassphraseRequired).unwrap();
    assert_eq!(error["kind"], "keyPassphraseRequired");
    assert_eq!(error["message"], "需要私钥口令");
    let error = serde_json::to_value(AppError::SudoAuthenticationFailed("请重新输入".into())).unwrap();
    assert_eq!(error["kind"], "sudoRequired");
    assert_eq!(error["message"], "sudo 验证失败：请重新输入");
}
