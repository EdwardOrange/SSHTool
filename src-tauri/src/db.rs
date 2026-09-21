use crate::{
    error::{AppError, AppResult},
    models::*,
};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use std::{path::Path, sync::Arc};

type CommandSink = Arc<dyn Fn(CommandRecord) + Send + Sync>;
pub struct Database(pub Mutex<Connection>, Mutex<Option<CommandSink>>);

impl Database {
    pub fn open(path: &Path) -> AppResult<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(path)?;
        connection.execute_batch(r#"
            PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, data TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS command_log (id TEXT PRIMARY KEY, host_id TEXT, timestamp TEXT NOT NULL, data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_command_host_time ON command_log(host_id, timestamp DESC);
            CREATE TABLE IF NOT EXISTS metrics (host_id TEXT NOT NULL, timestamp TEXT NOT NULL, resolution INTEGER NOT NULL DEFAULT 2, data TEXT NOT NULL, PRIMARY KEY(host_id,timestamp,resolution));
            CREATE INDEX IF NOT EXISTS idx_metrics_query ON metrics(host_id,resolution,timestamp);
            CREATE TABLE IF NOT EXISTS forward_profiles (id TEXT PRIMARY KEY, host_id TEXT NOT NULL, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS known_hosts (host_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, endpoint TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        "#)?;
        // Legacy databases did not scope trust to the actual network endpoint.
        // Keep those records for migration, but do not use them until the
        // endpoint has been explicitly confirmed again.
        let _ = connection.execute("ALTER TABLE known_hosts ADD COLUMN endpoint TEXT NOT NULL DEFAULT ''", []);
        Ok(Self(Mutex::new(connection), Mutex::new(None)))
    }

    pub fn hosts_list(&self) -> AppResult<Vec<HostProfile>> {
        let connection = self.0.lock();
        // Avoid SQLite JSON ordering so one malformed legacy record cannot block startup.
        let mut statement = connection.prepare("SELECT data FROM hosts")?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let mut hosts = Vec::new();
        for row in rows {
            let data = row?;
            match serde_json::from_str::<HostProfile>(&data) {
                Ok(mut host) => {
                    host.status = "disconnected".into();
                    hosts.push(host);
                }
                Err(error) => eprintln!("Ignoring invalid host record during startup: {error}"),
            }
        }
        hosts.sort_by(|a, b| {
            b.favorite
                .cmp(&a.favorite)
                .then_with(|| a.group_name.cmp(&b.group_name))
                .then_with(|| a.name.cmp(&b.name))
        });
        Ok(hosts)
    }
    pub fn host_get(&self, id: &str) -> AppResult<HostProfile> {
        let data: Option<String> = self
            .0
            .lock()
            .query_row("SELECT data FROM hosts WHERE id=?1", [id], |r| r.get(0))
            .optional()?;
        data.ok_or_else(|| AppError::NotFound(format!("服务器 {id}")))
            .and_then(|s| serde_json::from_str(&s).map_err(|e| AppError::Other(e.to_string())))
    }
    pub fn host_upsert(&self, host: &HostProfile) -> AppResult<()> {
        let data = serde_json::to_string(host).map_err(|e| AppError::Other(e.to_string()))?;
        self.0.lock().execute("INSERT INTO hosts(id,data,created_at,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO UPDATE SET data=excluded.data,updated_at=excluded.updated_at", params![host.id,data,host.created_at,host.updated_at])?;
        Ok(())
    }
    pub fn host_record_connection(&self, id: &str, connected: bool) -> AppResult<()> {
        let connection = self.0.lock();
        let data: String = connection.query_row("SELECT data FROM hosts WHERE id=?1", [id], |row| row.get(0))?;
        let mut host: HostProfile = serde_json::from_str(&data).map_err(|error| AppError::Other(error.to_string()))?;
        host.status = if connected { "connected".into() } else { "error".into() };
        host.updated_at = chrono::Utc::now().to_rfc3339();
        if connected { host.last_connected_at = Some(host.updated_at.clone()); }
        let data = serde_json::to_string(&host).map_err(|error| AppError::Other(error.to_string()))?;
        connection.execute("UPDATE hosts SET data=?2,updated_at=?3 WHERE id=?1", params![id, data, host.updated_at])?;
        Ok(())
    }
    pub fn hosts_import(&self, hosts: &[HostProfile]) -> AppResult<Vec<HostProfile>> {
        let mut connection = self.0.lock();
        let transaction = connection.transaction()?;
        let mut inserted = Vec::new();
        for host in hosts {
            let data = serde_json::to_string(host).map_err(|e| AppError::Other(e.to_string()))?;
            // Resolve duplicates inside the transaction: another import or save
            // may have inserted the host since the import file was read.
            if transaction.execute("INSERT INTO hosts(id,data,created_at,updated_at) VALUES(?1,?2,?3,?4) ON CONFLICT(id) DO NOTHING", params![host.id, data, host.created_at, host.updated_at])? != 0 {
                inserted.push(host.clone());
            }
        }
        transaction.commit()?;
        Ok(inserted)
    }
    pub fn host_delete(&self, id: &str) -> AppResult<()> {
        let mut connection = self.0.lock();
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM forward_profiles WHERE host_id=?1", [id])?;
        transaction.execute("DELETE FROM known_hosts WHERE host_id=?1", [id])?;
        transaction.execute("DELETE FROM metrics WHERE host_id=?1", [id])?;
        transaction.execute("DELETE FROM hosts WHERE id=?1", [id])?;
        transaction.commit()?;
        Ok(())
    }
    pub fn command_add(&self, record: &CommandRecord) -> AppResult<()> {
        // All producers share this boundary, including connection and SFTP
        // errors that may echo remote text. Persist and broadcast the same
        // redacted record; individual callers must not have to remember it.
        let mut record = record.clone();
        record.command = crate::security::redact(&record.command);
        record.stdout = crate::security::redact(&record.stdout);
        record.stderr = crate::security::redact(&record.stderr);
        let data = serde_json::to_string(&record).map_err(|e| AppError::Other(e.to_string()))?;
        let connection = self.0.lock();
        connection.execute(
            "INSERT OR REPLACE INTO command_log(id,host_id,timestamp,data) VALUES(?1,?2,?3,?4)",
            params![record.id, record.host_id, record.timestamp, data],
        )?;
        let retention_days: i64 = connection.query_row("SELECT COALESCE(json_extract(value, '$.commandRetentionDays'), 7) FROM settings WHERE key='app'", [], |row| row.get(0)).unwrap_or(7).clamp(1, 3650);
        connection.execute("DELETE FROM command_log WHERE julianday(timestamp) < julianday('now', '-' || ?1 || ' days')", [retention_days])?;
        let retention_mb: i64 = connection.query_row("SELECT COALESCE(json_extract(value, '$.commandRetentionMb'), 100) FROM settings WHERE key='app'", [], |row| row.get(0)).unwrap_or(100).clamp(10, 10_000);
        while connection.query_row::<i64, _, _>("SELECT COALESCE(SUM(length(CAST(data AS BLOB))),0) FROM command_log", [], |row| row.get(0)).unwrap_or(0) > retention_mb * 1024 * 1024 {
            connection.execute("DELETE FROM command_log WHERE id=(SELECT id FROM command_log ORDER BY timestamp ASC LIMIT 1)", [])?;
        }
        // Every producer, including background monitor/firewall tasks, reaches
        // the same live stream. Do not call consumers while holding SQLite's lock.
        drop(connection);
        let sink = self.1.lock().clone();
        if let Some(sink) = sink { sink(record.clone()); }
        Ok(())
    }
    pub fn set_command_sink(&self, sink: CommandSink) {
        *self.1.lock() = Some(sink);
    }
    pub fn commands(&self, host_id: Option<&str>) -> AppResult<Vec<CommandRecord>> {
        let connection = self.0.lock();
        let sql = "SELECT data FROM command_log WHERE (?1 IS NULL OR host_id=?1) ORDER BY timestamp DESC LIMIT 2000";
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map(params![host_id], |row| row.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(serde_json::from_str(&row?).map_err(|e| AppError::Other(e.to_string()))?);
        }
        result.reverse();
        Ok(result)
    }
    pub fn command_clear(&self) -> AppResult<Vec<String>> {
        let mut connection = self.0.lock();
        let transaction = connection.transaction()?;
        let ids = {
            let mut statement = transaction.prepare("SELECT id FROM command_log")?;
            statement.query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        transaction.execute("DELETE FROM command_log", [])?;
        transaction.commit()?;
        // The UI removes only these IDs. Events inserted after the clear can
        // arrive before this command's IPC response and must remain visible.
        Ok(ids)
    }
    pub fn command_cleanup_legacy_terminal_bootstrap(&self) -> AppResult<usize> {
        let connection = self.0.lock();
        let mut statement = connection.prepare("SELECT id,data FROM command_log")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?;
        let mut ids = Vec::new();
        for row in rows {
            let (id, data) = row?;
            let Ok(record) = serde_json::from_str::<CommandRecord>(&data) else { continue };
            if record.source == "terminal"
                && record.operation_kind.as_deref() == Some("terminal.shell")
                && record.command.trim_start().starts_with("__sshops_notice=''; if command -v base64")
                && record.command.contains("__sshops_emit")
                && record.command.contains("PROMPT_COMMAND")
            {
                ids.push(id);
            }
        }
        drop(statement);
        let mut removed = 0;
        for id in ids {
            removed += connection.execute("DELETE FROM command_log WHERE id=?1", [id])?;
        }
        Ok(removed)
    }
    pub fn setting_get(&self, key: &str) -> AppResult<Option<String>> {
        Ok(self.0.lock().query_row("SELECT value FROM settings WHERE key=?1", [key], |r| r.get(0)).optional()?)
    }
    pub fn setting_set(&self, key: &str, value: &str) -> AppResult<()> {
        self.0.lock().execute("INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value])?;
        Ok(())
    }
    pub fn setting_set_if_unchanged(&self, key: &str, previous: Option<&str>, value: &str) -> AppResult<bool> {
        let connection = self.0.lock();
        let changed = if let Some(previous) = previous {
            connection.execute("UPDATE settings SET value=?3 WHERE key=?1 AND value=?2", params![key, previous, value])?
        } else {
            connection.execute("INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO NOTHING", params![key, value])?
        };
        Ok(changed != 0)
    }
    pub fn metric_add(&self, metric: &MetricSnapshot, resolution: u32) -> AppResult<()> {
        if !matches!(resolution, 2 | 5 | 10 | 30) {
            return Err(AppError::Validation("监控采样间隔无效".into()));
        }
        let sampled_at = chrono::DateTime::parse_from_rfc3339(&metric.timestamp)
            .map_err(|_| AppError::Validation("监控时间戳无效".into()))?;
        let data = serde_json::to_string(metric).map_err(|e| AppError::Other(e.to_string()))?;
        let mut c = self.0.lock();
        let transaction = c.transaction()?;
        transaction.execute(
            "INSERT OR REPLACE INTO metrics(host_id,timestamp,resolution,data) VALUES(?1,?2,?3,?4)",
            params![metric.host_id, metric.timestamp, resolution, data],
        )?;
        // Retain the latest observed sample in each minute/five-minute bucket.
        // Without these rows, the 24-hour and seven-day history queries lose
        // all history as soon as raw samples reach their one-hour expiry.
        // Keep the real observation timestamp in data, and use the bucket
        // start only as its stable database key. Late writes cannot replace a
        // more recent observation in the same bucket.
        for bucket in [60i64, 300] {
            let bucket_start = chrono::DateTime::from_timestamp(sampled_at.timestamp().div_euclid(bucket) * bucket, 0)
                .ok_or_else(|| AppError::Validation("监控时间戳超出范围".into()))?
                .to_rfc3339();
            transaction.execute(
                "INSERT INTO metrics(host_id,timestamp,resolution,data) VALUES(?1,?2,?3,?4) ON CONFLICT(host_id,timestamp,resolution) DO UPDATE SET data=excluded.data WHERE julianday(json_extract(excluded.data,'$.timestamp')) > julianday(json_extract(metrics.data,'$.timestamp'))",
                params![metric.host_id, bucket_start, bucket, data],
            )?;
        }
        transaction.execute("DELETE FROM metrics WHERE (resolution IN (2,5,10,30) AND julianday(timestamp)<julianday('now','-1 hour')) OR (resolution=60 AND julianday(timestamp)<julianday('now','-1 day')) OR (resolution=300 AND julianday(timestamp)<julianday('now','-7 days'))",[])?;
        transaction.commit()?;
        Ok(())
    }
    pub fn metrics(&self, host_id: &str, since: &str) -> AppResult<Vec<MetricSnapshot>> {
        let c = self.0.lock();
        let mut s = c.prepare(
            "SELECT DISTINCT data FROM metrics WHERE host_id=?1 AND julianday(json_extract(data,'$.timestamp'))>=julianday(?2) AND (
                (resolution IN (2,5,10,30) AND julianday(json_extract(data,'$.timestamp'))>=julianday('now','-1 hour')) OR
                (resolution=60 AND julianday(json_extract(data,'$.timestamp'))<julianday('now','-1 hour') AND julianday(json_extract(data,'$.timestamp'))>=julianday('now','-1 day')) OR
                (resolution=300 AND julianday(json_extract(data,'$.timestamp'))<julianday('now','-1 day') AND julianday(json_extract(data,'$.timestamp'))>=julianday('now','-7 days'))
            ) ORDER BY timestamp",
        )?;
        let rows = s.query_map(params![host_id, since], |r| r.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(serde_json::from_str(&row?).map_err(|e| AppError::Other(e.to_string()))?);
        }
        Ok(result)
    }
    pub fn forward_list(&self, host_id: &str) -> AppResult<Vec<ForwardingProfile>> {
        let c = self.0.lock();
        let mut s = c.prepare("SELECT data FROM forward_profiles WHERE (?1='' OR host_id=?1)")?;
        let rows = s.query_map([host_id], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?).map_err(|e| AppError::Other(e.to_string()))?);
        }
        Ok(out)
    }
    pub fn forward_upsert(&self, p: &ForwardingProfile) -> AppResult<()> {
        let data = serde_json::to_string(p).map_err(|e| AppError::Other(e.to_string()))?;
        self.0.lock().execute("INSERT INTO forward_profiles(id,host_id,data) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET data=excluded.data,host_id=excluded.host_id",params![p.id,p.host_id,data])?;
        Ok(())
    }
    pub fn forward_delete(&self, id: &str) -> AppResult<()> {
        self.0
            .lock()
            .execute("DELETE FROM forward_profiles WHERE id=?1", [id])?;
        Ok(())
    }
    pub fn known_fingerprint(&self, host_id: &str, endpoint: &str) -> AppResult<Option<String>> {
        Ok(self
            .0
            .lock()
            .query_row(
                "SELECT fingerprint FROM known_hosts WHERE host_id=?1 AND endpoint=?2",
                params![host_id, endpoint],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn set_fingerprint(&self, host_id: &str, endpoint: &str, fingerprint: &str) -> AppResult<()> {
        self.0.lock().execute("INSERT INTO known_hosts(host_id,fingerprint,endpoint,updated_at) VALUES(?1,?2,?3,datetime('now')) ON CONFLICT(host_id) DO UPDATE SET fingerprint=excluded.fingerprint,endpoint=excluded.endpoint,updated_at=excluded.updated_at",params![host_id,fingerprint,endpoint])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_migration_cannot_overwrite_a_save_after_its_read() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        database.setting_set("app", "legacy").unwrap();
        let read_by_migration = database.setting_get("app").unwrap();
        database.setting_set("app", "new user preferences").unwrap();
        assert!(!database.setting_set_if_unchanged("app", read_by_migration.as_deref(), "migrated legacy").unwrap());
        assert_eq!(database.setting_get("app").unwrap().as_deref(), Some("new user preferences"));
        assert!(database.setting_set_if_unchanged("app", Some("new user preferences"), "normalized preferences").unwrap());
        assert_eq!(database.setting_get("app").unwrap().as_deref(), Some("normalized preferences"));
    }

    #[test]
    fn first_settings_read_cannot_replace_concurrently_created_preferences() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        assert_eq!(database.setting_get("app").unwrap(), None);
        database.setting_set("app", "saved before initialization").unwrap();
        assert!(!database.setting_set_if_unchanged("app", None, "defaults").unwrap());
        assert_eq!(database.setting_get("app").unwrap().as_deref(), Some("saved before initialization"));
        assert!(database.setting_set_if_unchanged("another-setting", None, "defaults").unwrap());
    }

    fn metric_at(timestamp: chrono::DateTime<chrono::Utc>, cpu_percent: f64) -> MetricSnapshot {
        MetricSnapshot {
            host_id: "metric-host".into(), timestamp: timestamp.to_rfc3339(), cpu_percent,
            memory_percent: 25.0, disk_percent: 50.0, load1: 0.5, rx_bytes_per_sec: 100.0,
            tx_bytes_per_sec: 50.0, connection_count: 1, memory_used_bytes: 256,
            memory_total_bytes: 1024, disk_used_bytes: 512, disk_total_bytes: 1024,
            uptime_seconds: 500, connections: Vec::new(), top_processes: Vec::new(),
        }
    }

    #[test]
    fn metric_history_retains_coarser_samples_for_a_day_and_a_week_without_duplicates() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        let now = chrono::Utc::now();
        for (age, value) in [(chrono::Duration::days(8), 80.0), (chrono::Duration::days(2), 20.0),
            (chrono::Duration::hours(2), 2.0), (chrono::Duration::minutes(2), 1.0)] {
            database.metric_add(&metric_at(now - age, value), 2).unwrap();
        }
        let since = |age: chrono::Duration| (now - age).to_rfc3339();
        let recent = database.metrics("metric-host", &since(chrono::Duration::hours(1))).unwrap();
        assert_eq!(recent.iter().map(|sample| sample.cpu_percent).collect::<Vec<_>>(), [1.0]);
        let day = database.metrics("metric-host", &since(chrono::Duration::days(1))).unwrap();
        assert_eq!(day.iter().map(|sample| sample.cpu_percent).collect::<Vec<_>>(), [2.0, 1.0]);
        let week = database.metrics("metric-host", &since(chrono::Duration::days(7))).unwrap();
        assert_eq!(week.iter().map(|sample| sample.cpu_percent).collect::<Vec<_>>(), [20.0, 2.0, 1.0]);
        let resolutions = database.0.lock().prepare("SELECT resolution FROM metrics ORDER BY resolution").unwrap()
            .query_map([], |row| row.get::<_, u32>(0)).unwrap().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(resolutions, [2, 60, 60, 300, 300, 300]);
    }

    #[test]
    fn metric_buckets_keep_the_latest_observation_and_validate_before_writing() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        let seconds = (chrono::Utc::now() - chrono::Duration::hours(2)).timestamp();
        let bucket = chrono::DateTime::from_timestamp(seconds.div_euclid(300) * 300, 0).unwrap();
        let latest = metric_at(bucket + chrono::Duration::seconds(20), 80.0);
        database.metric_add(&latest, 5).unwrap();
        database.metric_add(&metric_at(bucket + chrono::Duration::seconds(10), 10.0), 5).unwrap();
        let samples = database.metrics("metric-host", &(bucket - chrono::Duration::seconds(1)).to_rfc3339()).unwrap();
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].cpu_percent, 80.0);
        assert_eq!(samples[0].timestamp, latest.timestamp);
        assert!(database.metric_add(&latest, 3).is_err());
        let mut invalid = latest;
        invalid.timestamp = "invalid".into();
        assert!(database.metric_add(&invalid, 2).is_err());
        assert_eq!(database.0.lock().query_row::<u32, _, _>("SELECT count(*) FROM metrics", [], |row| row.get(0)).unwrap(), 2);
    }

    fn terminal_record(id: &str, command: &str) -> CommandRecord {
        CommandRecord {
            id: id.into(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            host_id: Some("host-1".into()),
            host_name: Some("Test".into()),
            source: "terminal".into(),
            command: command.into(),
            stdout: String::new(),
            stderr: String::new(),
            exit_code: Some(0),
            duration_ms: 0,
            status: "success".into(),
            repeat_count: 1,
            equivalent: None,
            operation_kind: Some("terminal.shell".into()),
        }
    }

    #[test]
    fn cleanup_removes_only_the_legacy_internal_bootstrap() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        database.command_add(&terminal_record(
            "legacy",
            "__sshops_notice=''; if command -v base64 >/dev/null; then __sshops_emit(){ :; }; PROMPT_COMMAND=__sshops_prompt; fi",
        )).unwrap();
        database.command_add(&terminal_record("normal", "printf '__sshops_notice' ")).unwrap();

        assert_eq!(database.command_cleanup_legacy_terminal_bootstrap().unwrap(), 1);
        let commands = database.commands(None).unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].id, "normal");
    }

    #[test]
    fn all_audit_sources_notify_after_persistence_without_holding_the_database_lock() {
        let directory = tempfile::tempdir().unwrap();
        let database = Arc::new(Database::open(&directory.path().join("test.db")).unwrap());
        let weak_database = Arc::downgrade(&database);
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let observed = emitted.clone();
        database.set_command_sink(Arc::new(move |record| {
            let database = weak_database.upgrade().unwrap();
            assert!(database.0.try_lock().is_some(), "callbacks must run after releasing SQLite");
            assert!(database.commands(None).unwrap().iter().any(|saved| saved.id == record.id));
            observed.lock().push(record.source);
        }));
        for source in ["monitor", "firewall", "terminal"] {
            let mut record = terminal_record(source, "test-only");
            record.source = source.into();
            database.command_add(&record).unwrap();
        }
        assert_eq!(&*emitted.lock(), &["monitor", "firewall", "terminal"]);
        database.0.lock().execute("DROP TABLE command_log", []).unwrap();
        assert!(database.command_add(&terminal_record("failed", "not persisted")).is_err());
        assert_eq!(emitted.lock().len(), 3, "failed writes must not appear as saved records");
    }

    #[test]
    fn every_audit_source_is_redacted_before_persistence_and_broadcast() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        let emitted = Arc::new(Mutex::new(Vec::new()));
        let observed = emitted.clone();
        database.set_command_sink(Arc::new(move |record| observed.lock().push(record)));
        let mut record = terminal_record("sftp-error", "copy --password command-secret");
        record.source = "sftp".into();
        record.stdout = r#"{"token":"output-secret"}"#.into();
        record.stderr = "password=error-secret".into();
        database.command_add(&record).unwrap();
        let persisted: String = database.0.lock().query_row("SELECT data FROM command_log", [], |row| row.get(0)).unwrap();
        let broadcast = serde_json::to_string(&emitted.lock()[0]).unwrap();
        for secret in ["command-secret", "output-secret", "error-secret"] {
            assert!(!persisted.contains(secret));
            assert!(!broadcast.contains(secret));
        }
        assert_eq!(persisted, broadcast);
        assert_eq!(record.command, "copy --password command-secret", "callers keep their original value");
    }

    #[test]
    fn command_clear_reports_only_deleted_records_and_preserves_later_inserts() {
        let directory = tempfile::tempdir().unwrap();
        let database = Database::open(&directory.path().join("test.db")).unwrap();
        database.command_add(&terminal_record("before", "first")).unwrap();
        let deleted = database.command_clear().unwrap();
        database.command_add(&terminal_record("after", "second")).unwrap();
        assert_eq!(deleted, ["before"]);
        assert_eq!(database.commands(None).unwrap()[0].id, "after");
        assert_eq!(database.command_clear().unwrap(), ["after"]);
        assert!(database.command_clear().unwrap().is_empty());
    }
}
