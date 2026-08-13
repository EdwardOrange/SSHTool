use crate::{
    error::{AppError, AppResult},
    models::*,
};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

pub struct Database(pub Mutex<Connection>);

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
            CREATE TABLE IF NOT EXISTS known_hosts (host_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        "#)?;
        Ok(Self(Mutex::new(connection)))
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
    pub fn host_delete(&self, id: &str) -> AppResult<()> {
        self.0
            .lock()
            .execute("DELETE FROM hosts WHERE id=?1", [id])?;
        Ok(())
    }
    pub fn command_add(&self, record: &CommandRecord) -> AppResult<()> {
        let data = serde_json::to_string(record).map_err(|e| AppError::Other(e.to_string()))?;
        let connection = self.0.lock();
        connection.execute(
            "INSERT OR REPLACE INTO command_log(id,host_id,timestamp,data) VALUES(?1,?2,?3,?4)",
            params![record.id, record.host_id, record.timestamp, data],
        )?;
        let retention_days: i64 = connection.query_row("SELECT COALESCE(json_extract(value, '$.commandRetentionDays'), 7) FROM settings WHERE key='app'", [], |row| row.get(0)).unwrap_or(7);
        connection.execute("DELETE FROM command_log WHERE timestamp < datetime('now', '-' || ?1 || ' days')", [retention_days])?;
        let retention_mb: i64 = connection.query_row("SELECT COALESCE(json_extract(value, '$.commandRetentionMb'), 100) FROM settings WHERE key='app'", [], |row| row.get(0)).unwrap_or(100);
        while connection.query_row::<i64, _, _>("SELECT COALESCE(SUM(length(data)),0) FROM command_log", [], |row| row.get(0)).unwrap_or(0) > retention_mb * 1024 * 1024 {
            connection.execute("DELETE FROM command_log WHERE id=(SELECT id FROM command_log ORDER BY timestamp ASC LIMIT 1)", [])?;
        }
        Ok(())
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
    pub fn command_clear(&self) -> AppResult<()> {
        self.0.lock().execute("DELETE FROM command_log", [])?;
        Ok(())
    }
    pub fn setting_get(&self, key: &str) -> AppResult<Option<String>> {
        Ok(self.0.lock().query_row("SELECT value FROM settings WHERE key=?1", [key], |r| r.get(0)).optional()?)
    }
    pub fn setting_set(&self, key: &str, value: &str) -> AppResult<()> {
        self.0.lock().execute("INSERT INTO settings(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key, value])?;
        Ok(())
    }
    pub fn metric_add(&self, metric: &MetricSnapshot, resolution: u32) -> AppResult<()> {
        let data = serde_json::to_string(metric).map_err(|e| AppError::Other(e.to_string()))?;
        let c = self.0.lock();
        c.execute(
            "INSERT OR REPLACE INTO metrics(host_id,timestamp,resolution,data) VALUES(?1,?2,?3,?4)",
            params![metric.host_id, metric.timestamp, resolution, data],
        )?;
        c.execute("DELETE FROM metrics WHERE (resolution=2 AND timestamp<datetime('now','-1 hour')) OR (resolution=60 AND timestamp<datetime('now','-1 day')) OR (resolution=300 AND timestamp<datetime('now','-7 days'))",[])?;
        Ok(())
    }
    pub fn metrics(&self, host_id: &str, since: &str) -> AppResult<Vec<MetricSnapshot>> {
        let c = self.0.lock();
        let mut s = c.prepare(
            "SELECT data FROM metrics WHERE host_id=?1 AND timestamp>=?2 ORDER BY timestamp",
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
    pub fn known_fingerprint(&self, host_id: &str) -> AppResult<Option<String>> {
        Ok(self
            .0
            .lock()
            .query_row(
                "SELECT fingerprint FROM known_hosts WHERE host_id=?1",
                [host_id],
                |r| r.get(0),
            )
            .optional()?)
    }
    pub fn set_fingerprint(&self, host_id: &str, fingerprint: &str) -> AppResult<()> {
        self.0.lock().execute("INSERT INTO known_hosts(host_id,fingerprint,updated_at) VALUES(?1,?2,datetime('now')) ON CONFLICT(host_id) DO UPDATE SET fingerprint=excluded.fingerprint,updated_at=excluded.updated_at",params![host_id,fingerprint])?;
        Ok(())
    }
}
