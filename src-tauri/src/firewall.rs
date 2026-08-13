use crate::{
    db::Database,
    error::{AppError, AppResult},
    models::*,
    security::{redact, shell_quote},
    ssh::SshManager,
};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Clone)]
struct StoredPlan {
    plan: FirewallPlan,
    change: FirewallChange,
    backend: String,
    applied: bool,
    rollback_unit: Option<String>,
}
pub struct FirewallManager {
    plans: RwLock<HashMap<String, StoredPlan>>,
}
impl Default for FirewallManager {
    fn default() -> Self {
        Self {
            plans: RwLock::new(HashMap::new()),
        }
    }
}

impl FirewallManager {
    pub fn plan_host(&self, plan_id: &str) -> Option<String> {
        self.plans.read().get(plan_id).map(|stored| stored.plan.host_id.clone())
    }

    pub async fn read(&self, ssh: &SshManager, host_id: &str) -> AppResult<FirewallState> {
        let detect = "LANG=C sh -c 'if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q Status; then echo ufw; sudo -n ufw status verbose 2>/dev/null || ufw status verbose; elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then echo firewalld; sudo -n firewall-cmd --list-all --zone=$(firewall-cmd --get-default-zone); elif command -v nft >/dev/null; then echo nftables; sudo -n nft list ruleset 2>/dev/null || nft list ruleset; else echo unsupported; fi; echo __ROLLBACK__; if command -v systemd-run >/dev/null || command -v at >/dev/null; then echo yes; else echo no; fi'";
        let out = ssh.exec(host_id, detect).await?;
        let before = out.stdout.split("__ROLLBACK__").next().unwrap_or("");
        let rollback = out
            .stdout
            .split("__ROLLBACK__")
            .nth(1)
            .unwrap_or("")
            .contains("yes");
        let mut lines = before.lines();
        let backend = lines.next().unwrap_or("unsupported").trim().to_string();
        let raw = lines.collect::<Vec<_>>().join("\n");
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let (enabled, default_in, default_out, rules) = match backend.as_str() {
            "ufw" => parse_ufw(&raw),
            "firewalld" => parse_firewalld(&raw),
            "nftables" => (
                !raw.trim().is_empty(),
                "unknown".into(),
                "unknown".into(),
                parse_nft(&raw),
            ),
            _ => (false, "unknown".into(), "unknown".into(), Vec::new()),
        };
        Ok(FirewallState {
            host_id: host_id.into(),
            backend,
            enabled,
            default_inbound: default_in,
            default_outbound: default_out,
            state_hash: hash,
            rollback_available: rollback,
            rules,
        })
    }
    pub async fn plan(
        &self,
        ssh: &SshManager,
        host_id: &str,
        change: FirewallChange,
    ) -> AppResult<FirewallPlan> {
        validate_rule(&change.rule)?;
        let mut rule = change.rule.clone();
        if rule.id.is_none() {
            rule.id = Some(Uuid::new_v4().to_string());
        }
        let change = FirewallChange {
            operation: change.operation,
            rule,
        };
        let state = self.read(ssh, host_id).await?;
        if !state.rollback_available {
            return Err(AppError::Permission(
                "服务器没有 systemd-run、at 或防火墙原生回滚机制".into(),
            ));
        }
        if state.backend == "unsupported" {
            return Err(AppError::Validation("没有检测到受支持的防火墙".into()));
        }
        let command = command_for(&state.backend, &change)?;
        let id = Uuid::new_v4().to_string();
        let risk = if change.rule.ports.contains("22") || change.rule.action != "allow" {
            "high"
        } else {
            "medium"
        };
        let plan = FirewallPlan {
            id: id.clone(),
            host_id: host_id.into(),
            state_hash: state.state_hash,
            summary: format!(
                "{} {} {} {}",
                if change.operation == "add" {
                    "添加"
                } else {
                    "修改"
                },
                change.rule.action.to_uppercase(),
                change.rule.protocol.to_uppercase(),
                change.rule.ports
            ),
            commands: vec![command],
            warnings: vec![
                "将保存当前规则快照，并建立 60 秒服务器端自动回滚。".into(),
                "应用后会验证 SSH 通道；只有点击“保留更改”才会取消回滚。".into(),
            ],
            risk: quality(risk),
            rollback_available: true,
            expires_at: (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        };
        self.plans.write().insert(
            id,
            StoredPlan {
                plan: plan.clone(),
                change,
                backend: state.backend,
                applied: false,
                rollback_unit: None,
            },
        );
        Ok(plan)
    }
    pub async fn apply(
        &self,
        ssh: &SshManager,
        db: &Database,
        plan_id: &str,
        sudo_password: Option<&str>,
    ) -> AppResult<serde_json::Value> {
        let stored = self
            .plans
            .read()
            .get(plan_id)
            .cloned()
            .ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
        if chrono::DateTime::parse_from_rfc3339(&stored.plan.expires_at)
            .map(|d| d.with_timezone(&chrono::Utc) < chrono::Utc::now())
            .unwrap_or(true)
        {
            return Err(AppError::StalePlan);
        }
        let current = self.read(ssh, &stored.plan.host_id).await?;
        if current.state_hash != stored.plan.state_hash {
            return Err(AppError::StalePlan);
        }
        let unit = format!("sshops-rollback-{}", &plan_id[..8]);
        let snapshot = format!("/tmp/{unit}.snapshot");
        let command = &stored.plan.commands[0];
        let rollback = match stored.backend.as_str() {
            "ufw" => format!(
                "sudo -n sh -c 'tar -C / -czf {snapshot} etc/ufw' && sudo -n systemd-run --unit={unit} --on-active=60s /bin/sh -c \"tar -C / -xzf {snapshot} && ufw reload\""
            ),
            "firewalld" => format!(
                "sudo -n firewall-cmd --runtime-to-permanent && sudo -n systemd-run --unit={unit} --on-active=60s /bin/sh -c \"firewall-cmd --reload\""
            ),
            "nftables" => format!(
                "sudo -n sh -c 'nft list ruleset > {snapshot}' && sudo -n systemd-run --unit={unit} --on-active=60s /bin/sh -c \"nft -f {snapshot}\""
            ),
            _ => return Err(AppError::Validation("不支持的防火墙".into())),
        };
        let full = format!("{rollback} && {command}");
        let elevated = if sudo_password.is_some() { full.replace("sudo -n", "sudo -S -p ''") } else { full.clone() };
        let output = ssh.exec_with_input(&stored.plan.host_id, &elevated, sudo_password).await?;
        log(db, ssh, &stored.plan.host_id, "firewall", &full, &output);
        if output.exit_code != 0 {
            if sudo_password.is_none() && (output.stderr.to_lowercase().contains("sudo") || output.stderr.to_lowercase().contains("password")) {
                return Err(AppError::SudoRequired);
            }
            return Err(AppError::Permission(format!(
                "防火墙命令失败：{}",
                output.stderr
            )));
        }
        ssh.exec(&stored.plan.host_id, "true").await?;
        if let Some(p) = self.plans.write().get_mut(plan_id) {
            p.applied = true;
            p.rollback_unit = Some(unit)
        }
        let deadline = (chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339();
        Ok(serde_json::json!({"rollbackDeadline":deadline}))
    }
    pub async fn commit(&self, ssh: &SshManager, plan_id: &str) -> AppResult<()> {
        let stored = self
            .plans
            .write()
            .remove(plan_id)
            .ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
        if !stored.applied {
            return Err(AppError::Validation("计划尚未执行".into()));
        }
        if let Some(unit) = stored.rollback_unit {
            let cmd = format!(
                "sudo -n systemctl stop {unit}.timer {unit}.service 2>/dev/null || true; sudo -n systemctl reset-failed {unit}.service 2>/dev/null || true"
            );
            let _ = ssh.exec(&stored.plan.host_id, &cmd).await;
        }
        Ok(())
    }
    pub async fn rollback(&self, ssh: &SshManager, plan_id: &str) -> AppResult<()> {
        let stored = self
            .plans
            .write()
            .remove(plan_id)
            .ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
        if let Some(unit) = stored.rollback_unit {
            let cmd = format!("sudo -n systemctl start {unit}.service");
            let out = ssh.exec(&stored.plan.host_id, &cmd).await?;
            if out.exit_code != 0 {
                return Err(AppError::Other(out.stderr));
            }
        }
        Ok(())
    }
}
fn quality(s: &str) -> String {
    s.into()
}
fn validate_rule(r: &FirewallRuleInput) -> AppResult<()> {
    if !["tcp", "udp", "icmp", "any"].contains(&r.protocol.as_str()) {
        return Err(AppError::Validation("协议无效".into()));
    }
    if !["allow", "deny", "reject"].contains(&r.action.as_str()) {
        return Err(AppError::Validation("动作无效".into()));
    }
    if r.ports.len() > 64
        || !r
            .ports
            .chars()
            .all(|c| c.is_ascii_digit() || ",:-".contains(c))
    {
        return Err(AppError::Validation("端口格式无效".into()));
    }
    if r.source.len() > 128
        || !r
            .source
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".:/-".contains(c))
    {
        return Err(AppError::Validation("来源地址格式无效".into()));
    }
    Ok(())
}
fn command_for(backend: &str, c: &FirewallChange) -> AppResult<String> {
    let r = &c.rule;
    let comment = shell_quote(&r.comment)?;
    let source = if r.source == "any" { "any" } else { &r.source };
    let port = if r.ports.is_empty() { "any" } else { &r.ports };
    let operation = if c.operation == "add" { r.action.as_str() } else { "delete" };
    Ok(match backend {
        "ufw" => {
            let proto = if r.protocol == "any" { String::new() } else { format!(" proto {}", r.protocol) };
            let from = if source == "any" { String::new() } else { format!(" from {}", source) };
            let port_clause = if port == "any" { String::new() } else { format!(" to any port {}", port) };
            format!("ufw {}{}{}{} comment {}", operation, proto, from, port_clause, comment)
        }
        "firewalld" => {
            let source_clause = if source == "any" { String::new() } else { format!(" source address=\"{}\"", source) };
            let port_clause = if port == "any" { String::new() } else { format!(" port port=\"{}\" protocol=\"{}\"", port, r.protocol) };
            let verb = if r.action == "allow" { "accept" } else { "drop" };
            format!("firewall-cmd --zone={} --add-rich-rule={}", r.zone.as_deref().unwrap_or("public"), shell_quote(&format!("rule family=\"{}\"{}{} {}", if r.family == "ipv6" { "ipv6" } else { "ipv4" }, source_clause, port_clause, verb))?)
        }
        "nftables" => {
            let family = if r.family == "ipv6" { "ip6" } else { "ip" };
            let source_clause = if source == "any" { String::new() } else { format!(" saddr {}", source) };
            let port_clause = if port == "any" || r.protocol == "icmp" || r.protocol == "any" { String::new() } else { format!(" dport {}", port) };
            format!("nft add rule inet filter input {}{}{} {} comment {}", family, source_clause, port_clause, if r.action == "allow" { "accept" } else { "drop" }, comment)
        }
        _ => return Err(AppError::Validation("不支持的防火墙".into())),
    })
}
fn parse_ufw(raw: &str) -> (bool, String, String, Vec<UnifiedFirewallRule>) {
    let enabled = raw.contains("Status: active");
    let mut di = "deny".into();
    let mut dout = "allow".into();
    for l in raw.lines() {
        if l.starts_with("Default:") {
            let low = l.to_lowercase();
            if low.contains("allow (incoming)") {
                di = "allow".into()
            }
            if low.contains("deny (outgoing)") {
                dout = "deny".into()
            }
        }
    }
    let mut rules = Vec::new();
    for (i, l) in raw.lines().enumerate() {
        if !(l.contains("ALLOW") || l.contains("DENY") || l.contains("REJECT")) {
            continue;
        }
        let p: Vec<&str> = l.split_whitespace().collect();
        if p.len() < 3 {
            continue;
        }
        let action = if l.contains("ALLOW") {
            "allow"
        } else if l.contains("REJECT") {
            "reject"
        } else {
            "deny"
        };
        let proto = if p[0].contains("/udp") { "udp" } else { "tcp" };
        rules.push(UnifiedFirewallRule {
            id: format!("ufw-{i}"),
            backend_ref: None,
            direction: "in".into(),
            family: if l.contains("(v6)") {
                "ipv6".into()
            } else {
                "ipv4".into()
            },
            protocol: proto.into(),
            ports: p[0].split('/').next().unwrap_or("any").into(),
            source: p.last().unwrap_or(&"any").to_string(),
            destination: "any".into(),
            action: action.into(),
            enabled: true,
            comment: l.split('#').nth(1).unwrap_or("").trim().into(),
            zone: None,
            read_only: None,
        });
    }
    (enabled, di, dout, rules)
}
fn parse_firewalld(raw: &str) -> (bool, String, String, Vec<UnifiedFirewallRule>) {
    let mut rules = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(ports) = line.strip_prefix("ports:") {
            for (i, p) in ports.split_whitespace().enumerate() {
                let mut x = p.split('/');
                rules.push(UnifiedFirewallRule {
                    id: format!("fw-{i}"),
                    backend_ref: None,
                    direction: "in".into(),
                    family: "both".into(),
                    protocol: x.nth(1).unwrap_or("tcp").into(),
                    ports: p.split('/').next().unwrap_or("any").into(),
                    source: "any".into(),
                    destination: "any".into(),
                    action: "allow".into(),
                    enabled: true,
                    comment: "firewalld port".into(),
                    zone: Some("public".into()),
                    read_only: None,
                });
            }
        }
    }
    (true, "zone policy".into(), "allow".into(), rules)
}
fn parse_nft(raw: &str) -> Vec<UnifiedFirewallRule> {
    raw.lines()
        .filter(|l| l.trim().starts_with("chain "))
        .enumerate()
        .map(|(i, l)| UnifiedFirewallRule {
            id: format!("nft-{i}"),
            backend_ref: None,
            direction: "in".into(),
            family: "both".into(),
            protocol: "any".into(),
            ports: "any".into(),
            source: "any".into(),
            destination: "any".into(),
            action: "allow".into(),
            enabled: true,
            comment: l.trim().into(),
            zone: None,
            read_only: Some(true),
        })
        .collect()
}
fn log(
    db: &Database,
    ssh: &SshManager,
    host_id: &str,
    source: &str,
    command: &str,
    out: &ExecOutput,
) {
    let _ = db.command_add(&CommandRecord {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        host_id: Some(host_id.into()),
        host_name: ssh.profile(host_id).ok().map(|h| h.name),
        source: source.into(),
        command: redact(command),
        stdout: redact(&out.stdout),
        stderr: redact(&out.stderr),
        exit_code: Some(out.exit_code),
        duration_ms: out.duration_ms,
        status: if out.exit_code == 0 {
            "success".into()
        } else {
            "error".into()
        },
        repeat_count: 1,
        equivalent: None,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rule() -> FirewallRuleInput {
        FirewallRuleInput {
            id: Some("x".into()),
            backend_ref: None,
            direction: "in".into(),
            family: "both".into(),
            protocol: "tcp".into(),
            ports: "22".into(),
            source: "10.0.0.0/8".into(),
            destination: "any".into(),
            action: "allow".into(),
            enabled: true,
            comment: "ssh".into(),
            zone: None,
            read_only: None,
        }
    }
    #[test]
    fn rejects_injection() {
        let mut r = rule();
        r.ports = "22;reboot".into();
        assert!(validate_rule(&r).is_err())
    }
    #[test]
    fn maps_ufw() {
        let c = command_for(
            "ufw",
            &FirewallChange {
                operation: "add".into(),
                rule: rule(),
            },
        )
        .unwrap();
        assert!(c.contains("ufw allow"));
        assert!(!c.contains("ufw add"));
    }
}
