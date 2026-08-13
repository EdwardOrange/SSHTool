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
        let detect = "LANG=C sh -c 'if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q Status; then echo ufw; echo __UFW_VERBOSE__; sudo -n ufw status verbose 2>/dev/null || ufw status verbose; echo __UFW_NUMBERED__; sudo -n ufw status numbered 2>/dev/null || ufw status numbered; elif command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then echo firewalld; sudo -n firewall-cmd --list-all --zone=$(firewall-cmd --get-default-zone); elif command -v nft >/dev/null; then echo nftables; sudo -n nft list ruleset 2>/dev/null || nft list ruleset; else echo unsupported; fi; echo __ROLLBACK__; if command -v systemd-run >/dev/null || command -v at >/dev/null; then echo yes; else echo no; fi'";
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
        if change.operation != "add" && change.operation != "delete" { return Err(AppError::Validation("防火墙操作必须是 add 或 delete".into())); }
        validate_rule(&change.rule)?;
        let mut rule = change.rule.clone();
        if change.operation == "delete" && rule.id.is_none() { return Err(AppError::Validation("删除规则必须提供 id".into())); }
        if rule.id.is_none() {
            rule.id = Some(Uuid::new_v4().to_string());
        }
        let mut change = FirewallChange {
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
        if change.operation == "delete" {
            let current = state.rules.iter().find(|item| Some(&item.id) == change.rule.id.as_ref()).ok_or(AppError::StalePlan)?;
            if !delete_target_matches(&change.rule, current) {
                return Err(AppError::StalePlan);
            }
            if current.read_only.unwrap_or(false) { return Err(AppError::Permission("该防火墙规则为只读，无法安全删除".into())); }
            if state.backend == "ufw" && !current.backend_ref.as_deref().map(|value| value.chars().all(|c| c.is_ascii_digit())).unwrap_or(false) { return Err(AppError::Validation("UFW 规则缺少可靠编号，请刷新规则后重试".into())); }
            change.rule = FirewallRuleInput { id: Some(current.id.clone()), backend_ref: current.backend_ref.clone(), direction: current.direction.clone(), family: current.family.clone(), protocol: current.protocol.clone(), ports: current.ports.clone(), source: current.source.clone(), destination: current.destination.clone(), action: current.action.clone(), enabled: current.enabled, comment: current.comment.clone(), zone: current.zone.clone(), read_only: current.read_only };
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
                "{}{} {} {} {}",
                match change.operation.as_str() {
                    "add" => "添加",
                    "delete" => "删除",
                    _ => "修改",
                },
                if change.operation == "delete" {
                    change.rule.backend_ref.as_deref().map(|reference| format!(" #{reference}")).unwrap_or_default()
                } else {
                    String::new()
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
            let rollback_command = format!("sudo -n systemctl start {unit}.service");
            let rollback_elevated = if sudo_password.is_some() { rollback_command.replace("sudo -n", "sudo -S -p ''") } else { rollback_command };
            let rollback_result = ssh.exec_with_input(&stored.plan.host_id, &rollback_elevated, sudo_password).await;
            let rollback_message = match rollback_result { Ok(result) if result.exit_code == 0 => "自动回滚已启动".to_string(), Ok(result) => format!("自动回滚失败：{}", meaningful_firewall_error(&result.stdout, &result.stderr)), Err(error) => format!("自动回滚失败：{error}") };
            return Err(AppError::Permission(format!("防火墙命令失败：{}；{}", meaningful_firewall_error(&output.stdout, &output.stderr), rollback_message)));
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
fn meaningful_firewall_error(stdout: &str, stderr: &str) -> String {
    let lines = stderr.lines().chain(stdout.lines()).filter(|line| {
        let line = line.trim();
        !line.is_empty() && !line.starts_with("Running timer as unit:") && !line.starts_with("Will run service as unit:")
    }).collect::<Vec<_>>();
    if lines.is_empty() { "未知错误".into() } else { lines.join("\n") }
}

fn quality(s: &str) -> String {
    s.into()
}

fn delete_target_matches(input: &FirewallRuleInput, current: &UnifiedFirewallRule) -> bool {
    input.backend_ref == current.backend_ref
        && input.direction == current.direction
        && input.family == current.family
        && input.protocol == current.protocol
        && input.ports == current.ports
        && input.source == current.source
        && input.destination == current.destination
        && input.action == current.action
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
    let operation = c.operation.as_str();
    Ok(match backend {
        "ufw" => {
            if operation == "delete" {
                let number = r.backend_ref.as_deref().filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())).ok_or_else(|| AppError::Validation("UFW 规则缺少可靠编号".into()))?;
                return Ok(format!("ufw --force delete {number}"));
            }
            let proto = if r.protocol == "any" { String::new() } else { format!(" proto {}", r.protocol) };
            let from = if source == "any" { String::new() } else { format!(" from {}", source) };
            let port_clause = if port == "any" { String::new() } else { format!(" to any port {}", port) };
            format!("ufw {}{}{}{} comment {}", r.action, proto, from, port_clause, comment)
        }
        "firewalld" => {
            let source_clause = if source == "any" { String::new() } else { format!(" source address=\"{}\"", source) };
            let port_clause = if port == "any" { String::new() } else { format!(" port port=\"{}\" protocol=\"{}\"", port, r.protocol) };
            let verb = if r.action == "allow" { "accept" } else { "drop" };
            let rich = shell_quote(&format!("rule family=\"{}\"{}{} {}", if r.family == "ipv6" { "ipv6" } else { "ipv4" }, source_clause, port_clause, verb))?;
            format!("firewall-cmd --zone={} --{}rich-rule={}", r.zone.as_deref().unwrap_or("public"), if operation == "add" { "add-" } else { "remove-" }, rich)
        }
        "nftables" => {
            let family = if r.family == "ipv6" { "ip6" } else { "ip" };
            let source_clause = if source == "any" { String::new() } else { format!(" saddr {}", source) };
            let port_clause = if port == "any" || r.protocol == "icmp" || r.protocol == "any" { String::new() } else { format!(" dport {}", port) };
            if operation != "add" { return Err(AppError::Validation("nftables 规则没有可靠的 handle，无法安全删除".into())); }
            format!("nft add rule inet filter input {}{}{} {} comment {}", family, source_clause, port_clause, if r.action == "allow" { "accept" } else { "drop" }, comment)
        }
        _ => return Err(AppError::Validation("不支持的防火墙".into())),
    })
}
fn parse_ufw(raw: &str) -> (bool, String, String, Vec<UnifiedFirewallRule>) {
    let verbose = raw.split("__UFW_VERBOSE__").nth(1).unwrap_or(raw).split("__UFW_NUMBERED__").next().unwrap_or("");
    let numbered = raw.split("__UFW_NUMBERED__").nth(1).unwrap_or(raw);
    let enabled = verbose.contains("Status: active") || numbered.contains("Status: active");
    let mut di = "deny".into();
    let mut dout = "allow".into();
    for l in verbose.lines() {
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
    let rules = numbered.lines().filter_map(parse_ufw_numbered_line).collect();
    (enabled, di, dout, rules)
}

fn parse_ufw_numbered_line(line: &str) -> Option<UnifiedFirewallRule> {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') { return None; }
    let close = trimmed.find(']')?;
    let number = trimmed[1..close].trim();
    if number.is_empty() || !number.chars().all(|c| c.is_ascii_digit()) { return None; }
    let rest = trimmed[close + 1..].trim();
    let (body, comment) = rest.split_once('#').map(|(body, comment)| (body.trim(), comment.trim())).unwrap_or((rest, ""));
    let tokens = body.split_whitespace().collect::<Vec<_>>();
    let action_index = tokens.iter().position(|value| matches!(*value, "ALLOW" | "DENY" | "REJECT"))?;
    if action_index == 0 { return None; }
    let destination_token = tokens[0];
    let direction = tokens.get(action_index + 1).copied().filter(|value| matches!(*value, "IN" | "OUT")).unwrap_or("IN");
    let source = tokens.iter().skip(action_index + 2).filter(|value| **value != "(v6)").copied().collect::<Vec<_>>().join(" ");
    let family = if body.contains("(v6)") { "ipv6" } else { "ipv4" };
    let protocol = if destination_token.ends_with("/udp") { "udp" } else if destination_token.ends_with("/tcp") { "tcp" } else { "any" };
    let destination = destination_token.split('/').next().unwrap_or("Anywhere");
    Some(UnifiedFirewallRule {
        id: format!("ufw-{number}"), backend_ref: Some(number.into()), direction: if direction == "OUT" { "out".into() } else { "in".into() }, family: family.into(), protocol: protocol.into(), ports: if destination.eq_ignore_ascii_case("Anywhere") { "any".into() } else { destination.into() }, source: if source.is_empty() || source.eq_ignore_ascii_case("Anywhere") { "any".into() } else { source }, destination: "any".into(), action: tokens[action_index].to_ascii_lowercase(), enabled: true, comment: comment.into(), zone: None, read_only: None,
    })
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
        operation_kind: Some(source.into()),
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
    #[test]
    fn parses_numbered_ufw_rules_without_treating_comments_as_sources() {
        let raw = "__UFW_VERBOSE__\nStatus: active\nDefault: deny (incoming), allow (outgoing)\n__UFW_NUMBERED__\nStatus: active\n[ 1] 22/tcp ALLOW IN 10.0.0.0/8 # SSH office\n[ 2] 443/tcp (v6) ALLOW IN Anywhere (v6) # Web v6";
        let (_, _, _, rules) = parse_ufw(raw);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].backend_ref.as_deref(), Some("1"));
        assert_eq!(rules[0].source, "10.0.0.0/8");
        assert_eq!(rules[0].comment, "SSH office");
        assert_eq!(rules[1].source, "any");
        assert_eq!(rules[1].family, "ipv6");
    }
    #[test]
    fn deletes_ufw_by_stable_number() {
        let mut r = rule(); r.backend_ref = Some("12".into());
        let command = command_for("ufw", &FirewallChange { operation: "delete".into(), rule: r }).unwrap();
        assert_eq!(command, "ufw --force delete 12");
    }
    #[test]
    fn refuses_a_number_that_now_points_to_a_different_rule() {
        let mut input = rule();
        input.backend_ref = Some("1".into());
        let current = UnifiedFirewallRule {
            id: "ufw-1".into(), backend_ref: Some("1".into()), direction: "in".into(), family: "ipv4".into(), protocol: "tcp".into(), ports: "443".into(), source: "any".into(), destination: "any".into(), action: "allow".into(), enabled: true, comment: String::new(), zone: None, read_only: None,
        };
        assert!(!delete_target_matches(&input, &current));
    }
    #[test]
    fn hides_systemd_run_noise_from_firewall_errors() {
        let message = meaningful_firewall_error("", "Running timer as unit: x.timer\nWill run service as unit: x.service\nERROR: Bad source address");
        assert_eq!(message, "ERROR: Bad source address");
    }
}
