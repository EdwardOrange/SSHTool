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
    scheduler: String,
    applied: bool,
    rollback_unit: Option<String>,
    rollback_deadline: Option<String>,
    rollback_restore: Option<String>,
    persist_command: Option<String>,
    busy: bool,
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
        if state.backend == "nftables" {
            return Err(AppError::Permission("nftables 当前无法生成可靠的单规则回滚句柄，已拒绝写入".into()));
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
        let scheduler = self.scheduler(ssh, host_id).await?;
        let command = command_for(&state.backend, &change)?;
        let rollback_restore = if state.backend == "firewalld" {
            let inverse = FirewallChange { operation: if change.operation == "add" { "delete".into() } else { "add".into() }, rule: change.rule.clone() };
            Some(command_for("firewalld", &inverse)?)
        } else { None };
        let persist_command = if state.backend == "firewalld" { Some(command_for_scoped("firewalld", &change, true)?) } else { None };
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
                scheduler,
                applied: false,
                rollback_unit: None,
                rollback_deadline: None,
                rollback_restore,
                persist_command,
                busy: false,
            },
        );
        Ok(plan)
    }

    async fn scheduler(&self, ssh: &SshManager, host_id: &str) -> AppResult<String> {
        let output = ssh.exec(host_id, "if ! command -v flock >/dev/null 2>&1; then echo none; elif command -v systemd-run >/dev/null 2>&1; then echo systemd; elif command -v at >/dev/null 2>&1; then echo at; else echo none; fi").await?;
        let scheduler = output.stdout.lines().find(|line| matches!(line.trim(), "systemd" | "at" | "none")).unwrap_or("none").trim().to_owned();
        if scheduler == "none" { return Err(AppError::Permission("安全回滚需要 flock 和 systemd-run 或 at".into())); }
        Ok(scheduler)
    }
    pub async fn apply(
        &self,
        ssh: &SshManager,
        db: &Database,
        plan_id: &str,
        sudo_password: Option<&str>,
    ) -> AppResult<FirewallApplyResult> {
        let host_id = self.plan_host(plan_id).ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
        let previous = self.plans.read().iter().filter(|(id, plan)| id.as_str() != plan_id && plan.plan.host_id == host_id && plan.applied && !plan.busy)
            .map(|(id, plan)| (id.clone(), plan.rollback_unit.clone())).collect::<Vec<_>>();
        for (id, unit) in previous {
            let Some(unit) = unit else { continue; };
            let check = format!("sudo -n sh -c {}", shell_quote(&format!("test -f /run/{unit}/committed || test -f /run/{unit}/rolled-back"))?);
            let elevated = if sudo_password.is_some() { check.replace("sudo -n", "sudo -S -p ''") } else { check };
            let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
            let output = ssh.exec_with_input(&host_id, &elevated, input.as_deref()).await?;
            if output.exit_code == 0 { self.plans.write().remove(&id); }
        }
        let stored = {
            let mut plans = self.plans.write();
            let host_id = plans.get(plan_id).ok_or_else(|| AppError::NotFound("防火墙计划".into()))?.plan.host_id.clone();
            if plans.iter().any(|(id, plan)| id != plan_id && plan.plan.host_id == host_id && (plan.busy || plan.applied)) {
                return Err(AppError::Validation("该服务器还有未完成的防火墙变更，请先提交或回滚".into()));
            }
            let plan = plans.get_mut(plan_id).ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
            if plan.busy { return Err(AppError::Validation("该防火墙计划正在执行其他操作".into())); }
            if plan.applied { return Err(AppError::Validation("该防火墙计划已经执行，请提交或回滚".into())); }
            plan.busy = true;
            plan.clone()
        };
        let result = self.apply_inner(ssh, db, stored, sudo_password).await;
        if let Some(plan) = self.plans.write().get_mut(plan_id) { plan.busy = false; }
        result
    }

    async fn apply_inner(
        &self,
        ssh: &SshManager,
        db: &Database,
        stored: StoredPlan,
        sudo_password: Option<&str>,
    ) -> AppResult<FirewallApplyResult> {
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
        // firewalld treats adding an existing rule as success. Its inverse
        // would then delete a rule that predates this change.
        if stored.backend == "firewalld" {
            for command in stored.plan.commands.iter().flat_map(|command| command.split(" && ")) {
                if command.contains("--add-rich-rule=") || command.contains("--add-rule ") {
                    let query = command.replace("--add-rich-rule=", "--query-rich-rule=").replace("--add-rule ", "--query-rule ");
                    let elevated = if sudo_password.is_some() { query.replace("sudo -n", "sudo -S -p ''") } else { query };
                    let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
                    let output = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
                    if output.exit_code == 0 { return Err(AppError::Validation("规则已经存在，已拒绝重复添加以保护原规则".into())); }
                    if output.exit_code != 1 || output.stdout.trim() != "no" {
                        if sudo_password.is_none() && output.stderr.contains("sudo") { return Err(AppError::SudoRequired); }
                        return Err(AppError::Permission(meaningful_firewall_error(&output.stdout, &output.stderr)));
                    }
                }
            }
        }
        let unit = format!("sshops-rollback-{}", Uuid::new_v4());
        // /run is root-owned; an unprivileged local account cannot pre-create
        // a snapshot symlink or forge the at scheduler's commit marker.
        let workspace = format!("/run/{unit}");
        let snapshot = format!("{workspace}/snapshot");
        let command = &stored.plan.commands[0];
        let rollback_started = chrono::Utc::now();
        let rollback = match stored.backend.as_str() {
            "ufw" => format!(
                "sudo -n sh -c 'umask 077; mkdir -m 700 {workspace} && tar -C / -czf {snapshot} etc/ufw'"
            ),
            "firewalld" => format!("sudo -n mkdir -m 700 {workspace}"),
            "nftables" => format!(
                "sudo -n sh -c \"printf 'flush ruleset\\n' > {snapshot} && nft list ruleset >> {snapshot}\""
            ),
            _ => return Err(AppError::Validation("不支持的防火墙".into())),
        };
        let rollback_restore = match stored.backend.as_str() {
            "ufw" => format!("tar -C / -xzf {snapshot} && ufw reload"),
            "firewalld" => stored.rollback_restore.clone().ok_or_else(|| AppError::Validation("缺少 firewalld 单规则回滚命令".into()))?,
            "nftables" => format!("nft -f {snapshot}"),
            _ => return Err(AppError::Validation("不支持的防火墙".into())),
        };
        let rollback_restore = locked_rollback_command(&unit, &rollback_restore)?;
        let schedule = if stored.scheduler == "systemd" {
            format!("sudo -n systemd-run --unit={unit} --on-active=60s /bin/sh -c {}", shell_quote(&rollback_restore)?)
        } else {
            at_schedule_command(&unit, &rollback_restore)?
        };
        let deadline = format!("sudo -n sh -c {}", shell_quote(&format!("echo $(( $(date +%s) + 60 )) > {workspace}/deadline"))?);
        let prepare = format!("{rollback} && {deadline} && {schedule}");
        let elevated = if sudo_password.is_some() { prepare.replace("sudo -n", "sudo -S -p ''") } else { prepare.clone() };
        let sudo_input = sudo_password.map(|password| sudo_input_for(&elevated, password));
        let prepared = ssh.exec_with_input(&stored.plan.host_id, &elevated, sudo_input.as_deref()).await?;
        if prepared.exit_code != 0 {
            if sudo_password.is_none() && prepared.stderr.contains("sudo") { return Err(AppError::SudoRequired); }
            return Err(AppError::Permission(meaningful_firewall_error(&prepared.stdout, &prepared.stderr)));
        }
        let rollback_deadline = (rollback_started + chrono::Duration::seconds(60)).to_rfc3339();
        if let Some(plan) = self.plans.write().get_mut(&stored.plan.id) {
            plan.applied = true;
            plan.rollback_unit = Some(unit.clone());
            plan.rollback_deadline = Some(rollback_deadline.clone());
        }
        let apply = format!("sudo -n {}", locked_apply_command(&unit, command)?);
        let elevated = if sudo_password.is_some() { apply.replace("sudo -n", "sudo -S -p ''") } else { apply };
        let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
        let output = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
        log(db, ssh, &stored.plan.host_id, "firewall", command, &output);
        if output.exit_code != 0 {
            let rollback_command = if stored.scheduler == "systemd" {
                format!("sudo -n systemctl stop {unit}.timer && sudo -n systemctl start {unit}.service")
            } else {
                let snapshot = format!("/run/{unit}/snapshot");
                let restore = match stored.backend.as_str() { "ufw" => format!("tar -C / -xzf {snapshot} && ufw reload"), "firewalld" => stored.rollback_restore.clone().unwrap_or_else(|| "false".to_owned()), "nftables" => format!("nft -f {snapshot}"), _ => "true".to_owned() };
                format!("sudo -n sh -c {}", shell_quote(&locked_rollback_command(&unit, &restore)?)?)
            };
            let rollback_elevated = if sudo_password.is_some() { rollback_command.replace("sudo -n", "sudo -S -p ''") } else { rollback_command };
            let rollback_input = sudo_password.map(|password| sudo_input_for(&rollback_elevated, password));
            let rollback_result = ssh.exec_with_input(&stored.plan.host_id, &rollback_elevated, rollback_input.as_deref()).await;
            let rollback_message = match rollback_result { Ok(result) if result.exit_code == 0 => "自动回滚已启动".to_string(), Ok(result) => format!("自动回滚失败：{}", meaningful_firewall_error(&result.stdout, &result.stderr)), Err(error) => format!("自动回滚失败：{error}") };
            return Err(AppError::Permission(format!("防火墙命令失败：{}；{}", meaningful_firewall_error(&output.stdout, &output.stderr), rollback_message)));
        }
        let verification = tokio::time::timeout(std::time::Duration::from_secs(15), ssh.verify_new_connection(db, &stored.plan.host_id)).await
            .unwrap_or_else(|_| Err(AppError::Ssh("验证新的 SSH 连接超时".into())));
        if let Err(error) = verification {
            let rollback_command = if stored.scheduler == "systemd" {
                format!("sudo -n systemctl stop {unit}.timer && sudo -n systemctl start {unit}.service")
            } else {
                let snapshot = format!("/run/{unit}/snapshot");
                let restore = match stored.backend.as_str() { "ufw" => format!("tar -C / -xzf {snapshot} && ufw reload"), "firewalld" => stored.rollback_restore.clone().unwrap_or_else(|| "false".to_owned()), "nftables" => format!("nft -f {snapshot}"), _ => "true".to_owned() };
                format!("sudo -n sh -c {}", shell_quote(&locked_rollback_command(&unit, &restore)?)?)
            };
            let rollback_elevated = if sudo_password.is_some() { rollback_command.replace("sudo -n", "sudo -S -p ''") } else { rollback_command };
            let rollback_input = sudo_password.map(|password| sudo_input_for(&rollback_elevated, password));
            let rollback_result = ssh.exec_with_input(&stored.plan.host_id, &rollback_elevated, rollback_input.as_deref()).await;
            let rollback_message = match rollback_result { Ok(result) if result.exit_code == 0 => "自动回滚已启动".to_owned(), Ok(result) => format!("自动回滚失败：{}", meaningful_firewall_error(&result.stdout, &result.stderr)), Err(result) => format!("自动回滚失败：{result}") };
            return Err(AppError::Permission(format!("新的 SSH 连接验证失败：{error}；{rollback_message}")));
        }
        // The remote timer starts before the firewall command and SSH
        // verification. Report that same deadline instead of granting a new
        // 60-second window after the work has already consumed time.
        if chrono::Utc::now() >= rollback_started + chrono::Duration::seconds(60) { return Err(AppError::StalePlan); }
        Ok(FirewallApplyResult { rollback_deadline, verified: true })
    }
    pub async fn commit(&self, ssh: &SshManager, plan_id: &str, sudo_password: Option<&str>) -> AppResult<()> {
        let stored = {
            let mut plans = self.plans.write();
            let plan = plans.get_mut(plan_id).ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
            if plan.busy { return Err(AppError::Validation("该防火墙计划正在执行其他操作".into())); }
            plan.busy = true;
            plan.clone()
        };
        let result = self.commit_inner(ssh, plan_id, stored, sudo_password).await;
        if let Some(plan) = self.plans.write().get_mut(plan_id) { plan.busy = false; }
        result
    }
    async fn commit_inner(&self, ssh: &SshManager, plan_id: &str, stored: StoredPlan, sudo_password: Option<&str>) -> AppResult<()> {
        if !stored.applied {
            return Err(AppError::Validation("计划尚未执行".into()));
        }
        if stored.rollback_deadline.as_deref().and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok()).map(|value| value.with_timezone(&chrono::Utc) < chrono::Utc::now()).unwrap_or(false) {
            return Err(AppError::StalePlan);
        }
        if let Some(unit) = stored.rollback_unit {
            let persist = if stored.backend == "firewalld" {
                stored.persist_command.as_deref().ok_or_else(|| AppError::Validation("缺少 firewalld 持久化命令".into()))?
            } else { "true" };
            let cmd = format!("sudo -n {}", locked_commit_command(&unit, persist)?);
            let elevated = if sudo_password.is_some() { cmd.replace("sudo -n", "sudo -S -p ''") } else { cmd };
            let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
            let out = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
            if out.exit_code != 0 { return Err(AppError::Permission(meaningful_firewall_error(&out.stdout, &out.stderr))); }
        }
        self.plans.write().remove(plan_id);
        Ok(())
    }
    pub async fn rollback(&self, ssh: &SshManager, plan_id: &str, sudo_password: Option<&str>) -> AppResult<()> {
        let stored = {
            let mut plans = self.plans.write();
            let plan = plans.get_mut(plan_id).ok_or_else(|| AppError::NotFound("防火墙计划".into()))?;
            if plan.busy { return Err(AppError::Validation("该防火墙计划正在执行其他操作".into())); }
            plan.busy = true;
            plan.clone()
        };
        let result = self.rollback_inner(ssh, plan_id, stored, sudo_password).await;
        if let Some(plan) = self.plans.write().get_mut(plan_id) { plan.busy = false; }
        result
    }
    async fn rollback_inner(&self, ssh: &SshManager, plan_id: &str, stored: StoredPlan, sudo_password: Option<&str>) -> AppResult<()> {
        if let Some(unit) = stored.rollback_unit {
            let cmd = if stored.scheduler == "systemd" {
                format!("sudo -n systemctl stop {unit}.timer 2>/dev/null || true; sudo -n systemctl start {unit}.service")
            } else {
                let snapshot = format!("/run/{unit}/snapshot");
                let restore = match stored.backend.as_str() { "ufw" => format!("tar -C / -xzf {snapshot} && ufw reload"), "firewalld" => stored.rollback_restore.clone().unwrap_or_else(|| "false".to_owned()), "nftables" => format!("nft -f {snapshot}"), _ => "true".to_owned() };
                format!("sudo -n sh -c {}", shell_quote(&locked_rollback_command(&unit, &restore)?)?)
            };
            let elevated = if sudo_password.is_some() { cmd.replace("sudo -n", "sudo -S -p ''") } else { cmd };
            let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
            let out = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
            if out.exit_code != 0 { return Err(AppError::Other(out.stderr)); }
        }
        self.plans.write().remove(plan_id);
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

fn sudo_input_for(command: &str, password: &str) -> String {
    let count = command.matches("sudo -S").count().max(1);
    std::iter::repeat_n(password, count).collect::<Vec<_>>().join("\n")
}

fn at_schedule_command(unit: &str, restore: &str) -> AppResult<String> {
    let job = format!("sleep 60; if [ ! -f /run/{unit}/committed ]; then {restore}; fi\n");
    // Keep the job pipe inside the privileged shell so sudo's password is
    // read from SSH stdin, never from the script being submitted to at.
    let script = format!("printf '%s\\n' {} | at now", shell_quote(job.trim_end())?);
    Ok(format!("sudo -n sh -c {}", shell_quote(&script)?))
}

fn locked_rollback_command(unit: &str, restore: &str) -> AppResult<String> {
    let root = format!("/run/{unit}");
    let script = format!("if [ ! -f {root}/committed ] && [ ! -f {root}/rolled-back ]; then touch {root}/rollback-started && {{ if [ -f {root}/mutation-started ]; then {restore}; fi; }} && touch {root}/rolled-back; fi");
    Ok(format!("flock -x {root}/lock /bin/sh -c {}", shell_quote(&script)?))
}

fn locked_commit_command(unit: &str, persist: &str) -> AppResult<String> {
    let root = format!("/run/{unit}");
    let script = format!("deadline=$(cat {root}/deadline) || exit 1; now=$(date +%s) || exit 1; if [ ! -f {root}/rollback-started ] && [ \"$now\" -lt \"$deadline\" ]; then {persist} && touch {root}/committed; else echo 'Rollback deadline expired or rollback already started' >&2; exit 1; fi");
    Ok(format!("flock -x {root}/lock /bin/sh -c {}", shell_quote(&script)?))
}

fn locked_apply_command(unit: &str, command: &str) -> AppResult<String> {
    let root = format!("/run/{unit}");
    let script = format!("deadline=$(cat {root}/deadline) || exit 1; now=$(date +%s) || exit 1; if [ ! -f {root}/rollback-started ] && [ \"$now\" -lt \"$deadline\" ]; then touch {root}/mutation-started && {command}; else echo 'Firewall apply deadline expired' >&2; exit 1; fi");
    Ok(format!("flock -x {root}/lock /bin/sh -c {}", shell_quote(&script)?))
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
    if r.ports != "any" && (r.ports.len() > 64
        || !r
            .ports
            .chars()
            .all(|c| c.is_ascii_digit() || ",:-".contains(c)))
    {
        return Err(AppError::Validation("端口格式无效".into()));
    }
    address_family(&r.source)?;
    address_family(&r.destination)?;
    if !["in", "out", "forward"].contains(&r.direction.as_str()) || !["ipv4", "ipv6", "both"].contains(&r.family.as_str()) {
        return Err(AppError::Validation("方向或地址族无效".into()));
    }
    if let Some(zone) = r.zone.as_deref()
        && (zone.is_empty() || zone.len() > 64 || !zone.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)))
    {
        return Err(AppError::Validation("防火墙 zone 无效".into()));
    }
    if !r.ports.is_empty() && r.ports != "any" {
        for item in r.ports.split(',') {
            let parts = item.split_once(':').or_else(|| item.split_once('-'));
            let (start, end) = parts.unwrap_or((item, item));
            let start = start.parse::<u16>().map_err(|_| AppError::Validation("端口格式无效".into()))?;
            let end = end.parse::<u16>().map_err(|_| AppError::Validation("端口格式无效".into()))?;
            if start == 0 || end == 0 || start > end { return Err(AppError::Validation("端口范围无效".into())); }
        }
    }
    Ok(())
}

fn address_family(value: &str) -> AppResult<Option<&'static str>> {
    if value == "any" { return Ok(None); }
    let (address, prefix) = value.split_once('/').map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address: std::net::IpAddr = address.parse().map_err(|_| AppError::Validation("地址必须是 IP、CIDR 或 any".into()))?;
    if let Some(prefix) = prefix {
        let prefix: u8 = prefix.parse().map_err(|_| AppError::Validation("CIDR 前缀无效".into()))?;
        if prefix > if address.is_ipv4() { 32 } else { 128 } { return Err(AppError::Validation("CIDR 前缀超出地址范围".into())); }
    }
    Ok(Some(if address.is_ipv4() { "ipv4" } else { "ipv6" }))
}

fn rule_families(rule: &FirewallRuleInput) -> AppResult<Vec<&'static str>> {
    let source = address_family(&rule.source)?;
    let destination = address_family(&rule.destination)?;
    let families = ["ipv4", "ipv6"].into_iter().filter(|family| {
        (rule.family == "both" || rule.family == *family)
            && source.is_none_or(|value| value == *family)
            && destination.is_none_or(|value| value == *family)
    }).collect::<Vec<_>>();
    if families.is_empty() { return Err(AppError::Validation("来源、目标与所选地址族不兼容".into())); }
    Ok(families)
}
fn command_for(backend: &str, c: &FirewallChange) -> AppResult<String> {
    command_for_scoped(backend, c, false)
}
fn command_for_scoped(backend: &str, c: &FirewallChange, permanent: bool) -> AppResult<String> {
    let r = &c.rule;
    validate_rule(r)?;
    if !matches!(c.operation.as_str(), "add" | "delete") { return Err(AppError::Validation("防火墙操作无效".into())); }
    if c.operation == "add" && !r.enabled { return Err(AppError::Validation("不支持创建停用规则".into())); }
    let comment = shell_quote(&r.comment)?;
    let source = if r.source == "any" { "any" } else { &r.source };
    let port = if r.ports.is_empty() { "any" } else { &r.ports };
    let operation = c.operation.as_str();
    Ok(match backend {
        "ufw" => {
            if operation == "delete" {
                let number = r.backend_ref.as_deref().filter(|value| !value.is_empty() && value.chars().all(|c| c.is_ascii_digit())).ok_or_else(|| AppError::Validation("UFW 规则缺少可靠编号".into()))?;
                return Ok(format!("sudo -n ufw --force delete {number}"));
            }
            if r.protocol == "icmp" { return Err(AppError::Validation("UFW CLI 不支持安全创建 ICMP 规则".into())); }
            let proto = if r.protocol == "any" { String::new() } else { format!(" proto {}", r.protocol) };
            let from = format!(" from {} to {}", source, r.destination);
            let port_clause = if port == "any" { String::new() } else { format!(" port {}", port.replace('-', ":")) };
            if r.family != "both" { return Err(AppError::Validation("UFW 命令行无法安全限定单独的 IPv4/IPv6 规则".into())); }
            let route = if r.direction == "forward" { "route " } else { "" };
            let direction = if r.direction == "out" { " out" } else { "" };
            format!("sudo -n ufw {route}{}{}{}{}{} comment {}", r.action, direction, proto, from, port_clause, comment)
        }
        "firewalld" => {
            let families = rule_families(r)?;
            if port != "any" && !matches!(r.protocol.as_str(), "tcp" | "udp") {
                return Err(AppError::Validation("firewalld 端口规则必须明确选择 TCP 或 UDP".into()));
            }
            let permanent = if permanent { " --permanent" } else { "" };
            if let Some(port_ref) = r.backend_ref.as_deref().and_then(|value| value.strip_prefix("port:")) {
                if r.direction != "in" || r.source != "any" || r.destination != "any" || r.family != "both" || r.action != "allow" || !matches!(r.protocol.as_str(), "tcp" | "udp") || port_ref != format!("{}/{}", r.ports, r.protocol) {
                    return Err(AppError::Validation("该 firewalld 普通端口规则无法安全转换为当前操作".into()));
                }
                let verb = if operation == "add" { "add" } else if operation == "delete" { "remove" } else { return Err(AppError::Validation("firewalld 操作无效".into())); };
                return Ok(format!("sudo -n firewall-cmd{permanent} --zone={} --{}-port={}", r.zone.as_deref().unwrap_or("public"), verb, port_ref));
            }
            let verb = if r.action == "allow" { "accept" } else if r.action == "reject" { "reject" } else { "drop" };
            let mut commands = Vec::new();
            for family in families {
                let source_clause = if source == "any" { String::new() } else { format!(" source address=\"{}\"", source) };
                let protocol = if r.protocol == "icmp" && family == "ipv6" { "ipv6-icmp" } else { &r.protocol };
                let destination_clause = if r.destination == "any" { String::new() } else { format!(" destination address=\"{}\"", r.destination) };
                if r.direction == "in" {
                    for port in port.split(',') {
                        let element = if port != "any" { format!(" port port=\"{}\" protocol=\"{}\"", port.replace(':', "-"), protocol) }
                            else if protocol != "any" { format!(" protocol value=\"{protocol}\"") } else { String::new() };
                        let rich = shell_quote(&format!("rule family=\"{family}\"{source_clause}{destination_clause}{element} {verb}"))?;
                        commands.push(format!("sudo -n firewall-cmd{permanent} --zone={} --{}rich-rule={}", r.zone.as_deref().unwrap_or("public"), if operation == "add" { "add-" } else { "remove-" }, rich));
                    }
                } else {
                    let action = if operation == "add" { "add" } else { "remove" };
                    let protocol = if protocol == "any" { String::new() } else { format!(" -p {}", protocol) };
                    let port = if port == "any" { String::new() } else { format!(" -m multiport --dports {}", port.replace('-', ":")) };
                    let source = if source == "any" { String::new() } else { format!(" -s {}", source) };
                    let destination = if r.destination == "any" { String::new() } else { format!(" -d {}", r.destination) };
                    let chain = if r.direction == "out" { "OUTPUT" } else { "FORWARD" };
                    commands.push(format!("sudo -n firewall-cmd{permanent} --direct --{}-rule {family} filter {chain} 0{}{}{}{} -j {}", action, protocol, port, source, destination, verb.to_ascii_uppercase()));
                }
            }
            commands.join(" && ")
        }
        "nftables" => {
            let family = if r.family == "ipv6" || (r.family == "both" && source.contains(':')) { "ip6" } else { "ip" };
            let chain = if r.direction == "out" { "output" } else if r.direction == "forward" { "forward" } else { "input" };
            let source_clause = if source == "any" { String::new() } else { format!(" {family} saddr {}", source) };
            let protocol = if r.protocol == "any" || r.protocol == "icmp" { String::new() } else { format!(" {}", r.protocol) };
            let port_clause = if port == "any" || r.protocol == "icmp" || r.protocol == "any" { String::new() } else { format!(" dport {}", nft_ports(port)) };
            if operation != "add" { return Err(AppError::Validation("nftables 规则没有可靠的 handle，无法安全删除".into())); }
            format!("sudo -n nft add rule {} filter {}{}{}{} {} comment {}", if r.family == "both" { "inet" } else { family }, chain, source_clause, protocol, port_clause, if r.action == "allow" { "accept" } else if r.action == "reject" { "reject" } else { "drop" }, comment)
        }
        _ => return Err(AppError::Validation("不支持的防火墙".into())),
    })
}

fn nft_ports(ports: &str) -> String {
    if ports.contains(',') { format!("{{ {} }}", ports.replace(',', ", ")) } else { ports.replace(':', "-") }
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
    let zone = raw.lines().next().and_then(|line| line.split_whitespace().next()).filter(|value| !value.contains(':')).unwrap_or("public").to_string();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(ports) = line.strip_prefix("ports:") {
            for p in ports.split_whitespace() {
                let mut x = p.split('/');
                rules.push(UnifiedFirewallRule {
                    id: format!("fw-port-{zone}-{p}"),
                    backend_ref: Some(format!("port:{p}")),
                    direction: "in".into(),
                    family: "both".into(),
                    protocol: x.nth(1).unwrap_or("tcp").into(),
                    ports: p.split('/').next().unwrap_or("any").into(),
                    source: "any".into(),
                    destination: "any".into(),
                    action: "allow".into(),
                    enabled: true,
                    comment: "firewalld port".into(),
                    zone: Some(zone.clone()),
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
    fn preserves_direction_family_and_protocol_in_generated_commands() {
        let mut input = rule();
        input.direction = "out".into();
        input.family = "both".into();
        input.ports = "443".into();
        input.source = "any".into();
        let change = FirewallChange { operation: "add".into(), rule: input };
        let ufw = command_for("ufw", &change).unwrap();
        assert!(ufw.contains("ufw allow out proto tcp"));
        let firewalld = command_for("firewalld", &change).unwrap();
        assert!(firewalld.contains("ipv4 filter OUTPUT") && firewalld.contains("ipv6 filter OUTPUT"));
        let nft = command_for("nftables", &change).unwrap();
        assert!(nft.contains("inet filter output") && nft.contains("tcp dport 443"));
    }
    #[test]
    fn firewalld_port_rules_keep_zone_and_use_port_operations() {
        let (_, _, _, rules) = parse_firewalld("corp (active)\nports: 8443/tcp 5353/udp\n");
        assert_eq!(rules[0].zone.as_deref(), Some("corp"));
        assert_eq!(rules[0].backend_ref.as_deref(), Some("port:8443/tcp"));
        let command = command_for("firewalld", &FirewallChange { operation: "delete".into(), rule: FirewallRuleInput {
            id: Some(rules[0].id.clone()), backend_ref: rules[0].backend_ref.clone(), direction: rules[0].direction.clone(), family: rules[0].family.clone(), protocol: rules[0].protocol.clone(), ports: rules[0].ports.clone(), source: rules[0].source.clone(), destination: rules[0].destination.clone(), action: rules[0].action.clone(), enabled: rules[0].enabled, comment: rules[0].comment.clone(), zone: rules[0].zone.clone(), read_only: rules[0].read_only,
        }}).unwrap();
        assert_eq!(command, "sudo -n firewall-cmd --zone=corp --remove-port=8443/tcp");
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
        assert_eq!(command, "sudo -n ufw --force delete 12");
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

    #[test]
    fn protocol_only_rules_do_not_become_allow_all() {
        for (protocol, expected) in [("tcp", "tcp"), ("udp", "udp"), ("icmp", "ipv6-icmp")] {
            let mut input = rule(); input.source = "any".into(); input.family = "ipv6".into();
            input.protocol = protocol.into(); input.ports = "any".into();
            let command = command_for("firewalld", &FirewallChange { operation: "add".into(), rule: input }).unwrap();
            assert!(command.contains(&format!("protocol value=\"{expected}\"")), "{command}");
        }
    }

    #[test]
    fn preserves_destination_and_expands_rich_port_lists() {
        let mut input = rule(); input.destination = "10.1.2.3".into(); input.ports = "80,8000:8010".into();
        let change = FirewallChange { operation: "add".into(), rule: input };
        let ufw = command_for("ufw", &change).unwrap();
        assert!(ufw.contains("to 10.1.2.3 port 80,8000:8010"));
        let fw = command_for("firewalld", &change).unwrap();
        assert_eq!(fw.matches("--add-rich-rule").count(), 2);
        assert_eq!(fw.matches("destination address=\"10.1.2.3\"").count(), 2);
        assert!(fw.contains("port=\"8000-8010\""));
        assert!(!fw.contains("ipv6"));
    }

    #[test]
    fn rejects_ambiguous_or_injected_rule_fields() {
        let mut input = rule(); input.protocol = "any".into();
        assert!(command_for("firewalld", &FirewallChange { operation: "add".into(), rule: input.clone() }).is_err());
        input.protocol = "tcp".into(); input.destination = "any;reboot".into();
        assert!(validate_rule(&input).is_err());
        input.destination = "any".into(); input.source = "10.0.0.1/33".into();
        assert!(validate_rule(&input).is_err());
        input.source = "any".into(); input.backend_ref = Some("port:22/tcp;reboot".into());
        assert!(command_for("firewalld", &FirewallChange { operation: "add".into(), rule: input }).is_err());
    }

    #[test]
    fn accepts_any_port_for_ufw_deletion() {
        let mut input = rule(); input.ports = "any".into(); input.backend_ref = Some("3".into());
        assert_eq!(command_for("ufw", &FirewallChange { operation: "delete".into(), rule: input }).unwrap(), "sudo -n ufw --force delete 3");
    }

    #[test]
    fn at_job_keeps_its_script_separate_from_sudo_stdin() {
        let command = at_schedule_command("sshops-test", "ufw reload").unwrap();
        assert!(command.starts_with("sudo -n sh -c "));
        assert!(command.contains("/run/sshops-test/committed"));
        assert!(!command.contains("| sudo"));
        assert!(!command.contains("/tmp/"));
    }

    #[test]
    fn commit_and_rollback_are_mutually_exclusive_in_a_real_shell() {
        use std::{path::PathBuf, process::{Command, Stdio}};
        let bash = [PathBuf::from(r"C:\msys64\usr\bin\bash.exe"), PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"), PathBuf::from("/bin/bash")]
            .into_iter().find(|path| path.exists());
        let Some(bash) = bash else { eprintln!("Skipped shell integration: Bash unavailable"); return; };
        if !Command::new(&bash).args(["-c", "PATH=/usr/bin:/bin:$PATH; command -v flock"]).stdout(Stdio::null()).status().unwrap().success() {
            eprintln!("Skipped shell integration: flock unavailable"); return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("mutation-started"), "").unwrap();
        std::fs::write(root.path().join("deadline"), (chrono::Utc::now().timestamp() + 60).to_string()).unwrap();
        let commit = format!("export PATH=/usr/bin:/bin:$PATH; {}", locked_commit_command("review-test", "sleep 0.1; echo commit >> effects").unwrap().replace("/run/review-test", "."));
        let rollback = format!("export PATH=/usr/bin:/bin:$PATH; {}", locked_rollback_command("review-test", "echo rollback >> effects").unwrap().replace("/run/review-test", "."));
        let mut a = Command::new(&bash).args(["-c", &commit]).current_dir(root.path()).stderr(Stdio::null()).spawn().unwrap();
        let mut b = Command::new(&bash).args(["-c", &rollback]).current_dir(root.path()).spawn().unwrap();
        let committed = a.wait().unwrap().success();
        assert!(b.wait().unwrap().success());
        let effects = std::fs::read_to_string(root.path().join("effects")).unwrap();
        assert_eq!(effects.trim(), if committed { "commit" } else { "rollback" });

        let expired = tempfile::tempdir().unwrap();
        std::fs::write(expired.path().join("deadline"), "1").unwrap();
        assert!(!Command::new(&bash).args(["-c", &commit]).current_dir(expired.path()).stderr(Stdio::null()).status().unwrap().success());
        assert!(!expired.path().join("effects").exists());

        // A prepared transaction that never mutated the firewall must not
        // restore an old snapshot; late apply requests must remain rejected.
        let untouched = tempfile::tempdir().unwrap();
        std::fs::write(untouched.path().join("deadline"), (chrono::Utc::now().timestamp() + 60).to_string()).unwrap();
        assert!(Command::new(&bash).args(["-c", &rollback]).current_dir(untouched.path()).status().unwrap().success());
        assert!(!untouched.path().join("effects").exists());
        let apply = format!("export PATH=/usr/bin:/bin:$PATH; {}", locked_apply_command("review-test", "echo apply >> effects").unwrap().replace("/run/review-test", "."));
        assert!(!Command::new(&bash).args(["-c", &apply]).current_dir(untouched.path()).stderr(Stdio::null()).status().unwrap().success());
        assert!(!untouched.path().join("effects").exists());
    }
}
