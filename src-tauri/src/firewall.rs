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

// Every privileged read must propagate its failure. A trailing capability
// probe must never turn a permission error into an empty, successful ruleset.
const READ_COMMAND: &str = r#"LANG=C; export LANG
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi; }
ufw_status=
if command -v ufw >/dev/null 2>&1; then
    ufw_status=$(as_root ufw status) || exit 1
fi
if printf '%s\n' "$ufw_status" | grep -q '^Status: active'; then
    backend=ufw
elif command -v firewall-cmd >/dev/null 2>&1 && as_root firewall-cmd --state >/dev/null 2>&1; then
    backend=firewalld
elif [ -n "$ufw_status" ]; then
    backend=ufw
elif command -v nft >/dev/null 2>&1; then
    backend=nftables
else backend=unsupported
fi
echo "$backend"
case "$backend" in
ufw)
    echo __UFW_VERBOSE__; as_root ufw status verbose || exit 1
    echo __UFW_NUMBERED__; as_root ufw status numbered || exit 1
    ;;
firewalld)
    printf '__FIREWALLD_DEFAULT__:'; as_root firewall-cmd --get-default-zone || exit 1
    as_root firewall-cmd --list-all-zones || exit 1
    echo __FIREWALLD_DIRECT__; as_root firewall-cmd --direct --get-all-rules || exit 1
    ;;
nftables) as_root nft list ruleset || exit 1 ;;
esac
echo __ROLLBACK__
if [ "$backend" != unsupported ] && [ "$backend" != nftables ] && command -v flock >/dev/null 2>&1 && { { command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; } || { command -v at >/dev/null 2>&1 && pgrep -x atd >/dev/null 2>&1; }; }; then echo yes; else echo no; fi"#;

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
    #[cfg(test)]
    pub(crate) fn live_test_rollback_unit(&self, plan_id: &str) -> Option<String> {
        self.plans.read().get(plan_id).and_then(|plan| plan.rollback_unit.clone())
    }

    #[cfg(test)]
    pub(crate) fn live_test_fail_after_mutation(&self, plan_id: &str) {
        self.plans.write().get_mut(plan_id).unwrap().plan.commands[0].push_str(" && false");
    }

    #[cfg(test)]
    pub(crate) fn live_test_use_scheduler(&self, plan_id: &str, scheduler: &str) {
        assert!(matches!(scheduler, "systemd" | "at"));
        self.plans.write().get_mut(plan_id).unwrap().scheduler = scheduler.into();
    }

    pub fn plan_host(&self, plan_id: &str) -> Option<String> {
        self.plans.read().get(plan_id).map(|stored| stored.plan.host_id.clone())
    }

    #[cfg(test)]
    pub async fn read(&self, ssh: &SshManager, host_id: &str) -> AppResult<FirewallState> {
        self.read_with_password(ssh, host_id, None).await
    }

    pub async fn read_with_password(&self, ssh: &SshManager, host_id: &str, sudo_password: Option<&str>) -> AppResult<FirewallState> {
        let command = firewall_read_command(sudo_password.is_some())?;
        let out = ssh.exec_with_input(host_id, &command, sudo_password).await?;
        if out.exit_code != 0 {
            return Err(firewall_read_error(&out, sudo_password.is_some()));
        }
        let before = out.stdout.split("__ROLLBACK__").next().unwrap_or("");
        let rollback = out
            .stdout
            .split("__ROLLBACK__")
            .nth(1)
            .unwrap_or("")
            .trim() == "yes";
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
    #[cfg(test)]
    pub async fn plan(
        &self,
        ssh: &SshManager,
        host_id: &str,
        change: FirewallChange,
    ) -> AppResult<FirewallPlan> {
        self.plan_with_password(ssh, host_id, change, None).await
    }

    pub async fn plan_with_password(
        &self,
        ssh: &SshManager,
        host_id: &str,
        change: FirewallChange,
        sudo_password: Option<&str>,
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
        let state = self.read_with_password(ssh, host_id, sudo_password).await?;
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
        let output = ssh.exec(host_id, "if ! command -v flock >/dev/null 2>&1; then echo none; elif command -v systemd-run >/dev/null 2>&1 && [ -d /run/systemd/system ]; then echo systemd; elif command -v at >/dev/null 2>&1 && pgrep -x atd >/dev/null 2>&1; then echo at; else echo none; fi").await?;
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
            if output.exit_code != 0 && output.stderr.to_ascii_lowercase().contains("sudo:") {
                return Err(firewall_read_error(&output, sudo_password.is_some()));
            }
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
        let current = self.read_with_password(ssh, &stored.plan.host_id, sudo_password).await?;
        if current.state_hash != stored.plan.state_hash {
            return Err(AppError::StalePlan);
        }
        // firewalld treats adding an existing rule as success. Its inverse
        // would then delete a rule that predates this change.
        if stored.backend == "firewalld" {
            for command in stored.plan.commands.iter().flat_map(|command| command.split(" && ")) {
                if command.contains("--add-") {
                    let query = firewalld_rule_operation(command, "query")?;
                    let elevated = if sudo_password.is_some() { query.replace("sudo -n", "sudo -S -p ''") } else { query };
                    let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
                    let output = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
                    if output.exit_code == 0 { return Err(AppError::Validation("规则已经存在，已拒绝重复添加以保护原规则".into())); }
                    if output.exit_code != 1 || output.stdout.trim() != "no" {
                        return Err(firewall_read_error(&output, sudo_password.is_some()));
                    }
                }
            }
        }
        // Runtime and permanent firewalld configurations are independent. A
        // multi-command commit can fail after writing only some permanent
        // rules, so capture each rule's original permanent presence before
        // scheduling rollback. Never derive this from its runtime presence.
        let mut permanent_restore = Vec::new();
        if let Some(persist) = stored.persist_command.as_deref() {
            for command in persist.split(" && ") {
                let query = firewalld_rule_operation(command, "query")?;
                let elevated = if sudo_password.is_some() { query.replace("sudo -n", "sudo -S -p ''") } else { query };
                let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
                let output = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
                let present = match (output.exit_code, output.stdout.trim()) {
                    (0, "yes") => true,
                    (1, "no") => false,
                    _ => {
                        return Err(firewall_read_error(&output, sudo_password.is_some()));
                    }
                };
                permanent_restore.push(firewalld_rule_operation(command, if present { "add" } else { "remove" })?.replace("sudo -n ", ""));
            }
        }
        let permanent_restore = if permanent_restore.is_empty() { "true".to_owned() } else { permanent_restore.join(" && ") };
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
            // systemd timers otherwise default to a one-minute coalescing
            // window, which can leave a promised 60-second rollback pending
            // for almost two minutes.
            format!("sudo -n systemd-run --unit={unit} --on-active=60s --timer-property=AccuracySec=1s --timer-property=RandomizedDelaySec=0 /bin/sh -c {}", shell_quote(&rollback_restore)?)
        } else {
            at_schedule_command(&unit, &rollback_restore)?
        };
        let deadline = format!("sudo -n sh -c {}", shell_quote(&format!("echo $(( $(date +%s) + 60 )) > {workspace}/deadline"))?);
        let save_permanent = format!("sudo -n sh -c {}", shell_quote(&format!("umask 077; printf '%s\\n' {} > {workspace}/permanent-restore", shell_quote(&permanent_restore)?))?);
        let prepare = format!("{rollback} && {save_permanent} && {deadline} && {schedule}");
        let elevated = if sudo_password.is_some() { prepare.replace("sudo -n", "sudo -S -p ''") } else { prepare.clone() };
        let sudo_input = sudo_password.map(|password| sudo_input_for(&elevated, password));
        let prepared = ssh.exec_with_input(&stored.plan.host_id, &elevated, sudo_input.as_deref()).await?;
        if prepared.exit_code != 0 {
            return Err(firewall_read_error(&prepared, sudo_password.is_some()));
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
            let rollback_command = immediate_rollback_command(&stored, &unit)?;
            let rollback_elevated = if sudo_password.is_some() { rollback_command.replace("sudo -n", "sudo -S -p ''") } else { rollback_command };
            let rollback_input = sudo_password.map(|password| sudo_input_for(&rollback_elevated, password));
            let rollback_result = ssh.exec_with_input(&stored.plan.host_id, &rollback_elevated, rollback_input.as_deref()).await;
            let rollback_message = match rollback_result { Ok(result) if result.exit_code == 0 => "自动回滚已启动".to_string(), Ok(result) => format!("自动回滚失败：{}", meaningful_firewall_error(&result.stdout, &result.stderr)), Err(error) => format!("自动回滚失败：{error}") };
            return Err(AppError::Permission(format!("防火墙命令失败：{}；{}", meaningful_firewall_error(&output.stdout, &output.stderr), rollback_message)));
        }
        let verification = tokio::time::timeout(std::time::Duration::from_secs(15), ssh.verify_new_connection(db, &stored.plan.host_id)).await
            .unwrap_or_else(|_| Err(AppError::Ssh("验证新的 SSH 连接超时".into())));
        if let Err(error) = verification {
            let rollback_command = immediate_rollback_command(&stored, &unit)?;
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
            if out.exit_code != 0 { return Err(firewall_read_error(&out, sudo_password.is_some())); }
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
        if let Some(unit) = stored.rollback_unit.as_deref() {
            // Starting a systemd service can return before its work finishes.
            // Execute the same locked restore synchronously, retaining the
            // plan until restoration finishes; the timer remains idempotent.
            let cmd = immediate_rollback_command(&stored, unit)?;
            let elevated = if sudo_password.is_some() { cmd.replace("sudo -n", "sudo -S -p ''") } else { cmd };
            let input = sudo_password.map(|password| sudo_input_for(&elevated, password));
            let out = ssh.exec_with_input(&stored.plan.host_id, &elevated, input.as_deref()).await?;
            if out.exit_code != 0 { return Err(firewall_read_error(&out, sudo_password.is_some())); }
        }
        self.plans.write().remove(plan_id);
        Ok(())
    }
}
fn firewall_read_command(with_password: bool) -> AppResult<String> {
    if !with_password { return Ok(READ_COMMAND.into()); }
    // Elevate the whole read once. Each inner as_root invocation now runs as
    // root, so no repeated sudo prompt can consume a second password line.
    // READ_COMMAND is a trusted compile-time script containing newlines.
    // Keep the stricter shell_quote validation for every user-supplied value.
    let quoted_script = format!("'{}'", READ_COMMAND.replace('\'', "'\"'\"'"));
    Ok(format!("LANG=C; export LANG; if [ \"$(id -u)\" -eq 0 ]; then {READ_COMMAND}\nelse sudo -S -p '' sh -c {quoted_script}; fi"))
}

fn firewall_read_error(output: &ExecOutput, supplied_password: bool) -> AppError {
    let stderr = output.stderr.to_ascii_lowercase();
    let sudo_error = stderr.lines().any(|line| line.trim_start().starts_with("sudo:"));
    if sudo_error {
        if stderr.contains("incorrect password attempt") || stderr.contains("sorry, try again")
            || (supplied_password && stderr.contains("no password was provided"))
        {
            // Never relay arbitrary authentication output alongside a secret;
            // the stable error kind allows replacing an expired saved secret.
            return AppError::SudoAuthenticationFailed("密码不正确或验证失败，请重新输入".into());
        }
        if stderr.contains("a password is required") || stderr.contains("no password was provided")
            || stderr.contains("a terminal is required to read the password")
        {
            return AppError::SudoRequired;
        }
    }
    AppError::Permission(meaningful_firewall_error(&output.stdout, &output.stderr))
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

fn firewalld_rule_operation(command: &str, operation: &str) -> AppResult<String> {
    for kind in ["rich-rule=", "port=", "rule "] {
        for current in ["add", "remove"] {
            let flag = format!("--{current}-{kind}");
            if command.contains(&flag) {
                return Ok(command.replacen(&flag, &format!("--{operation}-{kind}"), 1));
            }
        }
    }
    Err(AppError::Validation("无法识别 firewalld 规则命令".into()))
}

fn immediate_rollback_command(stored: &StoredPlan, unit: &str) -> AppResult<String> {
    let snapshot = format!("/run/{unit}/snapshot");
    let restore = match stored.backend.as_str() {
        "ufw" => format!("tar -C / -xzf {snapshot} && ufw reload"),
        "firewalld" => stored.rollback_restore.clone().ok_or_else(|| AppError::Validation("缺少 firewalld 回滚命令".into()))?,
        _ => return Err(AppError::Validation("不支持的防火墙".into())),
    };
    Ok(format!("sudo -n {}", locked_rollback_command(unit, &restore)?))
}

fn at_schedule_command(unit: &str, restore: &str) -> AppResult<String> {
    // atd may pick up `at now` on its next polling cycle. Sleep only until
    // the existing transaction deadline, not another full minute afterward.
    let job = format!("deadline=$(cat /run/{unit}/deadline) || exit 1; now=$(date +%s) || exit 1; remaining=$((deadline - now)); if [ \"$remaining\" -gt 0 ]; then sleep \"$remaining\"; fi; if [ ! -f /run/{unit}/committed ]; then {restore}; fi\n");
    // Keep the job pipe inside the privileged shell so sudo's password is
    // read from SSH stdin, never from the script being submitted to at.
    let script = format!("printf '%s\\n' {} | at now", shell_quote(job.trim_end())?);
    Ok(format!("sudo -n sh -c {}", shell_quote(&script)?))
}

fn locked_rollback_command(unit: &str, restore: &str) -> AppResult<String> {
    let root = format!("/run/{unit}");
    let script = format!("if [ ! -f {root}/committed ] && [ ! -f {root}/rolled-back ]; then touch {root}/rollback-started || exit 1; rollback_status=0; if [ -f {root}/persistence-started ]; then /bin/sh {root}/permanent-restore || rollback_status=1; fi; if [ -f {root}/mutation-started ]; then {{ {restore}; }} || rollback_status=1; fi; [ \"$rollback_status\" -eq 0 ] && touch {root}/rolled-back; fi");
    Ok(format!("flock -x {root}/lock /bin/sh -c {}", shell_quote(&script)?))
}

fn locked_commit_command(unit: &str, persist: &str) -> AppResult<String> {
    let root = format!("/run/{unit}");
    let script = format!("if [ -f {root}/committed ]; then exit 0; fi; deadline=$(cat {root}/deadline) || exit 1; now=$(date +%s) || exit 1; if [ -f {root}/apply-completed ] && [ ! -f {root}/rollback-started ] && [ \"$now\" -lt \"$deadline\" ]; then touch {root}/persistence-started && {persist} && touch {root}/committed; else echo 'Firewall apply incomplete, rollback deadline expired or rollback already started' >&2; exit 1; fi");
    Ok(format!("flock -x {root}/lock /bin/sh -c {}", shell_quote(&script)?))
}

fn locked_apply_command(unit: &str, command: &str) -> AppResult<String> {
    let root = format!("/run/{unit}");
    let script = format!("deadline=$(cat {root}/deadline) || exit 1; now=$(date +%s) || exit 1; if [ ! -f {root}/mutation-started ] && [ ! -f {root}/committed ] && [ ! -f {root}/rollback-started ] && [ \"$now\" -lt \"$deadline\" ]; then touch {root}/mutation-started && {command} && touch {root}/apply-completed; else echo 'Firewall apply already started or deadline expired' >&2; exit 1; fi");
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
            // Omit --zone to address the same default zone read() displays.
            // A server's default zone is not necessarily named public.
            let zone = r.zone.as_deref().map(|zone| format!(" --zone={zone}")).unwrap_or_default();
            for kind in ["rich:", "direct:"] {
                if let Some(reference) = r.backend_ref.as_deref().and_then(|value| value.strip_prefix(kind)) {
                    let current = if kind == "rich:" { parse_firewalld_rich(reference, r.zone.as_deref().unwrap_or("public")) }
                        else { parse_firewalld_direct(reference) };
                    let current = current.filter(|current| delete_target_matches(r, current))
                        .ok_or_else(|| AppError::Validation("firewalld 原始规则与显示字段不一致".into()))?;
                    if current.read_only.unwrap_or(false) { return Err(AppError::Validation("无法安全操作该 firewalld 规则".into())); }
                    let verb = if operation == "add" { "add" } else { "remove" };
                    return if kind == "rich:" {
                        Ok(format!("sudo -n firewall-cmd{permanent}{zone} --{verb}-rich-rule={}", shell_quote(reference)?))
                    } else {
                        // A direct rule is validated as an exact sequence of safe
                        // protocol/address/port tokens before being reused.
                        Ok(format!("sudo -n firewall-cmd{permanent} --direct --{verb}-rule {reference}"))
                    };
                }
            }
            if let Some(port_ref) = r.backend_ref.as_deref().and_then(|value| value.strip_prefix("port:")) {
                if r.direction != "in" || r.source != "any" || r.destination != "any" || r.family != "both" || r.action != "allow" || !matches!(r.protocol.as_str(), "tcp" | "udp") || port_ref != format!("{}/{}", r.ports, r.protocol) {
                    return Err(AppError::Validation("该 firewalld 普通端口规则无法安全转换为当前操作".into()));
                }
                let verb = if operation == "add" { "add" } else if operation == "delete" { "remove" } else { return Err(AppError::Validation("firewalld 操作无效".into())); };
                return Ok(format!("sudo -n firewall-cmd{permanent}{zone} --{verb}-port={port_ref}"));
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
                        commands.push(format!("sudo -n firewall-cmd{permanent}{zone} --{}rich-rule={rich}", if operation == "add" { "add-" } else { "remove-" }));
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
    let mut di = "unknown".into();
    let mut dout = "unknown".into();
    for l in verbose.lines() {
        if l.starts_with("Default:") {
            let low = l.to_lowercase();
            for policy in ["allow", "deny", "reject", "disabled"] {
                if low.contains(&format!("{policy} (incoming)")) { di = policy.into(); }
                if low.contains(&format!("{policy} (outgoing)")) { dout = policy.into(); }
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
    let explicit_direction = tokens.get(action_index + 1).copied().filter(|value| matches!(*value, "IN" | "OUT" | "FWD"));
    let direction = explicit_direction.unwrap_or("IN");
    let destination_tokens = tokens[..action_index].iter().copied().filter(|value| *value != "(v6)").collect::<Vec<_>>();
    let source_tokens = tokens[action_index + 1 + usize::from(explicit_direction.is_some())..].iter().copied().filter(|value| *value != "(v6)").collect::<Vec<_>>();
    let destination = parse_ufw_endpoint(&destination_tokens);
    let source = parse_ufw_endpoint(&source_tokens);
    let read_only = destination.is_none() || source.as_ref().is_none_or(|(_, ports, _)| ports != "any");
    let (destination, ports, protocol) = destination.unwrap_or_else(|| ("any".into(), "any".into(), "any".into()));
    let source = source.map(|(address, _, _)| address).unwrap_or_else(|| "any".into());
    let family = if body.contains("(v6)") { "ipv6" } else { "ipv4" };
    Some(UnifiedFirewallRule {
        id: format!("ufw-{number}"), backend_ref: Some(number.into()), direction: match direction { "OUT" => "out", "FWD" => "forward", _ => "in" }.into(), family: family.into(), protocol, ports, source, destination, action: tokens[action_index].to_ascii_lowercase(), enabled: true, comment: if read_only { format!("{comment} [UFW: {body}]").trim().into() } else { comment.into() }, zone: None, read_only: read_only.then_some(true),
    })
}

fn parse_ufw_endpoint(tokens: &[&str]) -> Option<(String, String, String)> {
    let mut tokens = tokens.iter().copied();
    let first = tokens.next()?;
    let address = if first.eq_ignore_ascii_case("Anywhere") { Some("any".to_owned()) }
        else if address_family(first).is_ok() { Some(first.to_owned()) } else { None };
    let (address, port) = if let Some(address) = address { (address, tokens.next()) } else { ("any".to_owned(), Some(first)) };
    if tokens.next().is_some() { return None; }
    let Some(port) = port else { return Some((address, "any".into(), "any".into())); };
    let (port, protocol) = port.split_once('/').unwrap_or((port, "any"));
    if !["tcp", "udp", "any"].contains(&protocol) || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit() || ",:-".contains(c)) { return None; }
    Some((address, port.into(), protocol.into()))
}
fn parse_firewalld(raw: &str) -> (bool, String, String, Vec<UnifiedFirewallRule>) {
    let mut rules = Vec::new();
    let (zones, direct) = raw.split_once("__FIREWALLD_DIRECT__").unwrap_or((raw, ""));
    let mut zone = "public".to_string();
    for line in zones.lines() {
        if !line.starts_with(char::is_whitespace) && !line.contains(':') && !line.trim().is_empty() {
            zone = line.split_whitespace().next().unwrap_or("public").to_owned();
        }
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
        } else if line.starts_with("rule ") {
            rules.push(parse_firewalld_rich(line, &zone).unwrap_or_else(|| opaque_firewalld_rule(line, Some(&zone), "rich")));
        } else if let Some(services) = line.strip_prefix("services:") {
            for service in services.split_whitespace() {
                let mut rule = opaque_firewalld_rule(service, Some(&zone), "service");
                rule.action = "allow".into();
                rules.push(rule);
            }
        }
    }
    for line in direct.lines().map(str::trim).filter(|line| !line.is_empty()) {
        rules.push(parse_firewalld_direct(line).unwrap_or_else(|| opaque_firewalld_rule(line, None, "direct")));
    }
    (true, "zone policy".into(), "allow".into(), rules)
}

fn opaque_firewalld_rule(raw: &str, zone: Option<&str>, kind: &str) -> UnifiedFirewallRule {
    let hash = hex::encode(Sha256::digest(format!("{}:{raw}", zone.unwrap_or("")).as_bytes()));
    UnifiedFirewallRule {
        id: format!("fw-{kind}-{hash}"), backend_ref: Some(format!("{kind}:{raw}")),
        direction: "in".into(), family: "both".into(), protocol: "any".into(), ports: "any".into(),
        source: "any".into(), destination: "any".into(), action: "unknown".into(), enabled: true,
        comment: format!("firewalld {kind}: {raw}"), zone: zone.map(str::to_owned), read_only: Some(true),
    }
}

fn firewall_input(rule: &UnifiedFirewallRule) -> FirewallRuleInput {
    FirewallRuleInput { id: Some(rule.id.clone()), backend_ref: rule.backend_ref.clone(), direction: rule.direction.clone(),
        family: rule.family.clone(), protocol: rule.protocol.clone(), ports: rule.ports.clone(), source: rule.source.clone(),
        destination: rule.destination.clone(), action: rule.action.clone(), enabled: rule.enabled, comment: rule.comment.clone(),
        zone: rule.zone.clone(), read_only: rule.read_only }
}

fn rich_attribute<'a>(token: &'a str, name: &str) -> Option<&'a str> {
    token.strip_prefix(name)?.strip_prefix('=')?.strip_prefix('"')?.strip_suffix('"')
}

fn parse_firewalld_rich(raw: &str, zone: &str) -> Option<UnifiedFirewallRule> {
    let tokens = raw.split_whitespace().collect::<Vec<_>>();
    if tokens.first().copied() != Some("rule") { return None; }
    let mut rule = opaque_firewalld_rule(raw, Some(zone), "rich");
    let mut index = 1;
    if let Some(family) = tokens.get(index).and_then(|token| rich_attribute(token, "family")) {
        rule.family = family.to_owned(); index += 1;
    }
    if tokens.get(index).copied() == Some("source") {
        rule.source = rich_attribute(tokens.get(index + 1)?, "address")?.into(); index += 2;
    }
    if tokens.get(index).copied() == Some("destination") {
        rule.destination = rich_attribute(tokens.get(index + 1)?, "address")?.into(); index += 2;
    }
    if tokens.get(index).copied() == Some("port") {
        rule.ports = rich_attribute(tokens.get(index + 1)?, "port")?.into();
        rule.protocol = rich_attribute(tokens.get(index + 2)?, "protocol")?.into(); index += 3;
    } else if tokens.get(index).copied() == Some("protocol") {
        rule.protocol = rich_attribute(tokens.get(index + 1)?, "value")?.into(); index += 2;
    }
    if rule.protocol == "ipv6-icmp" { rule.protocol = "icmp".into(); }
    rule.action = match *tokens.get(index)? { "accept" => "allow", "drop" => "deny", "reject" => "reject", _ => return None }.into();
    if index + 1 != tokens.len() { return None; }
    validate_rule(&firewall_input(&rule)).ok()?;
    rule_families(&firewall_input(&rule)).ok()?;
    rule.read_only = None;
    Some(rule)
}

fn parse_firewalld_direct(raw: &str) -> Option<UnifiedFirewallRule> {
    let tokens = raw.split_whitespace().collect::<Vec<_>>();
    if tokens.len() < 6 || tokens[1] != "filter" || tokens[3] != "0" { return None; }
    let mut rule = opaque_firewalld_rule(raw, None, "direct");
    rule.family = tokens[0].into();
    rule.direction = match tokens[2] { "INPUT" => "in", "OUTPUT" => "out", "FORWARD" => "forward", _ => return None }.into();
    let mut index = 4;
    let mut seen = std::collections::HashSet::new();
    while index + 1 < tokens.len() {
        let flag = tokens[index]; let value = tokens[index + 1];
        if !seen.insert(flag) { return None; }
        match flag {
            "-p" => rule.protocol = if value == "ipv6-icmp" { "icmp" } else { value }.into(),
            "-s" => rule.source = value.into(),
            "-d" => rule.destination = value.into(),
            "-m" if value == "multiport" => {},
            "--dports" => rule.ports = value.into(),
            "-j" if index + 2 == tokens.len() => rule.action = match value { "ACCEPT" => "allow", "DROP" => "deny", "REJECT" => "reject", _ => return None }.into(),
            _ => return None,
        }
        index += 2;
    }
    if index != tokens.len() { return None; }
    validate_rule(&firewall_input(&rule)).ok()?;
    rule_families(&firewall_input(&rule)).ok()?;
    rule.read_only = None;
    Some(rule)
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
    fn firewalld_new_rules_use_the_servers_default_zone() {
        let command = command_for("firewalld", &FirewallChange { operation: "add".into(), rule: rule() }).unwrap();
        assert!(!command.contains("--zone="), "{command}");
    }

    #[test]
    fn firewalld_reads_created_rich_and_direct_rules_and_preserves_other_rules() {
        let raw = "corp (active)\n  services: ssh\n  ports: 8443/tcp\n  rich rules:\n    rule family=\"ipv4\" source address=\"192.0.2.1/32\" port port=\"60123\" protocol=\"tcp\" accept\n    rule family=\"ipv6\" protocol value=\"ipv6-icmp\" drop\n    rule family=\"ipv4\" source ipset=\"trusted\" accept\nother\n  ports: 5353/udp\n__FIREWALLD_DIRECT__\nipv4 filter OUTPUT 0 -p tcp -m multiport --dports 60124 -j ACCEPT\n";
        let (_, _, _, rules) = parse_firewalld(raw);
        assert_eq!(rules.len(), 7);
        assert!(rules[0].read_only.unwrap());
        assert_eq!(rules[2].ports, "60123");
        assert_eq!(rules[2].zone.as_deref(), Some("corp"));
        assert!(!rules[2].read_only.unwrap_or(false));
        assert_eq!(rules[3].protocol, "icmp");
        assert!(rules[4].read_only.unwrap());
        assert_eq!(rules[5].zone.as_deref(), Some("other"));
        assert_eq!(rules[6].direction, "out");
        for rule in [&rules[2], &rules[3], &rules[6]] {
            let input = firewall_input(rule);
            let delete = command_for("firewalld", &FirewallChange { operation: "delete".into(), rule: input.clone() }).unwrap();
            let original = rule.backend_ref.as_deref().unwrap().split_once(':').unwrap().1;
            assert!(delete.contains(original));
            let mut tampered = input; tampered.ports = "22".into();
            assert!(command_for("firewalld", &FirewallChange { operation: "delete".into(), rule: tampered }).is_err());
        }
        assert!(parse_firewalld_direct("ipv4 filter OUTPUT 0 -p tcp -j ACCEPT;reboot").is_none());
        assert!(parse_firewalld_direct("ipv4 filter OUTPUT 0 -p tcp -p udp -j ACCEPT").is_none());
    }

    #[test]
    fn firewalld_queries_and_restores_preserve_permanent_scope() {
        for (command, query, restored) in [
            ("sudo -n firewall-cmd --permanent --zone=corp --remove-port=22/tcp", "--query-port=22/tcp", "--add-port=22/tcp"),
            ("sudo -n firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" accept'", "--query-rich-rule=", "--add-rich-rule="),
            ("sudo -n firewall-cmd --permanent --direct --remove-rule ipv4 filter OUTPUT 0 -j DROP", "--query-rule ipv4", "--add-rule ipv4"),
        ] {
            let presence = firewalld_rule_operation(command, "query").unwrap();
            assert!(presence.contains(query));
            assert!(presence.contains("--permanent"));
            assert!(firewalld_rule_operation(command, "add").unwrap().contains(restored));
            assert!(firewalld_rule_operation(command, "remove").unwrap().contains("--remove-"));
        }
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
    fn ufw_preserves_reject_policies_and_does_not_invent_inactive_defaults() {
        let (_, incoming, outgoing, _) = parse_ufw("Status: active\nDefault: reject (incoming), deny (outgoing), disabled (routed)\n");
        assert_eq!(incoming, "reject"); assert_eq!(outgoing, "deny");
        let (enabled, incoming, outgoing, _) = parse_ufw("Status: inactive\n");
        assert!(!enabled); assert_eq!(incoming, "unknown"); assert_eq!(outgoing, "unknown");
    }

    #[test]
    fn ufw_preserves_destination_and_forward_direction_and_marks_opaque_rules_read_only() {
        let rule = parse_ufw_numbered_line("[ 4] 10.0.0.8 443/tcp ALLOW FWD 192.0.2.1 # routed").unwrap();
        assert_eq!(rule.direction, "forward"); assert_eq!(rule.destination, "10.0.0.8");
        assert_eq!(rule.ports, "443"); assert_eq!(rule.protocol, "tcp"); assert_eq!(rule.source, "192.0.2.1");
        assert!(!rule.read_only.unwrap_or(false));
        let ipv6 = parse_ufw_numbered_line("[ 5] 2001:db8::8 443/tcp (v6) ALLOW OUT Anywhere (v6)").unwrap();
        assert_eq!(ipv6.destination, "2001:db8::8"); assert_eq!(ipv6.family, "ipv6");
        assert_eq!(ipv6.source, "any"); assert_eq!(ipv6.direction, "out");
        let opaque = parse_ufw_numbered_line("[ 6] OpenSSH ALLOW IN Anywhere").unwrap();
        assert!(opaque.read_only.unwrap()); assert!(opaque.comment.contains("OpenSSH"));
        let interface = parse_ufw_numbered_line("[ 7] 443/tcp on eth0 ALLOW IN Anywhere").unwrap();
        assert!(interface.read_only.unwrap());
        let source_port = parse_ufw_numbered_line("[ 8] 443/tcp ALLOW IN 192.0.2.1 12345/tcp").unwrap();
        assert!(source_port.read_only.unwrap());
    }

    #[test]
    fn firewall_read_propagates_failures_and_prefers_the_running_backend() {
        use std::{path::PathBuf, process::Command};
        let bash = [PathBuf::from(r"C:\msys64\usr\bin\bash.exe"), PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"), PathBuf::from("/bin/bash")]
            .into_iter().find(|path| path.exists());
        let Some(bash) = bash else { eprintln!("Skipped shell integration: Bash unavailable"); return; };
        let run = |fixture: &str| Command::new(&bash).args(["-c", &format!("export PATH=/usr/bin:/bin:$PATH; id() {{ echo 0; }}; {fixture}\n{READ_COMMAND}")]).output().unwrap();
        let denied = run("ufw() { echo permission-denied >&2; return 1; }");
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("permission-denied"));
        assert!(!String::from_utf8_lossy(&denied.stdout).contains("__ROLLBACK__"));
        let denied_verbose = run("ufw() { if [ \"$*\" = status ]; then echo 'Status: active'; else echo verbose-denied >&2; return 1; fi; }");
        assert!(!denied_verbose.status.success());
        assert!(!String::from_utf8_lossy(&denied_verbose.stdout).contains("__ROLLBACK__"));
        let active = run("ufw() { echo 'Status: inactive'; }; firewall-cmd() { case \"$1\" in --state) echo running;; --get-default-zone) echo corp;; --list-all-zones) printf 'corp (active)\\n  ports: 8443/tcp\\n';; --direct) :;; *) return 1;; esac; }");
        assert!(active.status.success(), "{}", String::from_utf8_lossy(&active.stderr));
        let stdout = String::from_utf8_lossy(&active.stdout);
        assert!(stdout.starts_with("firewalld\n"), "{stdout}");
        assert!(stdout.contains("__FIREWALLD_DEFAULT__:corp"));
        let denied_firewalld = run("ufw() { echo 'Status: inactive'; }; firewall-cmd() { case \"$1\" in --state) echo running;; --get-default-zone) echo corp;; *) echo firewalld-denied >&2; return 1;; esac; }");
        assert!(!denied_firewalld.status.success());
        assert!(!String::from_utf8_lossy(&denied_firewalld.stdout).contains("__ROLLBACK__"));
    }

    #[test]
    fn sudo_authentication_errors_are_retryable_without_hiding_other_permission_failures() {
        let output = |stderr: &str| ExecOutput { stdout: String::new(), stderr: stderr.into(), exit_code: 1, duration_ms: 0 };
        assert!(matches!(firewall_read_error(&output("sudo: a password is required"), false), AppError::SudoRequired));
        assert!(matches!(firewall_read_error(&output("Sorry, try again.\nsudo: 1 incorrect password attempt"), true), AppError::SudoAuthenticationFailed(_)));
        assert!(matches!(firewall_read_error(&output("sudo: no password was provided"), true), AppError::SudoAuthenticationFailed(_)));
        for stderr in ["sudo: ufw: command not found", "user is not in the sudoers file", "ERROR: permission denied", "cannot read /etc/ufw: a password is required"] {
            assert!(matches!(firewall_read_error(&output(stderr), true), AppError::Permission(_)), "{stderr}");
        }
    }

    #[test]
    fn password_protected_firewall_read_consumes_one_secret_line_for_the_whole_script() {
        use std::{io::Write, path::PathBuf, process::{Command, Stdio}};
        let bash = [PathBuf::from(r"C:\msys64\usr\bin\bash.exe"), PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"), PathBuf::from("/bin/bash")]
            .into_iter().find(|path| path.exists());
        let Some(bash) = bash else { eprintln!("Skipped shell integration: Bash unavailable"); return; };
        let fixture = r#"export PATH=/usr/bin:/bin:$PATH
id() { if [ "$SSHOPS_FAKE_ROOT" = 1 ]; then echo 0; else echo 1000; fi; }
ufw() { if [ "$SSHOPS_FAKE_ROOT" != 1 ]; then echo denied >&2; return 1; fi; echo 'Status: active'; }
sudo() {
    [ "$1" = -S ] && [ "$2" = -p ] || return 7
    IFS= read -r supplied || return 8
    if [ "$supplied" != test-only-pass ]; then echo 'sudo: 1 incorrect password attempt' >&2; return 1; fi
    echo authenticated-once >&2
    shift 3
    export SSHOPS_FAKE_ROOT=1
    "$@"
}
export -f id ufw sudo
"#;
        let script = format!("{fixture}\n{}", firewall_read_command(true).unwrap());
        let run = |input: &[u8]| {
            let mut child = Command::new(&bash).args(["-c", &script]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            child.stdin.take().unwrap().write_all(input).unwrap();
            child.wait_with_output().unwrap()
        };
        let result = run(b"test-only-pass\n");
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        assert!(String::from_utf8_lossy(&result.stdout).starts_with("ufw\n"));
        assert_eq!(String::from_utf8_lossy(&result.stderr).matches("authenticated-once").count(), 1);
        assert!(!String::from_utf8_lossy(&result.stdout).contains("test-only-pass"));
        let denied = run(b"wrong-password\n");
        assert!(!denied.status.success());
        assert!(String::from_utf8_lossy(&denied.stderr).contains("incorrect password attempt"));
        assert!(denied.stdout.is_empty());
    }

    #[test]
    fn at_job_keeps_its_script_separate_from_sudo_stdin() {
        let command = at_schedule_command("sshops-test", "ufw reload").unwrap();
        assert!(command.starts_with("sudo -n sh -c "));
        assert!(command.contains("/run/sshops-test/committed"));
        assert!(!command.contains("| sudo"));
        assert!(!command.contains("/tmp/"));
        assert!(command.contains("/run/sshops-test/deadline"));
        assert!(!command.contains("sleep 60"));
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
        std::fs::write(root.path().join("apply-completed"), "").unwrap();
        std::fs::write(root.path().join("permanent-restore"), "true").unwrap();
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

    #[test]
    fn failed_commit_restores_permanent_and_runtime_state_in_a_real_shell() {
        use std::{path::PathBuf, process::{Command, Stdio}};
        let bash = [PathBuf::from(r"C:\msys64\usr\bin\bash.exe"), PathBuf::from(r"C:\Program Files\Git\bin\bash.exe"), PathBuf::from("/bin/bash")]
            .into_iter().find(|path| path.exists());
        let Some(bash) = bash else { eprintln!("Skipped shell integration: Bash unavailable"); return; };
        if !Command::new(&bash).args(["-c", "PATH=/usr/bin:/bin:$PATH; command -v flock"]).stdout(Stdio::null()).status().unwrap().success() {
            eprintln!("Skipped shell integration: flock unavailable"); return;
        }
        let root = tempfile::tempdir().unwrap();
        let run = |script: String| Command::new(&bash)
            .args(["-c", &format!("export PATH=/usr/bin:/bin:$PATH; {}", script.replace("/run/review-test", "."))])
            .current_dir(root.path()).stderr(Stdio::null()).status().unwrap().success();
        std::fs::write(root.path().join("deadline"), (chrono::Utc::now().timestamp() + 60).to_string()).unwrap();

        // A failed/partial apply must never become eligible for commit.
        assert!(!run(locked_apply_command("review-test", "echo partial > runtime; false").unwrap()));
        assert!(!root.path().join("apply-completed").exists());
        assert!(!run(locked_commit_command("review-test", "echo bad > permanent").unwrap()));
        assert!(!root.path().join("permanent").exists());
        assert!(!run(locked_apply_command("review-test", "echo duplicate > runtime").unwrap()));

        // Simulate a successful apply and a two-rule commit that only writes
        // its first permanent rule. Rollback restores the original permanent
        // presence, including rules that already existed before this plan.
        std::fs::write(root.path().join("apply-completed"), "").unwrap();
        std::fs::write(root.path().join("permanent"), "original\n").unwrap();
        std::fs::write(root.path().join("permanent-restore"), "echo original > permanent").unwrap();
        assert!(!run(locked_commit_command("review-test", "echo partial > permanent && false").unwrap()));
        assert!(!root.path().join("committed").exists());
        assert!(run(locked_rollback_command("review-test", "echo original > runtime").unwrap()));
        assert_eq!(std::fs::read_to_string(root.path().join("permanent")).unwrap().trim(), "original");
        assert_eq!(std::fs::read_to_string(root.path().join("runtime")).unwrap().trim(), "original");
        assert!(root.path().join("rolled-back").exists());
        assert!(!run(locked_commit_command("review-test", "echo bad > permanent").unwrap()));

        // Failure to restore permanent config must not skip live restoration
        // (which may be needed to recover SSH), or claim full rollback success.
        std::fs::remove_file(root.path().join("rolled-back")).unwrap();
        std::fs::write(root.path().join("permanent-restore"), "false").unwrap();
        std::fs::write(root.path().join("runtime"), "changed").unwrap();
        assert!(!run(locked_rollback_command("review-test", "echo original > runtime").unwrap()));
        assert_eq!(std::fs::read_to_string(root.path().join("runtime")).unwrap().trim(), "original");
        assert!(!root.path().join("rolled-back").exists());
    }
}
