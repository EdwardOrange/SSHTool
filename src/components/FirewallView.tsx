import AddRounded from "@mui/icons-material/AddRounded";
import CheckCircleRounded from "@mui/icons-material/CheckCircleRounded";
import DeleteOutlineRounded from "@mui/icons-material/DeleteOutlineRounded";
import GppGoodRounded from "@mui/icons-material/GppGoodRounded";
import LockClockRounded from "@mui/icons-material/LockClockRounded";
import RefreshRounded from "@mui/icons-material/RefreshRounded";
import WarningAmberRounded from "@mui/icons-material/WarningAmberRounded";
import { Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, Divider, FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch, Table, TableBody, TableCell, TableHead, TableRow, TextField, Typography } from "@mui/material";
import React from "react";
import { api } from "../api";
import { useAppStore } from "../store";
import type { FirewallPlan, FirewallRuleInput, HostProfile } from "../types";
import { formatError } from "../utils";

const blankRule: FirewallRuleInput = { direction: "in", family: "both", protocol: "tcp", ports: "", source: "any", destination: "any", action: "allow", enabled: true, comment: "" };
type SudoAction = { kind: "read" } | { kind: "plan"; operation: "add" | "delete"; rule: FirewallRuleInput } | { kind: "apply" | "commit" | "rollback" };

export default function FirewallView({ host }: { host: HostProfile }) {
  const firewall = useAppStore((s) => s.firewall[host.id]); const setFirewall = useAppStore((s) => s.setFirewall);
  const [planning, setPlanning] = React.useState(false);
  const planningLock = React.useRef(false);
  const readingLock = React.useRef(false);
  const applyingLock = React.useRef(false);
  const [reading, setReading] = React.useState(false);
  const generation = React.useRef(0);
  const [verified, setVerified] = React.useState(false);
  const [sudoAction, setSudoAction] = React.useState<SudoAction>();
  const sudoCredentials = React.useRef({ password: "", remember: false });
  const [rule, setRule] = React.useState(blankRule); const [editorOpen, setEditorOpen] = React.useState(false); const [plan, setPlan] = React.useState<FirewallPlan>(); const [error, setError] = React.useState(""); const [applying, setApplying] = React.useState(false); const [deadline, setDeadline] = React.useState<string>(); const [remainingSeconds, setRemainingSeconds] = React.useState(0); const [sudoOpen, setSudoOpen] = React.useState(false); const [sudoPassword, setSudoPassword] = React.useState(""); const [rememberSudo, setRememberSudo] = React.useState(false);
  React.useEffect(() => {
    generation.current += 1; setPlan(undefined); setDeadline(undefined); setSudoOpen(false); setSudoAction(undefined); setSudoPassword(""); setRememberSudo(false); setError("");
    sudoCredentials.current = { password: "", remember: false };
    readingLock.current = false; planningLock.current = false; applyingLock.current = false;
    setReading(false); setPlanning(false); setApplying(false); setVerified(false); setEditorOpen(false);
    return () => { generation.current += 1; };
  }, [host.id, host.status]);
  const handleFailure = React.useCallback((reason: unknown, action: SudoAction) => {
    setError(formatError(reason));
    if ((reason as { kind?: string } | null)?.kind === "sudoRequired") {
      setSudoAction(action); setSudoOpen(true);
    }
  }, []);
  const acceptCredentials = React.useCallback((password?: string, remember = false) => {
    if (password) sudoCredentials.current = { password, remember };
    setSudoAction(undefined); setSudoOpen(false);
  }, []);
  const refresh = React.useCallback(async (password = sudoCredentials.current.password || undefined, remember = sudoCredentials.current.remember) => {
    if (host.status !== "connected" || readingLock.current) return;
    const current = generation.current;
    readingLock.current = true; setReading(true); setError("");
    try {
      const state = await api.firewallRead(host.id, password, remember);
      if (current === generation.current) { setFirewall(state); acceptCredentials(password, remember); }
    } catch (e) { if (current === generation.current) handleFailure(e, { kind: "read" }); }
    finally { if (current === generation.current) { readingLock.current = false; setReading(false); } }
  }, [host.id, host.status, setFirewall, handleFailure, acceptCredentials]); React.useEffect(() => { void refresh(); }, [refresh]);
  React.useEffect(() => { if (!deadline) { setRemainingSeconds(0); return; } const update = () => setRemainingSeconds(Math.max(0, Math.ceil((Date.parse(deadline) - Date.now()) / 1000))); update(); const timer = window.setInterval(update, 250); return () => window.clearInterval(timer); }, [deadline]);
  const createPlan = async (operation: "add" | "delete" = "add", selectedRule = rule, password = sudoCredentials.current.password || undefined, remember = sudoCredentials.current.remember) => {
    if (planningLock.current || host.status !== "connected") return;
    const current = generation.current;
    planningLock.current = true; setPlanning(true); setError("");
    try {
      const next = await api.firewallPlan(host.id, selectedRule, operation, password, remember);
      if (current === generation.current) { setPlan(next); setEditorOpen(false); acceptCredentials(password, remember); }
    } catch (e) { if (current === generation.current) handleFailure(e, { kind: "plan", operation, rule: selectedRule }); }
    finally { if (current === generation.current) { planningLock.current = false; setPlanning(false); } }
  };
  const apply = async (password = sudoCredentials.current.password || undefined, remember = sudoCredentials.current.remember) => {
    if (!plan || applyingLock.current) return;
    const current = generation.current;
    applyingLock.current = true; setApplying(true); setError("");
    try {
      const result = await api.firewallApply(plan.id, password, remember);
      if (current !== generation.current) return;
      setVerified(result.verified); setDeadline(result.rollbackDeadline); acceptCredentials(password, remember);
    } catch (e) {
      if (current !== generation.current) return;
      handleFailure(e, { kind: "apply" });
    } finally { if (current === generation.current) { applyingLock.current = false; setApplying(false); } }
  };
  const sudoBusy = reading || planning || applying;
  const runPlanAction = async (kind: "commit" | "rollback", password = sudoCredentials.current.password || undefined, remember = sudoCredentials.current.remember) => {
    if (!plan || applyingLock.current || (kind === "commit" && !verified)) return;
    const current = generation.current;
    applyingLock.current = true; setApplying(true); setError("");
    try {
      if (kind === "commit") await api.firewallCommit(plan.id, password);
      else await api.firewallRollback(plan.id, password);
      if (current !== generation.current) return;
      acceptCredentials(password, remember); setPlan(undefined); setDeadline(undefined); setSudoPassword("");
      void refresh(password, remember);
    } catch (e) {
      if (current === generation.current) handleFailure(e, { kind });
    } finally {
      if (current === generation.current) { applyingLock.current = false; setApplying(false); }
    }
  };
  const cancelSudo = () => { if (sudoBusy) return; setSudoOpen(false); setSudoAction(undefined); setSudoPassword(""); };
  const retrySudo = () => {
    if (!sudoAction || !sudoPassword || sudoBusy) return;
    if (sudoAction.kind === "read") void refresh(sudoPassword, rememberSudo);
    else if (sudoAction.kind === "plan") void createPlan(sudoAction.operation, sudoAction.rule, sudoPassword, rememberSudo);
    else if (sudoAction.kind === "apply") void apply(sudoPassword, rememberSudo);
    else void runPlanAction(sudoAction.kind, sudoPassword, rememberSudo);
  };
  const commit = () => void runPlanAction("commit");
  const rollback = () => void runPlanAction("rollback");
  const deadlineActive = Boolean(deadline && remainingSeconds > 0);
  const closePlan = () => { if (applying || deadlineActive) return; setPlan(undefined); setDeadline(undefined); setSudoPassword(""); void refresh(); };
  if (host.status !== "connected") return <Alert severity="info">请先连接服务器，再查看和管理防火墙。</Alert>;
  return <Box sx={{ overflowY: "auto", height: "100%", pr: .5 }}><Stack direction="row" alignItems="center" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 3 }}><GppGoodRounded color={firewall?.enabled ? "success" : "disabled"}/><Typography variant="h6">系统防火墙</Typography>{firewall && <><Chip size="small" label={firewall.backend}/><Chip size="small" color={firewall.enabled ? "success" : "default"} label={firewall.enabled ? "运行中" : "已停止"}/></>}<Box sx={{ flex: 1 }}/><IconButton aria-label="刷新防火墙" disabled={reading} onClick={() => void refresh()}><RefreshRounded/></IconButton><Button variant="contained" startIcon={<AddRounded/>} onClick={() => { setRule(blankRule); setEditorOpen(true); }} disabled={reading || planning || !firewall?.rollbackAvailable}>添加规则</Button></Stack>
    {error && <Alert severity="error" onClose={() => setError("")} sx={{ mb: 1.5 }}>{error}</Alert>}
    {firewall && !firewall.rollbackAvailable && <Alert severity="warning" sx={{ mb: 1.5 }}>服务器没有可靠的自动回滚机制，写入操作已禁用。</Alert>}
    {firewall && <Stack direction={{ xs: "column", md: "row" }} spacing={1.5} sx={{ mb: 1.5 }}><Info label="默认入站" value={firewall.defaultInbound.toUpperCase()}/><Info label="默认出站" value={firewall.defaultOutbound.toUpperCase()}/><Info label="回滚" value={firewall.rollbackAvailable ? "可用 · 60 秒" : "不可用"}/><Info label="规则数" value={String(firewall.rules.length)}/></Stack>}
    <Paper variant="outlined" sx={{ overflowX: "auto" }}><Table><TableHead><TableRow><TableCell>状态</TableCell><TableCell>方向</TableCell><TableCell>动作</TableCell><TableCell>协议</TableCell><TableCell>端口</TableCell><TableCell>来源</TableCell><TableCell>备注</TableCell><TableCell align="right">操作</TableCell></TableRow></TableHead><TableBody>{firewall?.rules.map((item) => <TableRow key={item.id} hover><TableCell><Chip size="small" variant="outlined" label={item.enabled ? "已启用" : "已禁用"} color={item.enabled ? "success" : "default"}/></TableCell><TableCell>{item.direction === "in" ? "入站" : item.direction === "out" ? "出站" : "转发"}</TableCell><TableCell><Chip size="small" label={item.action.toUpperCase()} color={item.action === "allow" ? "success" : "error"} variant="outlined"/></TableCell><TableCell className="mono">{item.protocol}</TableCell><TableCell className="mono">{item.ports || "any"}</TableCell><TableCell className="mono">{item.source}</TableCell><TableCell>{item.comment}{item.readOnly && <Chip size="small" label="只读" sx={{ ml: 1 }}/>}</TableCell><TableCell align="right"><IconButton aria-label={`删除规则 ${item.ports || item.id}`} size="small" color="error" disabled={reading || planning || item.readOnly || !firewall?.rollbackAvailable} onClick={() => createPlan("delete", item)}><DeleteOutlineRounded fontSize="small"/></IconButton></TableCell></TableRow>)}</TableBody></Table></Paper>
    <Dialog open={editorOpen} onClose={planning ? undefined : () => setEditorOpen(false)} fullWidth maxWidth="sm"><DialogTitle>添加防火墙规则</DialogTitle><DialogContent>{error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}<Stack spacing={2} sx={{ mt: 1 }}><Stack direction="row" spacing={1.5}><TextField select fullWidth label="方向" value={rule.direction} onChange={(e) => setRule({ ...rule, direction: e.target.value as "in" | "out" })}><MenuItem value="in">入站</MenuItem><MenuItem value="out">出站</MenuItem></TextField><TextField select fullWidth label="动作" value={rule.action} onChange={(e) => setRule({ ...rule, action: e.target.value as FirewallRuleInput["action"] })}><MenuItem value="allow">允许</MenuItem><MenuItem value="deny">丢弃</MenuItem><MenuItem value="reject">拒绝</MenuItem></TextField></Stack><Stack direction="row" spacing={1.5}><TextField select fullWidth label="协议" value={rule.protocol} onChange={(e) => setRule({ ...rule, protocol: e.target.value as FirewallRuleInput["protocol"] })}><MenuItem value="tcp">TCP</MenuItem><MenuItem value="udp">UDP</MenuItem><MenuItem value="icmp">ICMP</MenuItem><MenuItem value="any">任意</MenuItem></TextField><TextField fullWidth label="端口或范围" placeholder="80,443 或 8000:8100" value={rule.ports} onChange={(e) => setRule({ ...rule, ports: e.target.value })}/></Stack><TextField fullWidth label="来源 CIDR" value={rule.source} onChange={(e) => setRule({ ...rule, source: e.target.value })}/><TextField fullWidth label="备注" value={rule.comment} onChange={(e) => setRule({ ...rule, comment: e.target.value })}/><FormControlLabel control={<Switch checked={rule.family === "both"} onChange={(e) => setRule({ ...rule, family: e.target.checked ? "both" : "ipv4" })}/>} label="同时应用 IPv4 和 IPv6"/></Stack></DialogContent><DialogActions><Button disabled={planning} onClick={() => setEditorOpen(false)}>取消</Button><Button variant="contained" disabled={planning} onClick={() => createPlan()}>生成计划</Button></DialogActions></Dialog>
    <Dialog open={!!plan} onClose={closePlan} fullWidth maxWidth="md"><DialogTitle><Stack direction="row" alignItems="center" spacing={1}><LockClockRounded color="warning"/>防火墙安全变更计划</Stack></DialogTitle><DialogContent>{error && !sudoOpen && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}{plan && <Stack spacing={2}><Alert severity={plan.risk === "high" ? "error" : "warning"}>{plan.summary}</Alert><Paper variant="outlined" sx={{ p: 1.5, bgcolor: "#0A0E14", color: "#D8DEE9" }}>{plan.commands.map((command, index) => <Typography key={index} className="mono" variant="body2">$ {command}</Typography>)}</Paper>{plan.warnings.map((warning, index) => <Stack key={index} direction="row" spacing={1}><WarningAmberRounded color="warning" fontSize="small"/><Typography variant="body2">{warning}</Typography></Stack>)}<Divider/>{deadlineActive ? <Alert icon={<CheckCircleRounded/>} severity={verified ? "success" : "error"}>{verified ? "SSH 验证成功" : "SSH 验证未通过，无法保留更改"}，剩余 {remainingSeconds} 秒。请在截止时间前保留更改，否则服务器将自动回滚。</Alert> : deadline ? <Alert severity="warning">回滚截止时间已到，结果状态未知。请刷新防火墙状态后再决定下一步。</Alert> : <Typography variant="body2" color="text.secondary">应用前会保存快照并建立自动回滚，状态哈希：<span className="mono">{plan.stateHash.slice(0, 16)}</span></Typography>}</Stack>}</DialogContent><DialogActions>{deadline && !deadlineActive ? <Button variant="contained" disabled={applying} onClick={closePlan}>关闭并刷新状态</Button> : deadline ? <><Button color="error" onClick={rollback} disabled={!deadlineActive || applying}>立即回滚</Button><Button variant="contained" color="success" onClick={commit} disabled={!deadlineActive || applying || !verified}>保留更改</Button></> : <><Button onClick={() => setPlan(undefined)} disabled={applying}>取消</Button><Button variant="contained" color="warning" disabled={applying} onClick={() => apply()}>{applying ? "正在执行…" : "确认并执行"}</Button></>}</DialogActions></Dialog>
    <Dialog open={sudoOpen} onClose={cancelSudo} fullWidth maxWidth="xs"><DialogTitle>需要 sudo 密码</DialogTitle><DialogContent>{error && <Alert severity="error" sx={{ mt: 1 }}>{error}</Alert>}<Stack spacing={2} sx={{ mt: 1 }}><Typography variant="body2">{sudoAction?.kind === "read" ? "读取防火墙状态" : sudoAction?.kind === "plan" ? "生成防火墙计划" : sudoAction?.kind === "commit" ? "保留防火墙更改" : sudoAction?.kind === "rollback" ? "回滚防火墙更改" : "应用防火墙计划"}需要 sudo 权限。</Typography><Alert severity="info">密码不会写入命令记录；勾选下方选项后会保存到 Windows Credential Manager。</Alert><TextField autoFocus fullWidth type="password" label="sudo 密码" value={sudoPassword} onChange={(e) => setSudoPassword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && retrySudo()}/><FormControlLabel control={<Switch checked={rememberSudo} onChange={(e) => setRememberSudo(e.target.checked)}/>} label="安全记住到 Windows Credential Manager"/></Stack></DialogContent><DialogActions><Button onClick={cancelSudo} disabled={sudoBusy}>取消</Button><Button variant="contained" onClick={retrySudo} disabled={!sudoPassword || sudoBusy}>继续执行</Button></DialogActions></Dialog>
  </Box>;
}
function Info({ label, value }: { label: string; value: string }) { return <Paper variant="outlined" sx={{ flex: 1, p: 1.5 }}><Typography variant="caption" color="text.secondary">{label}</Typography><Typography variant="h6">{value}</Typography></Paper>; }
