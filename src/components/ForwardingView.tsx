import AddRounded from "@mui/icons-material/AddRounded";
import AltRouteRounded from "@mui/icons-material/AltRouteRounded";
import DeleteOutlineRounded from "@mui/icons-material/DeleteOutlineRounded";
import RefreshRounded from "@mui/icons-material/RefreshRounded";
import { Alert, Box, Button, Chip, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, MenuItem, Paper, Stack, Switch, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography } from "@mui/material";
import React from "react";
import { api } from "../api";
import type { ForwardingProfile, HostProfile } from "../types";
import { formatError } from "../utils";

const emptyDraft = (hostId: string): ForwardingProfile => ({ id: "", hostId, name: "", kind: "local", bindAddress: "127.0.0.1", bindPort: 8080, targetHost: "127.0.0.1", targetPort: 80, active: false, status: "stopped" });

export default function ForwardingView({ host }: { host: HostProfile }) {
  const [profiles, setProfiles] = React.useState<ForwardingProfile[]>([]); const [adding, setAdding] = React.useState(false); const [error, setError] = React.useState(""); const [pending, setPending] = React.useState<string[]>([]); const [deleteTarget, setDeleteTarget] = React.useState<ForwardingProfile>();
  const [draft, setDraft] = React.useState<ForwardingProfile>(() => emptyDraft(host.id));
  const [saving, setSaving] = React.useState(false);
  const [loading, setLoading] = React.useState(true);
  const [loaded, setLoaded] = React.useState(false);
  const [reload, setReload] = React.useState(0);
  const savingLock = React.useRef(false);
  const pendingLocks = React.useRef(new Set<string>());
  const generation = React.useRef(0);
  React.useEffect(() => { setAdding(false); setDraft(emptyDraft(host.id)); }, [host.id]);
  React.useEffect(() => {
    const current = ++generation.current;
    savingLock.current = false; pendingLocks.current.clear();
    setProfiles([]); setError(""); setPending([]); setSaving(false); setLoading(true); setLoaded(false); setDeleteTarget(undefined);
    api.forwardingList(host.id).then((items) => { if (current === generation.current) { setProfiles(items); setLoaded(true); } })
      .catch((e) => { if (current === generation.current) setError(formatError(e)); })
      .finally(() => { if (current === generation.current) setLoading(false); });
    return () => { generation.current += 1; };
  }, [host.id, host.status, reload]);
  const save = async () => {
    if (savingLock.current || loading || !loaded) return;
    if (!draft.name.trim() || !draft.bindAddress.trim() || !Number.isInteger(draft.bindPort) || draft.bindPort < 1 || draft.bindPort > 65535 || (draft.kind !== "dynamic" && (!draft.targetHost?.trim() || !Number.isInteger(draft.targetPort) || !draft.targetPort || draft.targetPort < 1 || draft.targetPort > 65535))) { setError("请填写名称、地址及有效的整数端口（1–65535）"); return; }
    const current = generation.current;
    savingLock.current = true; setSaving(true); setError("");
    try {
      const saved = await api.forwardingUpsert({ ...draft, name: draft.name.trim(), bindAddress: draft.bindAddress.trim(), targetHost: draft.targetHost?.trim(), id: draft.id || crypto.randomUUID(), hostId: host.id });
      if (current !== generation.current) return;
      setProfiles((items) => [...items.filter((item) => item.id !== saved.id), saved]); setAdding(false); setDraft(emptyDraft(host.id));
    } catch (e) { if (current === generation.current) setError(formatError(e)); }
    finally { if (current === generation.current) { savingLock.current = false; setSaving(false); } }
  };
  const toggle = async (profile: ForwardingProfile) => {
    if (pendingLocks.current.has(profile.id) || loading) return;
    const current = generation.current;
    pendingLocks.current.add(profile.id);
    setError(""); setPending((items) => [...items, profile.id]);
    try {
      const updated = await api.forwardingToggle(profile.id, !profile.active);
      if (current === generation.current && updated) setProfiles((items) => items.map((item) => item.id === updated.id ? updated : item));
    } catch (e) {
      if (current === generation.current) { setError(formatError(e)); setProfiles((items) => items.map((item) => item.id === profile.id ? { ...profile, status: profile.active ? profile.status : "error", lastError: formatError(e) } : item)); }
    } finally { if (current === generation.current) { pendingLocks.current.delete(profile.id); setPending((items) => items.filter((id) => id !== profile.id)); } }
  };
  const remove = async (profile: ForwardingProfile) => { setDeleteTarget(profile); };
  const performRemove = async () => { const profile = deleteTarget; const current = generation.current; if (!profile || pendingLocks.current.has(profile.id)) return; pendingLocks.current.add(profile.id); setDeleteTarget(undefined); setError(""); setPending((items) => [...items, profile.id]); try { await api.forwardingDelete(profile.id); if (current === generation.current) setProfiles((items) => items.filter((item) => item.id !== profile.id)); } catch (e) { if (current === generation.current) setError(formatError(e)); } finally { if (current === generation.current) { pendingLocks.current.delete(profile.id); setPending((items) => items.filter((id) => id !== profile.id)); } } };
  return <Stack sx={{ height: "100%", overflow: "auto" }} spacing={1.5}><Stack direction="row" alignItems="center"><AltRouteRounded color="primary" sx={{ mr: 1 }}/><Typography variant="h6">端口转发</Typography><Box sx={{ flex: 1 }}/><IconButton aria-label="刷新端口转发" disabled={loading || saving || pending.length > 0} onClick={() => setReload((value) => value + 1)}><RefreshRounded/></IconButton><Button startIcon={<AddRounded/>} variant="contained" disabled={loading || saving || !loaded} onClick={() => setAdding(!adding)}>{adding ? "收起表单" : "新建转发"}</Button></Stack>{error && <Alert severity="error" onClose={() => setError("")}>{error}</Alert>}
    {adding && <Paper variant="outlined" sx={{ p: 2 }}><Box sx={{ display: "grid", gridTemplateColumns: { xs: "1fr", sm: "repeat(2, minmax(0, 1fr))", xl: "repeat(3, minmax(0, 1fr))" }, gap: 2 }}><TextField size="small" label="名称" value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })}/><TextField size="small" select label="类型" value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value as ForwardingProfile["kind"] })}><MenuItem value="local">本地 -L</MenuItem><MenuItem value="remote">远程 -R</MenuItem><MenuItem value="dynamic">SOCKS -D</MenuItem></TextField><TextField size="small" label="监听地址" value={draft.bindAddress} onChange={(e) => setDraft({ ...draft, bindAddress: e.target.value })}/><TextField size="small" type="number" label="监听端口" value={draft.bindPort} onChange={(e) => setDraft({ ...draft, bindPort: Number(e.target.value) })}/>{draft.kind !== "dynamic" && <><TextField size="small" label="目标主机" value={draft.targetHost} onChange={(e) => setDraft({ ...draft, targetHost: e.target.value })}/><TextField size="small" type="number" label="目标端口" value={draft.targetPort} onChange={(e) => setDraft({ ...draft, targetPort: Number(e.target.value) })}/></>}<Button disabled={saving || loading || !loaded} variant="contained" onClick={save}>{saving ? "正在保存…" : "保存"}</Button></Box></Paper>}
    <Paper variant="outlined" sx={{ overflowX: "auto", flexShrink: 0 }}><Table><TableHead><TableRow><TableCell>状态</TableCell><TableCell>名称</TableCell><TableCell>类型</TableCell><TableCell>监听</TableCell><TableCell>目标</TableCell><TableCell>等价命令</TableCell><TableCell /></TableRow></TableHead><TableBody>{profiles.map((profile) => { const busy = pending.includes(profile.id); return <TableRow key={profile.id} hover><TableCell><Stack direction="row" alignItems="center" spacing={1}><Switch slotProps={{ input: { "aria-label": `${profile.active ? "停止" : "启动"}${profile.name}` } }} checked={profile.active} disabled={busy || (!profile.active && host.status !== "connected")} onChange={() => toggle(profile)}/>{statusChip(profile, busy)}</Stack></TableCell><TableCell>{profile.name}</TableCell><TableCell><Chip size="small" label={profile.kind.toUpperCase()}/></TableCell><TableCell className="mono">{profile.bindAddress}:{profile.bindPort}</TableCell><TableCell className="mono">{profile.kind === "dynamic" ? "SOCKS5" : `${profile.targetHost}:${profile.targetPort}`}</TableCell><TableCell className="mono">ssh -{profile.kind === "local" ? "L" : profile.kind === "remote" ? "R" : "D"} {profile.bindPort}{profile.kind !== "dynamic" ? `:${profile.targetHost}:${profile.targetPort}` : ""}</TableCell><TableCell><IconButton aria-label={`删除转发 ${profile.name}`} color="error" onClick={() => remove(profile)} disabled={busy}><DeleteOutlineRounded/></IconButton></TableCell></TableRow>; })}{profiles.length === 0 && <TableRow><TableCell colSpan={7}><Typography color="text.secondary" textAlign="center" sx={{ py: 5 }}>{loading ? "正在加载转发配置…" : loaded ? "尚未创建端口转发" : "未能读取转发配置，请刷新重试"}</Typography></TableCell></TableRow>}</TableBody></Table></Paper>
    <Dialog open={Boolean(deleteTarget)} onClose={() => setDeleteTarget(undefined)}><DialogTitle>删除端口转发？</DialogTitle><DialogContent><Typography>将删除“{deleteTarget?.name || "未命名转发"}”配置；正在运行的转发会先停止。</Typography></DialogContent><DialogActions><Button onClick={() => setDeleteTarget(undefined)}>取消</Button><Button color="error" variant="contained" onClick={() => void performRemove()}>删除</Button></DialogActions></Dialog>
  </Stack>;
}
function statusChip(profile: ForwardingProfile, busy: boolean) { const status = busy ? "starting" : (profile.status || (profile.active ? "active" : "stopped")); if (status === "active") return <Chip size="small" color="success" label="运行中"/>; if (status === "error") return <Tooltip title={profile.lastError || "启动失败"}><Chip size="small" color="error" label="启动失败"/></Tooltip>; if (status === "starting") return <Chip size="small" color="primary" icon={<CircularProgress size={13}/>} label={profile.active ? "正在停止" : "正在启动"}/>; return <Chip size="small" variant="outlined" label="已停止"/>; }
