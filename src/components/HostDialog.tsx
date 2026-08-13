import { Dialog, DialogActions, DialogContent, DialogTitle, Button, FormControlLabel, Grid, MenuItem, Switch, TextField } from "@mui/material";
import React from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAppStore } from "../store";
import type { AuthMethod, HostDraft } from "../types";

export default function HostDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { t } = useTranslation(); const upsertHost = useAppStore((s) => s.upsertHost);
  const [draft, setDraft] = React.useState<HostDraft>({ name: "", hostname: "", port: 22, username: "root", groupName: "默认", tags: [], favorite: false, authMethod: "password" });
  const [saving, setSaving] = React.useState(false); const [error, setError] = React.useState("");
  const update = <K extends keyof HostDraft>(key: K, value: HostDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));
  const save = async () => { if (!draft.name.trim() || !draft.hostname.trim() || !draft.username.trim()) { setError("请填写名称、主机和用户名"); return; } setSaving(true); try { upsertHost(await api.hostsUpsert(draft)); onClose(); setDraft({ name: "", hostname: "", port: 22, username: "root", groupName: "默认", tags: [], favorite: false, authMethod: "password" }); } catch (e) { setError(String(e)); } finally { setSaving(false); } };
  return <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm"><DialogTitle>{t("addServer")}</DialogTitle><DialogContent sx={{ pt: 3, overflowY: "auto" }}><Grid container spacing={2} sx={{ mt: .5 }}>
    <Grid size={{ xs: 12, sm: 7 }}><TextField fullWidth label="显示名称" value={draft.name} onChange={(e) => update("name", e.target.value)} /></Grid><Grid size={{ xs: 12, sm: 5 }}><TextField fullWidth label={t("group")} value={draft.groupName} onChange={(e) => update("groupName", e.target.value)} /></Grid>
    <Grid size={{ xs: 12, sm: 9 }}><TextField fullWidth label={t("host")} placeholder="server.example.com" value={draft.hostname} onChange={(e) => update("hostname", e.target.value)} /></Grid><Grid size={{ xs: 12, sm: 3 }}><TextField fullWidth type="number" label={t("port")} value={draft.port} onChange={(e) => update("port", Number(e.target.value))} /></Grid>
    <Grid size={{ xs: 12, sm: 6 }}><TextField fullWidth label={t("username")} value={draft.username} onChange={(e) => update("username", e.target.value)} /></Grid><Grid size={{ xs: 12, sm: 6 }}><TextField select fullWidth label={t("auth")} value={draft.authMethod} onChange={(e) => update("authMethod", e.target.value as AuthMethod)}><MenuItem value="password">密码</MenuItem><MenuItem value="key">私钥</MenuItem><MenuItem value="agent">SSH Agent</MenuItem><MenuItem value="keyboardInteractive">键盘交互 / MFA</MenuItem></TextField></Grid>
    {draft.authMethod === "password" && <><Grid size={12}><TextField fullWidth type="password" label="SSH 密码" value={draft.password || ""} onChange={(e) => update("password", e.target.value)} /></Grid><Grid size={12}><FormControlLabel control={<Switch checked={draft.rememberPassword || false} onChange={(e) => update("rememberPassword", e.target.checked)} />} label="安全保存到 Windows Credential Manager" /></Grid></>}
    {draft.authMethod === "key" && <Grid size={12}><TextField fullWidth label="私钥路径" placeholder="C:\\Users\\me\\.ssh\\id_ed25519" value={draft.privateKeyPath || ""} onChange={(e) => update("privateKeyPath", e.target.value)} /></Grid>}
    <Grid size={12}><TextField fullWidth label="标签" helperText="用逗号分隔" onChange={(e) => update("tags", e.target.value.split(",").map((x) => x.trim()).filter(Boolean))} /></Grid>
  </Grid>{error && <TextField fullWidth error value={error} sx={{ mt: 2 }} slotProps={{ input: { readOnly: true } }} />}</DialogContent><DialogActions><Button onClick={onClose}>{t("cancel")}</Button><Button disabled={saving} variant="contained" onClick={save}>{t("save")}</Button></DialogActions></Dialog>;
}
