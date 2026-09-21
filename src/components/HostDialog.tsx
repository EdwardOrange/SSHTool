import { Alert, Dialog, DialogActions, DialogContent, DialogTitle, Button, FormControlLabel, Grid, MenuItem, Switch, TextField } from "@mui/material";
import React from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAppStore } from "../store";
import type { AuthMethod, HostDraft, HostProfile } from "../types";
import { formatError } from "../utils";

const emptyDraft = (): HostDraft => ({ name: "", hostname: "", port: 22, username: "root", groupName: "默认", tags: [], favorite: false, authMethod: "password" });

export default function HostDialog({ open, onClose, initialHost }: { open: boolean; onClose: () => void; initialHost?: HostProfile }) {
  const { t } = useTranslation(); const upsertHost = useAppStore((s) => s.upsertHost);
  const [draft, setDraft] = React.useState<HostDraft>(emptyDraft);
  const [tagsText, setTagsText] = React.useState("");
  const [credentialsChanged, setCredentialsChanged] = React.useState(false);
  const [saving, setSaving] = React.useState(false); const [error, setError] = React.useState("");
  React.useEffect(() => {
    if (!open) return;
    setError("");
    setCredentialsChanged(false);
    setTagsText((initialHost?.tags || []).join(", "));
    setDraft(initialHost ? { id: initialHost.id, name: initialHost.name, hostname: initialHost.hostname, port: initialHost.port, username: initialHost.username, groupName: initialHost.groupName, tags: initialHost.tags, favorite: initialHost.favorite, authMethod: initialHost.authMethod, credentialId: initialHost.credentialId, privateKeyPath: initialHost.privateKeyPath, jumpHosts: initialHost.jumpHosts, hostKeyFingerprint: initialHost.hostKeyFingerprint, rememberPassword: Boolean(initialHost.credentialId) } : emptyDraft());
  }, [open, initialHost]);
  const update = <K extends keyof HostDraft>(key: K, value: HostDraft[K]) => {
    if ((key === "hostname" || key === "port" || key === "username") && draft[key] !== value) {
      if (initialHost || draft.password || draft.credentialId) setCredentialsChanged(true);
      setDraft((d) => ({ ...d, [key]: value, password: undefined, credentialId: undefined, rememberPassword: false }));
    } else setDraft((d) => ({ ...d, [key]: value }));
  };
  const changeAuthentication = (authMethod: AuthMethod) => setDraft((current) => current.authMethod === authMethod ? current : { ...current, authMethod, password: undefined, credentialId: undefined, rememberPassword: false });
  const changePrivateKeyPath = (privateKeyPath: string) => setDraft((current) => current.privateKeyPath === privateKeyPath ? current : { ...current, privateKeyPath, password: undefined, credentialId: undefined, rememberPassword: false });
  const save = async () => { if (saving) return; if (!draft.name.trim() || !draft.hostname.trim() || !draft.username.trim()) { setError("请填写名称、主机和用户名"); return; } if (!Number.isInteger(draft.port) || draft.port < 1 || draft.port > 65535) { setError("端口必须在 1–65535 之间"); return; } if (draft.authMethod === "key" && !draft.privateKeyPath?.trim()) { setError("请填写私钥路径"); return; } setSaving(true); try { upsertHost(await api.hostsUpsert({ ...draft, tags: tagsText.split(",").map((tag) => tag.trim()).filter(Boolean) })); onClose(); setDraft(emptyDraft()); } catch (e) { setError(formatError(e)); } finally { setSaving(false); } };
  return <Dialog open={open} onClose={saving ? undefined : onClose} fullWidth maxWidth="sm"><DialogTitle>{initialHost ? "编辑服务器" : t("addServer")}</DialogTitle><DialogContent sx={{ pt: 3, overflowY: "auto" }}><Grid container spacing={2} sx={{ mt: .5 }}>
    <Grid size={{ xs: 12, sm: 7 }}><TextField autoFocus required fullWidth label="显示名称" value={draft.name} onChange={(e) => update("name", e.target.value)} /></Grid><Grid size={{ xs: 12, sm: 5 }}><TextField fullWidth label={t("group")} value={draft.groupName} onChange={(e) => update("groupName", e.target.value)} /></Grid>
    <Grid size={{ xs: 12, sm: 9 }}><TextField fullWidth label={t("host")} placeholder="server.example.com" value={draft.hostname} onChange={(e) => update("hostname", e.target.value)} /></Grid><Grid size={{ xs: 12, sm: 3 }}><TextField fullWidth type="number" label={t("port")} value={draft.port} onChange={(e) => update("port", Number(e.target.value))} /></Grid>
    <Grid size={{ xs: 12, sm: 6 }}><TextField fullWidth label={t("username")} value={draft.username} onChange={(e) => update("username", e.target.value)} /></Grid><Grid size={{ xs: 12, sm: 6 }}><TextField select fullWidth label={t("auth")} value={draft.authMethod} onChange={(e) => changeAuthentication(e.target.value as AuthMethod)}><MenuItem value="password">密码</MenuItem><MenuItem value="key">私钥</MenuItem><MenuItem value="agent">SSH Agent</MenuItem><MenuItem value="keyboardInteractive">键盘交互（单次响应）</MenuItem></TextField></Grid>
    {draft.authMethod === "password" && <><Grid size={12}><TextField fullWidth type="password" label="SSH 密码" value={draft.password || ""} onChange={(e) => update("password", e.target.value)} /></Grid><Grid size={12}><FormControlLabel control={<Switch checked={draft.rememberPassword || false} onChange={(e) => update("rememberPassword", e.target.checked)} />} label="安全保存到 Windows Credential Manager" /></Grid></>}
    {draft.authMethod === "key" && <><Grid size={12}><TextField fullWidth label="私钥路径" placeholder="C:\\Users\\me\\.ssh\\id_ed25519" value={draft.privateKeyPath || ""} onChange={(e) => changePrivateKeyPath(e.target.value)} /></Grid><Grid size={12}><TextField fullWidth type="password" label="私钥口令（可选）" helperText={draft.credentialId ? "留空保留已保存的口令；取消安全保存可移除。" : "未加密的私钥可留空；未保存的口令将在连接时询问。"} value={draft.password || ""} onChange={(e) => update("password", e.target.value)} /></Grid><Grid size={12}><FormControlLabel control={<Switch checked={draft.rememberPassword || false} onChange={(e) => update("rememberPassword", e.target.checked)} />} label="安全保存私钥口令到 Windows Credential Manager" /></Grid></>}
    {draft.authMethod === "keyboardInteractive" && <Grid size={12}><Alert severity="info">仅支持单次响应认证，不支持需要多个不同回答的多步 MFA。</Alert></Grid>}
    <Grid size={12}><TextField fullWidth label="标签" helperText="用逗号分隔" value={tagsText} onChange={(e) => setTagsText(e.target.value)} /></Grid><Grid size={12}><FormControlLabel control={<Switch checked={draft.favorite} onChange={(e) => update("favorite", e.target.checked)} />} label="收藏服务器" /></Grid>
  </Grid>{credentialsChanged && <Alert severity="info" sx={{ mt: 2 }}>连接身份已更改，请重新输入认证凭据并选择是否安全保存；旧的 SSH 和 sudo 密码不会用于新的连接身份。</Alert>}{error && <Alert severity="error" sx={{ mt: 2 }}>{error}</Alert>}</DialogContent><DialogActions><Button disabled={saving} onClick={onClose}>{t("cancel")}</Button><Button disabled={saving} variant="contained" onClick={save}>{t("save")}</Button></DialogActions></Dialog>;
}
