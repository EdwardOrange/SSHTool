import Brightness4Rounded from "@mui/icons-material/Brightness4Rounded";
import Brightness7Rounded from "@mui/icons-material/Brightness7Rounded";
import Circle from "@mui/icons-material/Circle";
import CloudOffRounded from "@mui/icons-material/CloudOffRounded";
import LanguageRounded from "@mui/icons-material/LanguageRounded";
import MenuRounded from "@mui/icons-material/MenuRounded";
import MoreVertRounded from "@mui/icons-material/MoreVertRounded";
import SettingsRounded from "@mui/icons-material/SettingsRounded";
import TerminalRounded from "@mui/icons-material/TerminalRounded";
import { Alert, AppBar, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, Drawer, Chip, IconButton, Menu, MenuItem, Snackbar, Stack, Tab, Tabs, TextField, Toolbar, Tooltip, Typography, useMediaQuery, useTheme } from "@mui/material";
import { save } from "@tauri-apps/plugin-dialog";
import React from "react";
import { useTranslation } from "react-i18next";
import { api } from "./api";
import CommandLedger from "./components/CommandLedger";
import HostDialog from "./components/HostDialog";
import ServerSidebar from "./components/ServerSidebar";
import TransferDrawer from "./components/TransferDrawer";
import { useAppStore } from "./store";
import { settingsPersistence } from "./settingsPersistence";
import { loadCommandHistory } from "./commandHistory";
import { connectWithPrompts } from "./sshConnection";
import { startConnectionStatusPolling } from "./connectionStatus";
import type { HostProfile, PageId } from "./types";
import { materialColors } from "./theme";
import { formatError } from "./utils";

const pages: { id: PageId; label: string }[] = [
  { id: "terminal", label: "terminal" }, { id: "monitor", label: "monitor" }, { id: "firewall", label: "firewall" }, { id: "sftp", label: "sftp" }, { id: "forwarding", label: "forwarding" },
];
const TerminalView = React.lazy(() => import("./components/TerminalView"));
const MonitorView = React.lazy(() => import("./components/MonitorView"));
const FirewallView = React.lazy(() => import("./components/FirewallView"));
const SftpView = React.lazy(() => import("./components/SftpView"));
const ForwardingView = React.lazy(() => import("./components/ForwardingView"));
const SettingsView = React.lazy(() => import("./components/SettingsView"));

export default function App({ mode, setMode }: { mode: "light" | "dark"; setMode: React.Dispatch<React.SetStateAction<"light" | "dark">> }) {
  const { t, i18n } = useTranslation();
  const theme = useTheme();
  const colors = materialColors(mode);
  const compact = useMediaQuery(theme.breakpoints.down("lg"));
  const [sidebarOpen, setSidebarOpen] = React.useState(false);
  const [actionPending, setActionPending] = React.useState(false);
  const connectionLock = React.useRef(false);
  const connectionRevision = React.useRef(0);
  const hosts = useAppStore((s) => s.hosts); const setHosts = useAppStore((s) => s.setHosts); const selectedHostId = useAppStore((s) => s.selectedHostId); const page = useAppStore((s) => s.page); const setPage = useAppStore((s) => s.setPage); const removeHost = useAppStore((s) => s.removeHost); const setCommands = useAppStore((s) => s.setCommands); const addCommand = useAppStore((s) => s.addCommand); const setSettings = useAppStore((s) => s.setSettings); const settings = useAppStore((s) => s.settings);
  const [terminalHostIds, setTerminalHostIds] = React.useState<string[]>([]);
  React.useEffect(() => {
    setTerminalHostIds((previous) => {
      const next = previous.filter((id) => hosts.some((item) => item.id === id && item.status === "connected"));
      if (page === "terminal" && selectedHostId && hosts.some((item) => item.id === selectedHostId && item.status === "connected") && !next.includes(selectedHostId)) next.push(selectedHostId);
      return next.length === previous.length && next.every((id, index) => id === previous[index]) ? previous : next;
    });
  }, [hosts, page, selectedHostId]);
  const [loading, setLoading] = React.useState(true);
  const [startupError, setStartupError] = React.useState("");
  const [hostDialog, setHostDialog] = React.useState(false);
  const [editingHost, setEditingHost] = React.useState<HostProfile | undefined>();
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [connecting, setConnecting] = React.useState(false);
  const [menuEl, setMenuEl] = React.useState<HTMLElement | null>(null);
  const [confirmAction, setConfirmAction] = React.useState<{ kind: "edit" | "delete"; host: HostProfile } | null>(null);
  const [passwordRequest, setPasswordRequest] = React.useState<{ host: HostProfile; resolve: (value?: string) => void } | null>(null);
  const [passwordValue, setPasswordValue] = React.useState("");
  const [hostKeyRequest, setHostKeyRequest] = React.useState<{ host: HostProfile; fingerprint: string; resolve: (trusted: boolean) => void } | null>(null);
  const [notice, setNotice] = React.useState("");
  const host = hosts.find((item) => item.id === selectedHostId);
  const credentialLabel = passwordRequest?.host.authMethod === "key" ? "私钥口令" : passwordRequest?.host.authMethod === "keyboardInteractive" ? "键盘交互响应" : "SSH 密码";

  const askPassword = React.useCallback((target: HostProfile) => new Promise<string | undefined>((resolve) => {
    setPasswordValue("");
    setPasswordRequest({ host: target, resolve });
  }), []);
  const finishPasswordRequest = (value?: string) => {
    passwordRequest?.resolve(value);
    setPasswordRequest(null);
    setPasswordValue("");
  };
  const askHostKeyTrust = React.useCallback((target: HostProfile, fingerprint: string) => new Promise<boolean>((resolve) => {
    setHostKeyRequest({ host: target, fingerprint, resolve });
  }), []);
  const finishHostKeyRequest = (trusted: boolean) => {
    hostKeyRequest?.resolve(trusted);
    setHostKeyRequest(null);
  };
  const applyTheme = React.useCallback((theme: NonNullable<typeof settings>["theme"]) => {
    const next = theme === "system" ? (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light") : theme;
    if (theme === "system") localStorage.removeItem("theme"); else localStorage.setItem("theme", next);
    setMode(next);
  }, [setMode]);
  const cycleTheme = () => {
    if (!settings) return;
    const nextTheme = mode === "dark" ? "light" : "dark";
    void settingsPersistence.update({ theme: nextTheme }).catch((reason) => setNotice(formatError(reason)));
  };

  React.useEffect(() => {
    if (settings?.theme !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const apply = () => setMode(media.matches ? "dark" : "light");
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [setMode, settings?.theme]);
  React.useEffect(() => {
    if (settings) applyTheme(settings.theme);
  }, [applyTheme, settings?.theme]);
  React.useEffect(() => {
    if (!settings) return;
    void i18n.changeLanguage(settings.locale);
    localStorage.setItem("locale", settings.locale);
  }, [i18n, settings?.locale]);

  React.useEffect(() => {
    let alive = true;
    Promise.all([api.hostsList(), loadCommandHistory({ subscribe: api.commandLogSubscribe, query: api.commandLogQuery }, setCommands, addCommand, () => alive), api.settingsGet()])
      .then(([list, , settings]) => {
        if (!alive) return;
        setHosts(list); setSettings(settings);
        if (settings.locale !== i18n.language) void i18n.changeLanguage(settings.locale);
        if (pages.some((item) => item.id === settings.defaultPage)) setPage(settings.defaultPage);
      })
      .catch((error) => alive && setStartupError(String(error)))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [setHosts, setCommands, addCommand, setSettings, setPage, i18n]);

  React.useEffect(() => startConnectionStatusPolling({
    listHosts: api.hostsList,
    getHosts: () => useAppStore.getState().hosts,
    updateConnection: (id, patch) => useAppStore.getState().updateHostConnection(id, patch),
    operationRevision: () => connectionRevision.current,
    operationPending: () => connectionLock.current,
  }), []);

  const toggleConnection = async () => {
    if (!host || connectionLock.current) return;
    connectionLock.current = true;
    connectionRevision.current += 1;
    setConnecting(true);
    try {
      if (host.status === "connected") { await api.sshDisconnect(host.id); useAppStore.getState().updateHostConnection(host.id, { status: "disconnected" }); }
      else {
        if (!(await connectWithPrompts(host, api, askPassword, askHostKeyTrust))) return;
        useAppStore.getState().updateHostConnection(host.id, { status: "connected", lastConnectedAt: new Date().toISOString() });
      }
    } catch (error) { useAppStore.getState().updateHostConnection(host.id, { status: "error" }); setNotice(formatError(error)); }
    finally { connectionLock.current = false; setConnecting(false); }
  };

  const changeLanguage = () => {
    const next = i18n.language.startsWith("zh") ? "en" : "zh";
    if (!settings) return;
    void settingsPersistence.update({ locale: next }).catch((reason) => setNotice(formatError(reason)));
  };

  const openAddHost = () => { setSidebarOpen(false); setEditingHost(undefined); setHostDialog(true); };
  const openEditHost = () => {
    if (!host) return;
    setMenuEl(null);
    if (host.status === "connected") setConfirmAction({ kind: "edit", host });
    else { setEditingHost(host); setHostDialog(true); }
  };
  const exportHost = async () => {
    if (!host) return;
    setMenuEl(null);
    try {
      const path = await save({ defaultPath: `${host.name.replace(/[\\/:*?"<>|]/g, "_")}.sshops.json`, filters: [{ name: "SSH 配置", extensions: ["json"] }] });
      if (path) { await api.configExport(path, host.id); setNotice("服务器配置已导出"); }
    } catch (error) { setNotice(formatError(error)); }
  };
  const executeConfirmedAction = async () => {
    if (!confirmAction || actionPending || connectionLock.current) return;
    connectionLock.current = true;
    connectionRevision.current += 1;
    setActionPending(true);
    const target = confirmAction.host;
    try {
      if (confirmAction.kind === "edit") {
        await api.sshDisconnect(target.id);
        useAppStore.getState().updateHostConnection(target.id, { status: "disconnected" });
        const disconnected = useAppStore.getState().hosts.find((item) => item.id === target.id);
        if (disconnected) { setEditingHost(disconnected); setHostDialog(true); }
      } else {
        await api.hostsDelete(target.id);
        removeHost(target.id);
        setNotice("服务器已删除，命令审计历史已保留");
      }
      setConfirmAction(null);
    } catch (error) { setNotice(formatError(error)); }
    finally { connectionLock.current = false; setActionPending(false); }
  };

  return <Box sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
    <AppBar position="static" color="inherit" elevation={0} sx={{ borderBottom: 1, borderColor: "divider", zIndex: 5 }}><Toolbar variant="dense" className="drag-region" sx={{ minHeight: "64px!important", px: { xs: 1, sm: 3 }, gap: 1 }}><>{compact && <IconButton className="no-drag" aria-label="打开服务器列表" onClick={() => setSidebarOpen(true)}><MenuRounded/></IconButton>}</><Stack direction="row" alignItems="center" spacing={1.5}><Box sx={{ width: 40, height: 40, borderRadius: "12px", display: "grid", placeItems: "center", color: colors.onPrimaryContainer, bgcolor: colors.primaryContainer }}><TerminalRounded fontSize="small"/></Box><Typography variant="subtitle1" noWrap sx={{ maxWidth: { xs: 110, sm: "none" } }}>{t("appName")}</Typography></Stack>{!("__TAURI_INTERNALS__" in window) && <Chip label="演示数据" size="small" variant="outlined" sx={{ ml: 2, display: { xs: "none", sm: "inline-flex" } }}/>}<Box sx={{ flex: 1 }}/><Stack className="no-drag" direction="row" alignItems="center" spacing={.5}><Tooltip title={t("language")}><IconButton aria-label={t("language")} onClick={changeLanguage}><LanguageRounded fontSize="small"/></IconButton></Tooltip><Tooltip title={t("theme")}><IconButton aria-label={t("theme")} onClick={cycleTheme}>{mode === "dark" ? <Brightness7Rounded fontSize="small"/> : <Brightness4Rounded fontSize="small"/>}</IconButton></Tooltip><Tooltip title={t("settings")}><IconButton aria-label={t("settings")} onClick={() => setSettingsOpen(true)}><SettingsRounded fontSize="small"/></IconButton></Tooltip></Stack></Toolbar></AppBar>
    <Box sx={{ display: "flex", flex: 1, minHeight: 0 }}>{compact ? <Drawer open={sidebarOpen} onClose={() => setSidebarOpen(false)} slotProps={{ paper: { sx: { borderRadius: "0 16px 16px 0" } } }}><ServerSidebar onAdd={openAddHost} onSelect={() => setSidebarOpen(false)}/></Drawer> : <ServerSidebar onAdd={openAddHost}/>}<Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
      {host && <><Stack direction="row" alignItems="center" sx={{ minHeight: 80, px: { xs: 2, sm: 3 }, gap: 1, bgcolor: "background.default" }}><Stack direction="row" alignItems="center" spacing={1} sx={{ minWidth: 0, flexWrap: "wrap" }}><Circle sx={{ fontSize: 10, color: host.status === "connected" ? "success.main" : host.status === "error" ? "error.main" : "text.disabled" }}/><Typography variant="h6" noWrap>{host.name}</Typography><Typography variant="caption" color="text.secondary" className="mono" sx={{ display: { xs: "none", sm: "block" } }}>{host.username}@{host.hostname}:{host.port}</Typography><Chip size="small" variant="outlined" color={host.status === "connected" ? "success" : "default"} label={host.status === "connected" ? "已连接" : host.status === "error" ? "连接失败" : "未连接"} sx={{ display: { xs: "none", md: "inline-flex" } }}/></Stack><Box sx={{ flex: 1 }}/><Button size="small" variant={host.status === "connected" ? "outlined" : "contained"} color={host.status === "connected" ? "inherit" : "primary"} onClick={toggleConnection} disabled={connecting} startIcon={connecting ? <CircularProgress size={16}/> : host.status === "connected" ? <CloudOffRounded/> : <TerminalRounded/>}>{host.status === "connected" ? t("disconnect") : t("connect")}</Button><IconButton aria-label="更多服务器操作" disabled={connecting || actionPending} size="small" onClick={(event) => setMenuEl(event.currentTarget)}><MoreVertRounded/></IconButton></Stack><Menu anchorEl={menuEl} open={Boolean(menuEl)} onClose={() => setMenuEl(null)}><MenuItem onClick={openEditHost}>编辑服务器</MenuItem><MenuItem onClick={() => void exportHost()}>导出配置</MenuItem><Divider/><MenuItem sx={{ color: "error.main" }} onClick={() => { setMenuEl(null); setConfirmAction({ kind: "delete", host }); }}>删除服务器</MenuItem></Menu><Tabs aria-label="服务器功能" variant="scrollable" scrollButtons="auto" allowScrollButtonsMobile value={page} onChange={(_, value) => setPage(value)} sx={{ minHeight: 48, px: { xs: 0, sm: 2 }, bgcolor: "background.default", borderBottom: 1, borderColor: "divider" }}>{pages.map((item) => <Tab key={item.id} value={item.id} id={`tab-${item.id}`} aria-controls={`panel-${item.id}`} label={t(item.label)}/>)}</Tabs></>}
      <Box component="main" role={host ? "tabpanel" : undefined} id={`panel-${page}`} aria-labelledby={host ? `tab-${page}` : undefined} sx={{ flex: 1, minHeight: 0, p: host ? { xs: 2, sm: 3 } : 0, position: "relative", overflow: "hidden" }}>
        {loading ? <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><CircularProgress/></Box> : startupError ? <Box sx={{ height: "100%", display: "grid", placeItems: "center", p: 3 }}><Stack alignItems="center" spacing={2}><Typography variant="h6" color="error">无法加载本地数据</Typography><Typography color="text.secondary">{startupError}</Typography><Button variant="contained" onClick={() => window.location.reload()}>重新加载</Button></Stack></Box> : !host ? <EmptyState onAdd={openAddHost}/> : <>
          <React.Suspense fallback={<CircularProgress aria-label="正在打开终端" size={28}/>}>{hosts.filter((item) => item.status === "connected" && terminalHostIds.includes(item.id)).map((item) => {
            const active = page === "terminal" && item.id === host.id;
            return <Box key={item.id} aria-hidden={!active} inert={!active} sx={{ position: active ? "relative" : "absolute", inset: active ? undefined : 0, height: "100%", visibility: active ? "visible" : "hidden", pointerEvents: active ? "auto" : "none" }}><TerminalView host={item} active={active}/></Box>;
          })}</React.Suspense>
          <React.Suspense fallback={<Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><CircularProgress size={28}/></Box>}>
            {page === "terminal" && host.status !== "connected" ? <DisconnectedTerminal/> : page === "monitor" ? <MonitorView key={host.id} host={host}/> : page === "firewall" ? <FirewallView key={host.id} host={host}/> : page === "sftp" ? <SftpView key={host.id} host={host}/> : page === "forwarding" ? <ForwardingView key={host.id} host={host}/> : null}
          </React.Suspense>
        </>}
      </Box>
      <TransferDrawer/><CommandLedger/>
    </Box></Box>
    <HostDialog open={hostDialog} initialHost={editingHost} onClose={() => { setHostDialog(false); setEditingHost(undefined); }}/>
    <Dialog open={Boolean(confirmAction)} onClose={actionPending ? undefined : () => setConfirmAction(null)} maxWidth="sm" fullWidth>
      <DialogTitle>{confirmAction?.kind === "delete" ? "删除服务器" : "编辑已连接服务器"}</DialogTitle>
      <DialogContent>{confirmAction?.kind === "delete" ? <Typography>确定删除“{confirmAction.host.name}”吗？服务器配置、凭据、转发和监控历史将被删除，但命令审计记录会保留。</Typography> : <Typography>编辑连接参数前需要断开“{confirmAction?.host.name}”的当前 SSH 会话。是否继续？</Typography>}</DialogContent>
      <DialogActions><Button disabled={actionPending} onClick={() => setConfirmAction(null)}>取消</Button><Button disabled={actionPending} color={confirmAction?.kind === "delete" ? "error" : "primary"} variant="contained" onClick={() => void executeConfirmedAction()}>{confirmAction?.kind === "delete" ? "确认删除" : "断开并编辑"}</Button></DialogActions>
    </Dialog>
    <Dialog open={Boolean(passwordRequest)} onClose={() => finishPasswordRequest()} maxWidth="xs" fullWidth>
      <DialogTitle>输入{credentialLabel}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>请输入“{passwordRequest?.host.name}”的{credentialLabel}。</Typography>
        {passwordRequest?.host.authMethod === "key" && <Alert severity="info" sx={{ mb: 2 }}>此口令仅用于本次连接解密私钥；需要保存时请在服务器编辑页设置。</Alert>}
        {passwordRequest?.host.authMethod === "keyboardInteractive" && <Alert severity="info" sx={{ mb: 2 }}>仅支持单次响应认证，不支持需要多个不同回答的多步 MFA。</Alert>}
        <TextField autoFocus fullWidth type="password" label={credentialLabel} value={passwordValue} onChange={(event) => setPasswordValue(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter" && passwordValue) finishPasswordRequest(passwordValue); }} />
      </DialogContent>
      <DialogActions><Button onClick={() => finishPasswordRequest()}>取消</Button><Button variant="contained" onClick={() => finishPasswordRequest(passwordValue || undefined)} disabled={!passwordValue}>连接</Button></DialogActions>
    </Dialog>
    <Dialog open={Boolean(hostKeyRequest)} onClose={() => finishHostKeyRequest(false)} maxWidth="sm" fullWidth>
      <DialogTitle>确认服务器主机密钥</DialogTitle>
      <DialogContent>
        <Alert severity="warning" sx={{ mb: 2 }}>首次连接或主机密钥发生变化。仅在你已通过可信渠道核对指纹后继续。</Alert>
        <Stack spacing={1}>
          <Typography variant="body2">主机：{hostKeyRequest?.host.hostname}:{hostKeyRequest?.host.port}</Typography>
          <Typography variant="body2" color="text.secondary">指纹</Typography>
          <Typography className="mono" sx={{ overflowWrap: "anywhere", p: 1.5, borderRadius: 2, bgcolor: "action.hover" }}>{hostKeyRequest?.fingerprint}</Typography>
        </Stack>
      </DialogContent>
      <DialogActions><Button onClick={() => finishHostKeyRequest(false)}>取消</Button><Button variant="contained" color="warning" onClick={() => finishHostKeyRequest(true)}>信任并连接</Button></DialogActions>
    </Dialog>
    <Snackbar open={Boolean(notice)} autoHideDuration={3500} onClose={() => setNotice("")}><Alert severity="info" onClose={() => setNotice("")}>{notice}</Alert></Snackbar>
    <React.Suspense fallback={null}><SettingsView open={settingsOpen} onClose={() => setSettingsOpen(false)} onTheme={applyTheme}/></React.Suspense>
  </Box>;
}

function DisconnectedTerminal() {
  return <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><Stack alignItems="center" spacing={1.5}><CloudOffRounded color="disabled" sx={{ fontSize: 38 }}/><Typography variant="subtitle1">服务器尚未连接</Typography><Typography variant="body2" color="text.secondary">连接后将创建一个终端；在本次连接断开前切换页面不会重启终端。</Typography></Stack></Box>;
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><Stack alignItems="center" spacing={2}><Box sx={{ width: 72, height: 72, borderRadius: 5, bgcolor: "action.hover", display: "grid", placeItems: "center" }}><TerminalRounded color="primary" sx={{ fontSize: 36 }}/></Box><Typography variant="h6">添加第一台 SSH 服务器</Typography><Typography color="text.secondary">服务器凭据仅保存在本机安全存储中</Typography><Button variant="contained" onClick={onAdd}>添加服务器</Button></Stack></Box>;
}
