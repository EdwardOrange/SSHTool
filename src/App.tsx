import { Brightness4Rounded, Brightness7Rounded, Circle, CloudOffRounded, LanguageRounded, MoreVertRounded, SettingsRounded, TerminalRounded } from "@mui/icons-material";
import { Alert, AppBar, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, IconButton, Menu, MenuItem, Snackbar, Stack, Tab, Tabs, TextField, Toolbar, Tooltip, Typography } from "@mui/material";
import { save } from "@tauri-apps/plugin-dialog";
import React from "react";
import { useTranslation } from "react-i18next";
import { api } from "./api";
import CommandLedger from "./components/CommandLedger";
import HostDialog from "./components/HostDialog";
import ServerSidebar from "./components/ServerSidebar";
import TerminalView from "./components/TerminalView";
import TransferDrawer from "./components/TransferDrawer";
import { useAppStore } from "./store";
import type { HostProfile, PageId } from "./types";
import { formatError } from "./utils";

const pages: { id: PageId; label: string }[] = [
  { id: "terminal", label: "terminal" }, { id: "monitor", label: "monitor" }, { id: "firewall", label: "firewall" }, { id: "sftp", label: "sftp" }, { id: "forwarding", label: "forwarding" },
];
const MonitorView = React.lazy(() => import("./components/MonitorView"));
const FirewallView = React.lazy(() => import("./components/FirewallView"));
const SftpView = React.lazy(() => import("./components/SftpView"));
const ForwardingView = React.lazy(() => import("./components/ForwardingView"));
const SettingsView = React.lazy(() => import("./components/SettingsView"));

export default function App({ mode, toggleMode, setMode }: { mode: "light" | "dark"; toggleMode: () => void; setMode: React.Dispatch<React.SetStateAction<"light" | "dark">> }) {
  const { t, i18n } = useTranslation();
  const hosts = useAppStore((s) => s.hosts); const setHosts = useAppStore((s) => s.setHosts); const selectedHostId = useAppStore((s) => s.selectedHostId); const page = useAppStore((s) => s.page); const setPage = useAppStore((s) => s.setPage); const upsertHost = useAppStore((s) => s.upsertHost); const removeHost = useAppStore((s) => s.removeHost); const setCommands = useAppStore((s) => s.setCommands); const addCommand = useAppStore((s) => s.addCommand); const setSettings = useAppStore((s) => s.setSettings); const settings = useAppStore((s) => s.settings);
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
  const themeSaveChain = React.useRef<Promise<unknown>>(Promise.resolve());
  const host = hosts.find((item) => item.id === selectedHostId);

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
    const previous = settings;
    const nextTheme = mode === "dark" ? "light" : "dark";
    const next = { ...settings, theme: nextTheme as typeof settings.theme };
    setSettings(next);
    applyTheme(nextTheme);
    themeSaveChain.current = themeSaveChain.current.catch(() => undefined).then(() => api.settingsUpdate(next)).then((saved) => {
      if (useAppStore.getState().settings === next) setSettings(saved);
    }, (reason) => {
      if (useAppStore.getState().settings === next) { setSettings(previous); applyTheme(previous.theme); }
      setNotice(formatError(reason));
    });
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
    let alive = true;
    Promise.all([api.hostsList(), api.commandLogQuery(), api.settingsGet()])
      .then(([list, commands, settings]) => {
        if (!alive) return;
        setHosts(list); setCommands(commands); setSettings(settings);
        if (settings.locale !== i18n.language) void i18n.changeLanguage(settings.locale);
        if (pages.some((item) => item.id === settings.defaultPage)) setPage(settings.defaultPage);
      })
      .then(() => api.commandLogSubscribe((event) => alive && addCommand(event.payload)))
      .catch((error) => alive && setStartupError(String(error)))
      .finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [setHosts, setCommands, addCommand, setSettings, setPage, i18n]);

  const toggleConnection = async () => {
    if (!host) return;
    setConnecting(true);
    try {
      if (host.status === "connected") { await api.sshDisconnect(host.id); upsertHost({ ...host, status: "disconnected" }); }
      else {
        let password: string | undefined;
        if ((host.authMethod === "password" || host.authMethod === "keyboardInteractive") && !host.credentialId) {
          password = await askPassword(host);
          if (!password) return;
        }
        try {
          await api.sshConnect(host.id, password);
        } catch (firstError) {
          const fingerprint = await api.sshHostKeyPending(host.id);
          if (!fingerprint || !(await askHostKeyTrust(host, fingerprint))) throw firstError;
          await api.sshTrustHostKey(host.id, fingerprint);
          await api.sshConnect(host.id, password);
        }
        upsertHost({ ...host, status: "connected", lastConnectedAt: new Date().toISOString() }, false);
      }
    } catch (error) { upsertHost({ ...host, status: "error" }, false); setNotice(formatError(error)); }
    finally { setConnecting(false); }
  };

  const changeLanguage = () => {
    const next = i18n.language.startsWith("zh") ? "en" : "zh";
    void i18n.changeLanguage(next); localStorage.setItem("locale", next);
    const settings = useAppStore.getState().settings;
    if (settings) { const updated = { ...settings, locale: next as "zh" | "en" }; setSettings(updated); void api.settingsUpdate(updated); }
  };

  const openAddHost = () => { setEditingHost(undefined); setHostDialog(true); };
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
    if (!confirmAction) return;
    const target = confirmAction.host;
    try {
      if (confirmAction.kind === "edit") {
        await api.sshDisconnect(target.id);
        const disconnected = { ...target, status: "disconnected" as const };
        upsertHost(disconnected);
        setEditingHost(disconnected);
        setHostDialog(true);
      } else {
        await api.hostsDelete(target.id);
        removeHost(target.id);
        setNotice("服务器已删除，命令审计历史已保留");
      }
      setConfirmAction(null);
    } catch (error) { setNotice(formatError(error)); }
  };

  return <Box sx={{ height: "100%", display: "flex", flexDirection: "column" }}>
    <AppBar position="static" color="inherit" elevation={0} sx={{ borderBottom: 1, borderColor: "divider", zIndex: 5 }}><Toolbar variant="dense" className="drag-region" sx={{ minHeight: "52px!important", px: 1.5 }}><Stack direction="row" alignItems="center" spacing={1.2}><Box sx={{ width: 32, height: 32, borderRadius: 2.5, display: "grid", placeItems: "center", color: "white", background: "linear-gradient(135deg, #2E5BFF, #6C63E8)" }}><TerminalRounded fontSize="small"/></Box><Typography variant="subtitle1" fontWeight={800}>{t("appName")}</Typography></Stack><Box sx={{ flex: 1 }}/><Stack className="no-drag" direction="row" alignItems="center" spacing={.5}><Tooltip title={t("language")}><IconButton aria-label={t("language")} onClick={changeLanguage}><LanguageRounded fontSize="small"/></IconButton></Tooltip><Tooltip title={t("theme")}><IconButton aria-label={t("theme")} onClick={cycleTheme}>{mode === "dark" ? <Brightness7Rounded fontSize="small"/> : <Brightness4Rounded fontSize="small"/>}</IconButton></Tooltip><Tooltip title={t("settings")}><IconButton aria-label={t("settings")} onClick={() => setSettingsOpen(true)}><SettingsRounded fontSize="small"/></IconButton></Tooltip></Stack></Toolbar></AppBar>
    <Box sx={{ display: "flex", flex: 1, minHeight: 0 }}><ServerSidebar onAdd={openAddHost}/><Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
      {host && <><Stack direction="row" alignItems="center" sx={{ minHeight: 50, px: 2, borderBottom: 1, borderColor: "divider", bgcolor: "background.paper" }}><Stack direction="row" alignItems="center" spacing={1}><Circle sx={{ fontSize: 10, color: host.status === "connected" ? "success.main" : host.status === "error" ? "error.main" : "text.disabled" }}/><Typography variant="subtitle2">{host.name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{host.hostname}:{host.port}</Typography></Stack><Box sx={{ flex: 1 }}/><Button size="small" variant={host.status === "connected" ? "outlined" : "contained"} color={host.status === "connected" ? "inherit" : "primary"} onClick={toggleConnection} disabled={connecting} startIcon={connecting ? <CircularProgress size={16}/> : host.status === "connected" ? <CloudOffRounded/> : <TerminalRounded/>}>{host.status === "connected" ? t("disconnect") : t("connect")}</Button><IconButton aria-label="更多服务器操作" size="small" onClick={(event) => setMenuEl(event.currentTarget)}><MoreVertRounded/></IconButton></Stack><Menu anchorEl={menuEl} open={Boolean(menuEl)} onClose={() => setMenuEl(null)}><MenuItem onClick={openEditHost}>编辑服务器</MenuItem><MenuItem onClick={() => void exportHost()}>导出配置</MenuItem><Divider/><MenuItem sx={{ color: "error.main" }} onClick={() => { setMenuEl(null); setConfirmAction({ kind: "delete", host }); }}>删除服务器</MenuItem></Menu><Tabs value={page} onChange={(_, value) => setPage(value)} sx={{ minHeight: 45, px: 1.5, bgcolor: "background.paper", borderBottom: 1, borderColor: "divider", "& .MuiTab-root": { minHeight: 45 } }}>{pages.map((item) => <Tab key={item.id} value={item.id} label={t(item.label)}/>)}</Tabs></>}
      <Box sx={{ flex: 1, minHeight: 0, p: host ? 2 : 0, position: "relative" }}>
        {loading ? <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><CircularProgress/></Box> : startupError ? <Box sx={{ height: "100%", display: "grid", placeItems: "center", p: 3 }}><Stack alignItems="center" spacing={2}><Typography variant="h6" color="error">无法加载本地数据</Typography><Typography color="text.secondary">{startupError}</Typography><Button variant="contained" onClick={() => window.location.reload()}>重新加载</Button></Stack></Box> : !host ? <EmptyState onAdd={openAddHost}/> : <>
          {hosts.filter((item) => item.status === "connected").map((item) => {
            const active = page === "terminal" && item.id === host.id;
            return <Box key={item.id} aria-hidden={!active} sx={{ position: active ? "relative" : "absolute", inset: active ? undefined : 0, height: "100%", visibility: active ? "visible" : "hidden", pointerEvents: active ? "auto" : "none" }}><TerminalView host={item} active={active}/></Box>;
          })}
          <React.Suspense fallback={<Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><CircularProgress size={28}/></Box>}>
            {page === "terminal" && host.status !== "connected" ? <DisconnectedTerminal/> : page === "monitor" ? <MonitorView host={host}/> : page === "firewall" ? <FirewallView host={host}/> : page === "sftp" ? <SftpView host={host}/> : page === "forwarding" ? <ForwardingView host={host}/> : null}
          </React.Suspense>
        </>}
      </Box>
      <TransferDrawer/><CommandLedger/>
    </Box></Box>
    <HostDialog open={hostDialog} initialHost={editingHost} onClose={() => { setHostDialog(false); setEditingHost(undefined); }}/>
    <Dialog open={Boolean(confirmAction)} onClose={() => setConfirmAction(null)} maxWidth="sm" fullWidth>
      <DialogTitle>{confirmAction?.kind === "delete" ? "删除服务器" : "编辑已连接服务器"}</DialogTitle>
      <DialogContent>{confirmAction?.kind === "delete" ? <Typography>确定删除“{confirmAction.host.name}”吗？服务器配置、凭据、转发和监控历史将被删除，但命令审计记录会保留。</Typography> : <Typography>编辑连接参数前需要断开“{confirmAction?.host.name}”的当前 SSH 会话。是否继续？</Typography>}</DialogContent>
      <DialogActions><Button onClick={() => setConfirmAction(null)}>取消</Button><Button color={confirmAction?.kind === "delete" ? "error" : "primary"} variant="contained" onClick={() => void executeConfirmedAction()}>{confirmAction?.kind === "delete" ? "确认删除" : "断开并编辑"}</Button></DialogActions>
    </Dialog>
    <Dialog open={Boolean(passwordRequest)} onClose={() => finishPasswordRequest()} maxWidth="xs" fullWidth>
      <DialogTitle>输入 SSH 密码</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>请输入“{passwordRequest?.host.name}”的登录密码。</Typography>
        <TextField autoFocus fullWidth type="password" label="SSH 密码" value={passwordValue} onChange={(event) => setPasswordValue(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") finishPasswordRequest(passwordValue || undefined); }} />
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
