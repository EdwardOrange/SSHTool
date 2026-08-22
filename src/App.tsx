import { Brightness4Rounded, Brightness7Rounded, Circle, CloudOffRounded, LanguageRounded, MoreVertRounded, SettingsRounded, TerminalRounded } from "@mui/icons-material";
import { Alert, AppBar, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Divider, IconButton, Menu, MenuItem, Snackbar, Stack, Tab, Tabs, Toolbar, Tooltip, Typography } from "@mui/material";
import { save } from "@tauri-apps/plugin-dialog";
import React from "react";
import { useTranslation } from "react-i18next";
import { api } from "./api";
import CommandLedger from "./components/CommandLedger";
import FirewallView from "./components/FirewallView";
import ForwardingView from "./components/ForwardingView";
import HostDialog from "./components/HostDialog";
import MonitorView from "./components/MonitorView";
import ServerSidebar from "./components/ServerSidebar";
import SettingsView from "./components/SettingsView";
import SftpView from "./components/SftpView";
import TerminalView from "./components/TerminalView";
import TransferDrawer from "./components/TransferDrawer";
import { useAppStore } from "./store";
import type { HostProfile, PageId } from "./types";
import { formatError } from "./utils";

const pages: { id: PageId; label: string }[] = [
  { id: "terminal", label: "terminal" }, { id: "monitor", label: "monitor" }, { id: "firewall", label: "firewall" }, { id: "sftp", label: "sftp" }, { id: "forwarding", label: "forwarding" },
];

export default function App({ mode, toggleMode }: { mode: "light" | "dark"; toggleMode: () => void }) {
  const { t, i18n } = useTranslation();
  const { hosts, setHosts, selectedHostId, page, setPage, upsertHost, removeHost, setCommands, addCommand, setSettings } = useAppStore();
  const [loading, setLoading] = React.useState(true);
  const [startupError, setStartupError] = React.useState("");
  const [hostDialog, setHostDialog] = React.useState(false);
  const [editingHost, setEditingHost] = React.useState<HostProfile | undefined>();
  const [settingsOpen, setSettingsOpen] = React.useState(false);
  const [connecting, setConnecting] = React.useState(false);
  const [menuEl, setMenuEl] = React.useState<HTMLElement | null>(null);
  const [confirmAction, setConfirmAction] = React.useState<{ kind: "edit" | "delete"; host: HostProfile } | null>(null);
  const [notice, setNotice] = React.useState("");
  const host = hosts.find((item) => item.id === selectedHostId);

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
    const timer = window.setInterval(() => { if (alive) void api.commandLogQuery().then(setCommands).catch(() => undefined); }, 1500);
    return () => { alive = false; window.clearInterval(timer); };
  }, [setHosts, setCommands, addCommand, setSettings, setPage, i18n]);

  const toggleConnection = async () => {
    if (!host) return;
    setConnecting(true);
    try {
      if (host.status === "connected") { await api.sshDisconnect(host.id); upsertHost({ ...host, status: "disconnected" }); }
      else { await api.sshConnect(host.id); upsertHost({ ...host, status: "connected", lastConnectedAt: new Date().toISOString() }); }
    } catch { upsertHost({ ...host, status: "error" }); }
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
    <AppBar position="static" color="inherit" elevation={0} sx={{ borderBottom: 1, borderColor: "divider", zIndex: 5 }}><Toolbar variant="dense" className="drag-region" sx={{ minHeight: "52px!important", px: 1.5 }}><Stack direction="row" alignItems="center" spacing={1.2}><Box sx={{ width: 32, height: 32, borderRadius: 2.5, display: "grid", placeItems: "center", color: "white", background: "linear-gradient(135deg, #2E5BFF, #6C63E8)" }}><TerminalRounded fontSize="small"/></Box><Typography variant="subtitle1" fontWeight={800}>{t("appName")}</Typography></Stack><Box sx={{ flex: 1 }}/><Stack className="no-drag" direction="row" alignItems="center" spacing={.5}><Tooltip title={t("language")}><IconButton onClick={changeLanguage}><LanguageRounded fontSize="small"/></IconButton></Tooltip><Tooltip title={t("theme")}><IconButton onClick={toggleMode}>{mode === "dark" ? <Brightness7Rounded fontSize="small"/> : <Brightness4Rounded fontSize="small"/>}</IconButton></Tooltip><Tooltip title={t("settings")}><IconButton onClick={() => setSettingsOpen(true)}><SettingsRounded fontSize="small"/></IconButton></Tooltip></Stack></Toolbar></AppBar>
    <Box sx={{ display: "flex", flex: 1, minHeight: 0 }}><ServerSidebar onAdd={openAddHost}/><Box sx={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
      {host && <><Stack direction="row" alignItems="center" sx={{ minHeight: 50, px: 2, borderBottom: 1, borderColor: "divider", bgcolor: "background.paper" }}><Stack direction="row" alignItems="center" spacing={1}><Circle sx={{ fontSize: 10, color: host.status === "connected" ? "success.main" : host.status === "error" ? "error.main" : "text.disabled" }}/><Typography variant="subtitle2">{host.name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{host.hostname}:{host.port}</Typography></Stack><Box sx={{ flex: 1 }}/><Button size="small" variant={host.status === "connected" ? "outlined" : "contained"} color={host.status === "connected" ? "inherit" : "primary"} onClick={toggleConnection} disabled={connecting} startIcon={connecting ? <CircularProgress size={16}/> : host.status === "connected" ? <CloudOffRounded/> : <TerminalRounded/>}>{host.status === "connected" ? t("disconnect") : t("connect")}</Button><IconButton size="small" onClick={(event) => setMenuEl(event.currentTarget)}><MoreVertRounded/></IconButton></Stack><Menu anchorEl={menuEl} open={Boolean(menuEl)} onClose={() => setMenuEl(null)}><MenuItem onClick={openEditHost}>编辑服务器</MenuItem><MenuItem onClick={() => void exportHost()}>导出配置</MenuItem><Divider/><MenuItem sx={{ color: "error.main" }} onClick={() => { setMenuEl(null); setConfirmAction({ kind: "delete", host }); }}>删除服务器</MenuItem></Menu><Tabs value={page} onChange={(_, value) => setPage(value)} sx={{ minHeight: 45, px: 1.5, bgcolor: "background.paper", borderBottom: 1, borderColor: "divider", "& .MuiTab-root": { minHeight: 45 } }}>{pages.map((item) => <Tab key={item.id} value={item.id} label={t(item.label)}/>)}</Tabs></>}
      <Box sx={{ flex: 1, minHeight: 0, p: host ? 2 : 0, position: "relative" }}>
        {loading ? <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><CircularProgress/></Box> : startupError ? <Box sx={{ height: "100%", display: "grid", placeItems: "center", p: 3 }}><Stack alignItems="center" spacing={2}><Typography variant="h6" color="error">无法加载本地数据</Typography><Typography color="text.secondary">{startupError}</Typography><Button variant="contained" onClick={() => window.location.reload()}>重新加载</Button></Stack></Box> : !host ? <EmptyState onAdd={openAddHost}/> : <>
          {hosts.filter((item) => item.status === "connected").map((item) => {
            const active = page === "terminal" && item.id === host.id;
            return <Box key={item.id} aria-hidden={!active} sx={{ position: active ? "relative" : "absolute", inset: active ? undefined : 0, height: "100%", visibility: active ? "visible" : "hidden", pointerEvents: active ? "auto" : "none" }}><TerminalView host={item} active={active}/></Box>;
          })}
          {page === "terminal" && host.status !== "connected" ? <DisconnectedTerminal/> : page === "monitor" ? <MonitorView host={host}/> : page === "firewall" ? <FirewallView host={host}/> : page === "sftp" ? <SftpView host={host}/> : page === "forwarding" ? <ForwardingView host={host}/> : null}
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
    <Snackbar open={Boolean(notice)} autoHideDuration={3500} onClose={() => setNotice("")}><Alert severity="info" onClose={() => setNotice("")}>{notice}</Alert></Snackbar>
    <SettingsView open={settingsOpen} onClose={() => setSettingsOpen(false)} onTheme={(theme) => { if (theme !== "system" && ((theme === "dark") !== (mode === "dark"))) toggleMode(); }}/>
  </Box>;
}

function DisconnectedTerminal() {
  return <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><Stack alignItems="center" spacing={1.5}><CloudOffRounded color="disabled" sx={{ fontSize: 38 }}/><Typography variant="subtitle1">服务器尚未连接</Typography><Typography variant="body2" color="text.secondary">连接后将创建一个终端；在本次连接断开前切换页面不会重启终端。</Typography></Stack></Box>;
}

function EmptyState({ onAdd }: { onAdd: () => void }) {
  return <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}><Stack alignItems="center" spacing={2}><Box sx={{ width: 72, height: 72, borderRadius: 5, bgcolor: "action.hover", display: "grid", placeItems: "center" }}><TerminalRounded color="primary" sx={{ fontSize: 36 }}/></Box><Typography variant="h6">添加第一台 SSH 服务器</Typography><Typography color="text.secondary">服务器凭据仅保存在本机安全存储中</Typography><Button variant="contained" onClick={onAdd}>添加服务器</Button></Stack></Box>;
}
