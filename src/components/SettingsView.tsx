import { AddRounded, CloseRounded, DeleteOutlineRounded, RestoreRounded, SettingsRounded } from "@mui/icons-material";
import { Alert, Box, Button, CardContent, Chip, Dialog, DialogContent, DialogTitle, Divider, FormControl, FormControlLabel, IconButton, InputLabel, MenuItem, Select, Slider, Stack, Switch, Tab, Tabs, TextField, Typography } from "@mui/material";
import React from "react";
import { useTranslation } from "react-i18next";
import { api } from "../api";
import { useAppStore } from "../store";
import type { AppSettings, CommandSuppressionRule } from "../types";

interface SettingsViewProps {
  open: boolean;
  onClose: () => void;
  onTheme: (theme: AppSettings["theme"]) => void;
}

export default function SettingsView({ open, onClose, onTheme }: SettingsViewProps) {
  const { i18n } = useTranslation();
  const settings = useAppStore((state) => state.settings);
  const setSettings = useAppStore((state) => state.setSettings);
  const [section, setSection] = React.useState(0);
  const [saving, setSaving] = React.useState(false);
  const [saved, setSaved] = React.useState(false);
  const [error, setError] = React.useState("");
  const pendingWrites = React.useRef(0);
  const closeRequested = React.useRef(false);
  const saveChain = React.useRef<Promise<unknown>>(Promise.resolve());

  const finishWrite = () => {
    pendingWrites.current = Math.max(0, pendingWrites.current - 1);
    if (pendingWrites.current === 0) {
      setSaving(false);
      setSaved(true);
      window.setTimeout(() => setSaved(false), 1200);
      if (closeRequested.current) {
        closeRequested.current = false;
        onClose();
      }
    }
  };

  const persist = (next: AppSettings) => {
    setSettings(next);
    pendingWrites.current += 1;
    setSaving(true);
    saveChain.current = saveChain.current
      .catch(() => undefined)
      .then(() => api.settingsUpdate(next))
      .catch((reason) => setError(String(reason)))
      .finally(finishWrite);
  };

  const update = (patch: Partial<AppSettings>) => {
    if (!settings) return;
    const next = { ...settings, ...patch };
    persist(next);
    if (patch.theme) onTheme(patch.theme);
    if (patch.locale) {
      void i18n.changeLanguage(patch.locale);
      localStorage.setItem("locale", patch.locale);
    }
  };

  const requestClose = () => {
    if (pendingWrites.current > 0) {
      closeRequested.current = true;
      return;
    }
    onClose();
  };

  const reset = () => {
    pendingWrites.current += 1;
    setSaving(true);
    saveChain.current = saveChain.current
      .catch(() => undefined)
      .then(() => api.settingsReset())
      .then((next) => {
        setSettings(next);
        onTheme(next.theme);
        void i18n.changeLanguage(next.locale);
      })
      .catch((reason) => setError(String(reason)))
      .finally(finishWrite);
  };

  return <Dialog open={open} onClose={requestClose} fullWidth maxWidth="md" slotProps={{ paper: { sx: { width: 860, maxHeight: "80vh", borderRadius: 3 } } }}>
    <DialogTitle sx={{ p: 0 }}>
      <Stack direction="row" alignItems="center" spacing={1.2} sx={{ px: 2.5, py: 1.5 }}>
        <SettingsRounded color="primary"/>
        <Typography variant="h6">设置</Typography>
        <Box sx={{ flex: 1 }}/>
        {saving ? <Chip size="small" color="primary" label="正在保存…"/> : saved ? <Chip size="small" color="success" label="已保存"/> : null}
        <Button size="small" startIcon={<RestoreRounded/>} onClick={reset} disabled={saving}>恢复默认</Button>
        <IconButton aria-label="关闭设置" onClick={requestClose}><CloseRounded/></IconButton>
      </Stack>
      <Divider/>
      <Tabs value={section} onChange={(_, value) => setSection(value)} variant="scrollable" sx={{ px: 1.5 }}>
        <Tab label="常规"/><Tab label="终端"/><Tab label="监控"/><Tab label="文件传输"/><Tab label="命令记录"/>
      </Tabs>
    </DialogTitle>
    <DialogContent dividers sx={{ p: 0 }}>
      {error && <Alert severity="error" onClose={() => setError("")} sx={{ m: 2 }}>{error}</Alert>}
      {!settings ? <Box sx={{ p: 4, textAlign: "center" }}>正在加载设置…</Box> : <CardContent sx={{ p: 3 }}>
        {section === 0 && <Stack spacing={2} maxWidth={620}>
          <FormControl fullWidth><InputLabel>语言</InputLabel><Select label="语言" value={settings.locale} onChange={(event) => update({ locale: event.target.value as "zh" | "en" })}><MenuItem value="zh">中文</MenuItem><MenuItem value="en">English</MenuItem></Select></FormControl>
          <FormControl fullWidth><InputLabel>主题</InputLabel><Select label="主题" value={settings.theme} onChange={(event) => update({ theme: event.target.value as AppSettings["theme"] })}><MenuItem value="system">跟随系统</MenuItem><MenuItem value="light">浅色</MenuItem><MenuItem value="dark">深色</MenuItem></Select></FormControl>
          <FormControl fullWidth><InputLabel>默认页面</InputLabel><Select label="默认页面" value={settings.defaultPage} onChange={(event) => update({ defaultPage: event.target.value as AppSettings["defaultPage"] })}><MenuItem value="monitor">资源监控</MenuItem><MenuItem value="terminal">终端</MenuItem><MenuItem value="sftp">文件管理</MenuItem></Select></FormControl>
        </Stack>}
        {section === 1 && <Stack spacing={2} maxWidth={680}>
          <Typography>字体大小：{settings.terminalFontSize}px</Typography><Slider value={settings.terminalFontSize} min={11} max={22} step={1} onChange={(_, value) => setSettings({ ...settings, terminalFontSize: value as number })} onChangeCommitted={(_, value) => update({ terminalFontSize: value as number })}/>
          <TextField label="滚动缓冲行数" type="number" value={settings.terminalScrollback} onChange={(event) => update({ terminalScrollback: Math.max(100, Number(event.target.value)) })}/>
          <FormControlLabel control={<Switch checked={settings.terminalPasteProtection} onChange={(event) => update({ terminalPasteProtection: event.target.checked })}/>} label="粘贴前确认"/>
          <FormControlLabel control={<Switch checked={settings.terminalCommandLogging} onChange={(event) => update({ terminalCommandLogging: event.target.checked })}/>} label="记录终端命令（隐私保护）"/>
        </Stack>}
        {section === 2 && <Stack spacing={2} maxWidth={680}><Typography>监控采样周期</Typography><Select value={settings.monitorIntervalSeconds} onChange={(event) => update({ monitorIntervalSeconds: Number(event.target.value) as AppSettings["monitorIntervalSeconds"] })}><MenuItem value={2}>2 秒</MenuItem><MenuItem value={5}>5 秒</MenuItem><MenuItem value={10}>10 秒</MenuItem><MenuItem value={30}>30 秒</MenuItem></Select><Alert severity="info">资源采样命令默认在命令记录台中隐藏，但仍保留在本地审计数据库。</Alert></Stack>}
        {section === 3 && <Stack spacing={2} maxWidth={680}><Typography>默认冲突处理</Typography><Select value={settings.transferConflictPolicy} onChange={(event) => update({ transferConflictPolicy: event.target.value as AppSettings["transferConflictPolicy"] })}><MenuItem value="ask">每次询问</MenuItem><MenuItem value="overwrite">覆盖</MenuItem><MenuItem value="skip">跳过</MenuItem><MenuItem value="rename">自动重命名</MenuItem><MenuItem value="resume">断点续传</MenuItem></Select><Alert severity="info">复制、删除和粘贴仅在同一服务器内执行。</Alert></Stack>}
        {section === 4 && <CommandSettings settings={settings} update={update}/>} 
      </CardContent>}
    </DialogContent>
  </Dialog>;
}

function CommandSettings({ settings, update }: { settings: AppSettings; update: (patch: Partial<AppSettings>) => void }) {
  const hosts = useAppStore((state) => state.hosts);
  const [draft, setDraft] = React.useState("");
  const [draftSource, setDraftSource] = React.useState<CommandSuppressionRule["source"]>();
  const [draftHost, setDraftHost] = React.useState<string>();
  const add = () => {
    if (!draft.trim() && !draftSource && !draftHost) return;
    const rule: CommandSuppressionRule = { id: crypto.randomUUID(), enabled: true, source: draftSource, hostId: draftHost, contains: draft.trim() || undefined };
    update({ suppressionRules: [...settings.suppressionRules, rule] });
    setDraft(""); setDraftSource(undefined); setDraftHost(undefined);
  };
  return <Stack spacing={2} maxWidth={760}>
    <Typography variant="subtitle1" fontWeight={700}>保留策略</Typography>
    <Stack direction="row" spacing={2}><TextField label="保留天数" type="number" value={settings.commandRetentionDays} onChange={(event) => update({ commandRetentionDays: Math.max(1, Number(event.target.value)) })}/><TextField label="最大容量 MB" type="number" value={settings.commandRetentionMb} onChange={(event) => update({ commandRetentionMb: Math.max(10, Number(event.target.value)) })}/></Stack>
    <Typography variant="subtitle1" fontWeight={700}>屏蔽规则</Typography>
    <Typography variant="body2" color="text.secondary">模块、服务器和命令文本条件同时满足时隐藏；规则不会删除审计记录。</Typography>
    <Stack direction="row" spacing={1}><Select size="small" displayEmpty value={draftSource || ""} onChange={(event) => setDraftSource((event.target.value || undefined) as CommandSuppressionRule["source"])}><MenuItem value="">全部模块</MenuItem>{["connection", "terminal", "monitor", "firewall", "sftp", "forward", "system"].map((source) => <MenuItem key={source} value={source}>{source}</MenuItem>)}</Select><Select size="small" displayEmpty value={draftHost || ""} onChange={(event) => setDraftHost(event.target.value || undefined)}><MenuItem value="">全部服务器</MenuItem>{hosts.map((host) => <MenuItem key={host.id} value={host.id}>{host.name}</MenuItem>)}</Select><TextField fullWidth size="small" label="命令包含文本" value={draft} onChange={(event) => setDraft(event.target.value)} onKeyDown={(event) => event.key === "Enter" && add()}/><Button variant="contained" startIcon={<AddRounded/>} onClick={add}>添加</Button></Stack>
    {settings.suppressionRules.map((rule) => <Stack key={rule.id} direction="row" alignItems="center" spacing={1}><Switch checked={rule.enabled} onChange={(event) => update({ suppressionRules: settings.suppressionRules.map((item) => item.id === rule.id ? { ...item, enabled: event.target.checked } : item) })}/><Chip label={`${rule.source || "全部模块"} · ${rule.hostId ? hosts.find((host) => host.id === rule.hostId)?.name || "指定服务器" : "全部服务器"} · ${rule.contains || "全部命令"}`} sx={{ flex: 1, justifyContent: "flex-start" }}/><IconButton color="error" onClick={() => update({ suppressionRules: settings.suppressionRules.filter((item) => item.id !== rule.id) })}><DeleteOutlineRounded/></IconButton></Stack>)}
    <Divider/><Alert severity="warning">清空命令记录会永久删除 SQLite 中的全部历史。</Alert>
  </Stack>;
}
