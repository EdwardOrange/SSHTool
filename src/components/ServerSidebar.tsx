import AddRounded from "@mui/icons-material/AddRounded";
import Circle from "@mui/icons-material/Circle";
import CloudQueueRounded from "@mui/icons-material/CloudQueueRounded";
import ExpandMoreRounded from "@mui/icons-material/ExpandMoreRounded";
import FavoriteRounded from "@mui/icons-material/FavoriteRounded";
import SearchRounded from "@mui/icons-material/SearchRounded";
import { Box, Button, Chip, Collapse, Divider, IconButton, InputAdornment, List, ListItemButton, ListItemText, Stack, TextField, Typography } from "@mui/material";
import React from "react";
import { useTranslation } from "react-i18next";
import { useAppStore } from "../store";

export default function ServerSidebar({ onAdd, onSelect }: { onAdd: () => void; onSelect?: () => void }) {
  const { t } = useTranslation();
  const hosts = useAppStore((s) => s.hosts);
  const selectedHostId = useAppStore((s) => s.selectedHostId);
  const selectHost = useAppStore((s) => s.selectHost);
  const [query, setQuery] = React.useState("");
  const groups = React.useMemo(() => {
    const result = new Map<string, typeof hosts>();
    hosts.filter((host) => `${host.name} ${host.hostname} ${host.tags.join(" ")}`.toLowerCase().includes(query.toLowerCase())).forEach((host) => result.set(host.groupName || "未分组", [...(result.get(host.groupName || "未分组") || []), host]));
    return result;
  }, [hosts, query]);
  return <Box component="nav" aria-label="服务器列表" sx={{ width: 280, maxWidth: "85vw", height: "100%", display: "flex", flexDirection: "column", bgcolor: "background.paper", flexShrink: 0 }}>
    <Box sx={{ p: 2 }}>
      <Typography variant="subtitle2" color="text.secondary" sx={{ mb: 2 }}>工作空间 · 服务器</Typography>
      <TextField fullWidth size="small" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("searchServers")} sx={{ "& .MuiOutlinedInput-root": { borderRadius: 999 } }} slotProps={{ htmlInput: { "aria-label": t("searchServers") }, input: { startAdornment: <InputAdornment position="start"><SearchRounded fontSize="small" /></InputAdornment> } }} />
      <Button onClick={onAdd} fullWidth variant="contained" startIcon={<AddRounded />} sx={{ mt: 1.25 }}>{t("addServer")}</Button>
    </Box>
    <Divider />
    <Box sx={{ overflowY: "auto", flex: 1, py: 1 }}>
      {[...groups.entries()].map(([name, items]) => <Group key={name} name={name} count={items.length}>
        {items.sort((a, b) => Number(b.favorite) - Number(a.favorite)).map((host) => <ListItemButton key={host.id} aria-current={selectedHostId === host.id ? "true" : undefined} aria-label={`${host.name}，${host.status === "connected" ? "已连接" : host.status === "error" ? "连接失败" : "未连接"}`} selected={selectedHostId === host.id} onClick={() => { selectHost(host.id); onSelect?.(); }} sx={{ minHeight: 64, mb: .5 }}>
          <Box sx={{ width: 30, height: 30, mr: 1.25, borderRadius: 2, bgcolor: "action.hover", display: "grid", placeItems: "center" }}><CloudQueueRounded fontSize="small" color={selectedHostId === host.id ? "primary" : "inherit"} /></Box>
          <ListItemText sx={{ minWidth: 0 }} disableTypography primary={<Stack direction="row" alignItems="center" spacing={.5}><Typography variant="body2" fontWeight={500} noWrap>{host.name}</Typography>{host.favorite && <FavoriteRounded sx={{ fontSize: 13, color: "primary.main" }} />}</Stack>} secondary={<Typography variant="caption" color="text.secondary" className="mono" noWrap>{host.username}@{host.hostname}</Typography>} />
          <Circle sx={{ fontSize: 9, color: host.status === "connected" ? "success.main" : host.status === "error" ? "error.main" : "text.disabled" }} />
        </ListItemButton>)}
      </Group>)}
      {groups.size === 0 && <Typography variant="body2" color="text.secondary" textAlign="center" sx={{ mt: 6 }}>没有匹配的服务器</Typography>}
    </Box>
    <Divider />
    <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ px: 2, py: 1.25 }}><Typography variant="caption" color="text.secondary">{hosts.length} 台服务器</Typography><Chip size="small" label={`${hosts.filter((h) => h.status === "connected").length} 在线`} color="success" variant="outlined" /></Stack>
  </Box>;
}

function Group({ name, count, children }: React.PropsWithChildren<{ name: string; count: number }>) {
  const [open, setOpen] = React.useState(true);
  return <><Stack direction="row" alignItems="center" sx={{ px: 1.5, py: .5 }}><IconButton size="small" aria-label={`${open ? "收起" : "展开"}${name}`} aria-expanded={open} onClick={() => setOpen(!open)}><ExpandMoreRounded sx={{ fontSize: 20, transform: open ? "none" : "rotate(-90deg)", transition: "transform 200ms cubic-bezier(0.2, 0, 0, 1)" }} /></IconButton><Typography variant="subtitle2" color="text.secondary" sx={{ flex: 1 }}>{name}</Typography><Typography variant="caption" color="text.secondary">{count}</Typography></Stack><Collapse in={open}><List disablePadding>{children}</List></Collapse></>;
}
