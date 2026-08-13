import { AddRounded, Circle, CloudQueueRounded, ExpandMoreRounded, FavoriteRounded, SearchRounded } from "@mui/icons-material";
import { Box, Button, Chip, Collapse, Divider, IconButton, InputAdornment, List, ListItemButton, ListItemText, Stack, TextField, Typography } from "@mui/material";
import React from "react";
import { useTranslation } from "react-i18next";
import { useAppStore } from "../store";

export default function ServerSidebar({ onAdd }: { onAdd: () => void }) {
  const { t } = useTranslation();
  const { hosts, selectedHostId, selectHost } = useAppStore();
  const [query, setQuery] = React.useState("");
  const groups = React.useMemo(() => {
    const result = new Map<string, typeof hosts>();
    hosts.filter((host) => `${host.name} ${host.hostname} ${host.tags.join(" ")}`.toLowerCase().includes(query.toLowerCase())).forEach((host) => result.set(host.groupName || "未分组", [...(result.get(host.groupName || "未分组") || []), host]));
    return result;
  }, [hosts, query]);
  return <Box sx={{ width: 278, minWidth: 278, height: "100%", display: "flex", flexDirection: "column", borderRight: 1, borderColor: "divider", bgcolor: "background.paper" }}>
    <Box sx={{ p: 1.5 }}>
      <TextField fullWidth size="small" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("searchServers")} slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchRounded fontSize="small" /></InputAdornment> } }} />
      <Button onClick={onAdd} fullWidth variant="contained" startIcon={<AddRounded />} sx={{ mt: 1.25 }}>{t("addServer")}</Button>
    </Box>
    <Divider />
    <Box sx={{ overflowY: "auto", flex: 1, py: 1 }}>
      {[...groups.entries()].map(([name, items]) => <Group key={name} name={name} count={items.length}>
        {items.sort((a, b) => Number(b.favorite) - Number(a.favorite)).map((host) => <ListItemButton key={host.id} selected={selectedHostId === host.id} onClick={() => selectHost(host.id)} sx={{ minHeight: 54 }}>
          <Box sx={{ width: 30, height: 30, mr: 1.25, borderRadius: 2, bgcolor: "action.hover", display: "grid", placeItems: "center" }}><CloudQueueRounded fontSize="small" color={selectedHostId === host.id ? "primary" : "inherit"} /></Box>
          <ListItemText primary={<Stack direction="row" alignItems="center" spacing={.5}><Typography variant="body2" fontWeight={600} noWrap>{host.name}</Typography>{host.favorite && <FavoriteRounded sx={{ fontSize: 13, color: "primary.main" }} />}</Stack>} secondary={<Typography variant="caption" color="text.secondary" className="mono" noWrap>{host.username}@{host.hostname}</Typography>} />
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
  return <><Stack direction="row" alignItems="center" sx={{ px: 1.5, py: .5 }}><IconButton size="small" onClick={() => setOpen(!open)}><ExpandMoreRounded sx={{ fontSize: 18, transform: open ? "none" : "rotate(-90deg)", transition: ".2s" }} /></IconButton><Typography variant="overline" color="text.secondary" fontWeight={700} sx={{ flex: 1, lineHeight: 2 }}>{name}</Typography><Typography variant="caption" color="text.disabled">{count}</Typography></Stack><Collapse in={open}><List disablePadding>{children}</List></Collapse></>;
}
