import { ContentCopyRounded, SearchRounded, TerminalRounded } from "@mui/icons-material";
import { Alert, Box, IconButton, InputAdornment, Menu, MenuItem, Paper, Stack, TextField, Tooltip, Typography, useTheme } from "@mui/material";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal } from "@xterm/xterm";
import React from "react";
import { api } from "../api";
import type { HostProfile } from "../types";

export default function TerminalView({ host }: { host: HostProfile }) {
  const theme = useTheme(); const containerRef = React.useRef<HTMLDivElement>(null); const termRef = React.useRef<Terminal | null>(null); const sessionRef = React.useRef<string | undefined>(undefined);
  const [search, setSearch] = React.useState(""); const [error, setError] = React.useState(""); const [menu, setMenu] = React.useState<{x:number;y:number}|null>(null);
  React.useEffect(() => {
    if (!containerRef.current) return;
    const terminal = new Terminal({ cursorBlink: true, convertEol: true, scrollback: 10000, fontFamily: '"JetBrains Mono", Consolas, monospace', fontSize: 13, lineHeight: 1.2, allowProposedApi: false, theme: { background: theme.palette.mode === "dark" ? "#0A0E14" : "#10141C", foreground: "#D8DEE9", cursor: "#A8C7FA", selectionBackground: "#385175" } });
    const fit = new FitAddon(), finder = new SearchAddon(); terminal.loadAddon(fit); terminal.loadAddon(finder); terminal.loadAddon(new WebLinksAddon()); terminal.open(containerRef.current); fit.fit(); terminal.focus(); termRef.current = terminal;
    const encoder = new TextEncoder(), decoder = new TextDecoder();
    api.terminalOpen(host.id, terminal.cols, terminal.rows, (event) => terminal.write(decoder.decode(new Uint8Array(event.payload)))).then((id) => { sessionRef.current = id; terminal.onData((data) => api.terminalInput(id, Array.from(encoder.encode(data)))); }).catch((e) => { setError(String(e)); terminal.writeln(`\r\n\x1b[31m${String(e)}\x1b[0m`); });
    const observer = new ResizeObserver(() => { fit.fit(); if (sessionRef.current) api.terminalResize(sessionRef.current, terminal.cols, terminal.rows); }); observer.observe(containerRef.current);
    const onKey = (e: KeyboardEvent) => { if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "c" && terminal.hasSelection()) { navigator.clipboard.writeText(terminal.getSelection()); e.preventDefault(); } };
    window.addEventListener("keydown", onKey);
    return () => { observer.disconnect(); window.removeEventListener("keydown", onKey); if (sessionRef.current) api.terminalClose(sessionRef.current); terminal.dispose(); };
  }, [host.id, theme.palette.mode]);
  const doSearch = () => { const addon = (termRef.current as unknown as { _core?: { _addonManager?: unknown } })?._core; void addon; /* SearchAddon is bound in effect; xterm native Ctrl+F can be extended later. */ };
  return <Stack sx={{ height: "100%", minHeight: 0 }} spacing={1}>
    <Stack direction="row" alignItems="center" spacing={1}><TerminalRounded color="primary" /><Typography variant="subtitle1" fontWeight={700}>{host.name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{host.username}@{host.hostname}:{host.port}</Typography><Box sx={{ flex: 1 }} /><TextField size="small" placeholder="搜索终端" value={search} onChange={(e) => setSearch(e.target.value)} onKeyDown={(e) => e.key === "Enter" && doSearch()} slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchRounded fontSize="small" /></InputAdornment> } }} /><Tooltip title="复制选中"><IconButton onClick={() => termRef.current?.hasSelection() && navigator.clipboard.writeText(termRef.current.getSelection())}><ContentCopyRounded fontSize="small" /></IconButton></Tooltip></Stack>
    {error && <Alert severity="error" onClose={() => setError("")}>{error}</Alert>}
    <Paper variant="outlined" onContextMenu={(e) => { e.preventDefault(); setMenu({ x: e.clientX, y: e.clientY }); }} sx={{ flex: 1, minHeight: 0, overflow: "hidden", bgcolor: "#0A0E14", borderRadius: 2 }}><Box ref={containerRef} sx={{ width: "100%", height: "100%" }} /></Paper>
    <Menu open={Boolean(menu)} onClose={() => setMenu(null)} anchorReference="anchorPosition" anchorPosition={menu ? { top: menu.y, left: menu.x } : undefined}><MenuItem onClick={() => { if (termRef.current?.hasSelection()) navigator.clipboard.writeText(termRef.current.getSelection()); setMenu(null); }}>复制</MenuItem><MenuItem onClick={async () => { const text = await navigator.clipboard.readText(); if (text) termRef.current?.paste(text); setMenu(null); }}>粘贴</MenuItem><MenuItem onClick={() => { termRef.current?.selectAll(); setMenu(null); }}>全选</MenuItem><MenuItem onClick={() => { termRef.current?.clear(); setMenu(null); }}>清屏</MenuItem></Menu>
  </Stack>;
}
