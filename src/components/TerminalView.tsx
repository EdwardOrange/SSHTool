import { ContentCopyRounded, SearchRounded, TerminalRounded } from "@mui/icons-material";
import { Alert, Box, IconButton, InputAdornment, Menu, MenuItem, Paper, Stack, TextField, Tooltip, Typography, useTheme } from "@mui/material";
import { FitAddon } from "@xterm/addon-fit";
import { SearchAddon } from "@xterm/addon-search";
import { WebLinksAddon } from "@xterm/addon-web-links";
import { Terminal } from "@xterm/xterm";
import React from "react";
import { api } from "../api";
import { useAppStore } from "../store";
import type { HostProfile } from "../types";
import { formatError } from "../utils";

export default function TerminalView({ host, active = true }: { host: HostProfile; active?: boolean }) {
  const theme = useTheme();
  const settings = useAppStore((state) => state.settings);
  const containerRef = React.useRef<HTMLDivElement>(null);
  const termRef = React.useRef<Terminal | null>(null);
  const fitAddonRef = React.useRef<FitAddon | null>(null);
  const searchAddonRef = React.useRef<SearchAddon | null>(null);
  const [search, setSearch] = React.useState("");
  const [error, setError] = React.useState("");
  const [menu, setMenu] = React.useState<{ x: number; y: number } | null>(null);

  React.useEffect(() => {
    if (!containerRef.current) return;
    let disposed = false;
    let sessionId: string | undefined;
    let queuedBytes = 0;
    const pending: number[][] = [];
    let sendChain: Promise<unknown> = Promise.resolve();
    const terminal = new Terminal({ cursorBlink: true, convertEol: true, scrollback: settings?.terminalScrollback || 10000, fontFamily: '"JetBrains Mono", Consolas, monospace', fontSize: settings?.terminalFontSize || 13, lineHeight: 1.2, allowProposedApi: false, theme: terminalTheme(theme.palette.mode) });
    const fit = new FitAddon();
    const finder = new SearchAddon();
    terminal.loadAddon(fit); terminal.loadAddon(finder); terminal.loadAddon(new WebLinksAddon());
    terminal.open(containerRef.current); fit.fit(); terminal.focus();
    termRef.current = terminal; fitAddonRef.current = fit; searchAddonRef.current = finder;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const send = (bytes: number[]) => {
      if (!sessionId) {
        if (queuedBytes + bytes.length > 64 * 1024) { setError("SSH 会话仍在建立，暂存输入已达到 64 KB 上限"); return; }
        pending.push(bytes); queuedBytes += bytes.length; return;
      }
      const currentSession = sessionId;
      sendChain = sendChain.then(() => api.terminalInput(currentSession, bytes)).catch((reason) => { if (!disposed) setError(formatError(reason)); });
    };
    const inputSubscription = terminal.onData((data) => send(Array.from(encoder.encode(data))));

    void api.terminalOpen(host.id, terminal.cols, terminal.rows, settings?.terminalCommandLogging !== false, (event) => {
      if (!disposed) terminal.write(decoder.decode(new Uint8Array(event.payload), { stream: true }));
    }).then((id) => {
      if (disposed) { void api.terminalClose(id); return; }
      sessionId = id;
      for (const bytes of pending.splice(0)) send(bytes);
      queuedBytes = 0;
    }).catch((reason) => {
      if (!disposed) { setError(formatError(reason)); terminal.writeln(`\r\n\x1b[31m${formatError(reason)}\x1b[0m`); }
    });

    const observer = new ResizeObserver(() => { fit.fit(); if (sessionId) void api.terminalResize(sessionId, terminal.cols, terminal.rows); });
    observer.observe(containerRef.current);
    const onKey = (event: KeyboardEvent) => { if (event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "c" && terminal.hasSelection()) { void navigator.clipboard.writeText(terminal.getSelection()); event.preventDefault(); } };
    window.addEventListener("keydown", onKey);
    return () => {
      disposed = true; inputSubscription.dispose(); observer.disconnect(); window.removeEventListener("keydown", onKey);
      const closingSession = sessionId;
      if (closingSession) void sendChain.finally(() => api.terminalClose(closingSession));
      terminal.dispose(); termRef.current = null; fitAddonRef.current = null; searchAddonRef.current = null;
    };
  }, [host.id]);

  React.useEffect(() => {
    if (!termRef.current) return;
    termRef.current.options.theme = terminalTheme(theme.palette.mode);
    if (settings?.terminalFontSize) termRef.current.options.fontSize = settings.terminalFontSize;
    if (settings?.terminalScrollback) termRef.current.options.scrollback = settings.terminalScrollback;
  }, [theme.palette.mode, settings?.terminalFontSize, settings?.terminalScrollback]);

  React.useEffect(() => {
    if (!active) return;
    const frame = window.requestAnimationFrame(() => {
      fitAddonRef.current?.fit();
      termRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [active]);

  const doSearch = () => { if (search) searchAddonRef.current?.findNext(search); };
  return <Stack sx={{ height: "100%", minHeight: 0 }} spacing={1}>
    <Stack direction="row" alignItems="center" spacing={1}><TerminalRounded color="primary"/><Typography variant="subtitle1" fontWeight={700}>{host.name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{host.username}@{host.hostname}:{host.port}</Typography><Box sx={{ flex: 1 }}/><TextField size="small" placeholder="搜索终端" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && doSearch()} slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchRounded fontSize="small"/></InputAdornment> } }}/><Tooltip title="复制选中"><IconButton onClick={() => termRef.current?.hasSelection() && navigator.clipboard.writeText(termRef.current.getSelection())}><ContentCopyRounded fontSize="small"/></IconButton></Tooltip></Stack>
    {error && <Alert severity="error" onClose={() => setError("")}>{error}</Alert>}
    <Paper variant="outlined" onContextMenu={(event) => { event.preventDefault(); setMenu({ x: event.clientX, y: event.clientY }); }} sx={{ flex: 1, minHeight: 0, overflow: "hidden", bgcolor: "#0A0E14", borderRadius: 2 }}><Box ref={containerRef} sx={{ width: "100%", height: "100%" }}/></Paper>
    <Menu open={Boolean(menu)} onClose={() => setMenu(null)} anchorReference="anchorPosition" anchorPosition={menu ? { top: menu.y, left: menu.x } : undefined}><MenuItem onClick={() => { if (termRef.current?.hasSelection()) void navigator.clipboard.writeText(termRef.current.getSelection()); setMenu(null); }}>复制</MenuItem><MenuItem onClick={async () => { const text = await navigator.clipboard.readText(); if (text) termRef.current?.paste(text); setMenu(null); }}>粘贴</MenuItem><MenuItem onClick={() => { termRef.current?.selectAll(); setMenu(null); }}>全选</MenuItem><MenuItem onClick={() => { termRef.current?.clear(); setMenu(null); }}>清屏</MenuItem></Menu>
  </Stack>;
}

function terminalTheme(mode: "light" | "dark") { return { background: mode === "dark" ? "#0A0E14" : "#10141C", foreground: "#D8DEE9", cursor: "#A8C7FA", selectionBackground: "#385175" }; }
