import ContentCopyRounded from "@mui/icons-material/ContentCopyRounded";
import SearchRounded from "@mui/icons-material/SearchRounded";
import TerminalRounded from "@mui/icons-material/TerminalRounded";
import { Alert, Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, IconButton, InputAdornment, Menu, MenuItem, Paper, Stack, TextField, Tooltip, Typography, useTheme } from "@mui/material";
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
  const [pastePreview, setPastePreview] = React.useState<string>();
  const pasteProtectionRef = React.useRef(true);
  const auditEnabledRef = React.useRef(true);
  const sessionIdRef = React.useRef<string | undefined>(undefined);
  const pasteRequest = React.useRef(0);
  const activeRef = React.useRef(active);
  pasteProtectionRef.current = settings?.terminalPasteProtection !== false;
  auditEnabledRef.current = settings?.terminalCommandLogging !== false;
  activeRef.current = active;

  React.useEffect(() => {
    setError(""); setMenu(null); setPastePreview(undefined);
    if (!containerRef.current || host.status !== "connected") return;
    const container = containerRef.current;
    let disposed = false;
    let sessionId: string | undefined;
    let queuedBytes = 0;
    const pending: number[][] = [];
    let sendChain: Promise<unknown> = Promise.resolve();
    const terminal = new Terminal({ cursorBlink: true, convertEol: true, scrollback: settings?.terminalScrollback || 10000, fontFamily: '"JetBrains Mono", Consolas, monospace', fontSize: settings?.terminalFontSize || 13, lineHeight: 1.2, allowProposedApi: false, theme: terminalTheme(theme.palette.mode) });
    const fit = new FitAddon();
    const finder = new SearchAddon();
    terminal.loadAddon(fit); terminal.loadAddon(finder); terminal.loadAddon(new WebLinksAddon());
    terminal.open(containerRef.current); if (activeRef.current) { fit.fit(); terminal.focus(); }
    termRef.current = terminal; fitAddonRef.current = fit; searchAddonRef.current = finder;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const send = (bytes: number[]) => {
      if (disposed) return;
      if (!sessionId) {
        if (queuedBytes + bytes.length > 64 * 1024) { setError("SSH 会话仍在建立，暂存输入已达到 64 KB 上限"); return; }
        pending.push(bytes); queuedBytes += bytes.length; return;
      }
      const currentSession = sessionId;
      sendChain = sendChain.then(() => { if (!disposed) return api.terminalInput(currentSession, bytes); }).catch((reason) => { if (!disposed) setError(formatError(reason)); });
    };
    const inputSubscription = terminal.onData((data) => send(Array.from(encoder.encode(data))));
    const onPaste = (event: ClipboardEvent) => {
      if (disposed || !activeRef.current || !pasteProtectionRef.current) return;
      const text = event.clipboardData?.getData("text/plain") || "";
      if (!text) return;
      event.preventDefault();
      event.stopPropagation();
      setPastePreview(text);
    };
    // xterm installs its own paste listener on the terminal element. Capture
    // before it so the safety dialog cannot be bypassed by Ctrl/Cmd+V.
    container.addEventListener("paste", onPaste, true);

    void api.terminalOpen(host.id, terminal.cols, terminal.rows, settings?.terminalCommandLogging !== false, (event) => {
      if (!disposed) terminal.write(decoder.decode(new Uint8Array(event.payload), { stream: true }));
    }).then((id) => {
      if (disposed) { void api.terminalClose(id).catch(() => undefined); return; }
      sessionId = id;
      sessionIdRef.current = id;
      void api.terminalResize(id, terminal.cols, terminal.rows).catch((reason) => !disposed && setError(formatError(reason)));
      void api.terminalSetAudit(id, auditEnabledRef.current).catch((reason) => !disposed && setError(formatError(reason)));
      for (const bytes of pending.splice(0)) send(bytes);
      queuedBytes = 0;
    }).catch((reason) => {
      if (!disposed) { setError(formatError(reason)); terminal.writeln(`\r\n\x1b[31m${formatError(reason)}\x1b[0m`); }
    });

    const resizeSubscription = terminal.onResize(({ cols, rows }) => {
      if (sessionId) void api.terminalResize(sessionId, cols, rows).catch((reason) => !disposed && setError(formatError(reason)));
    });
    const observer = new ResizeObserver(() => {
      if (!activeRef.current) return;
      fit.fit();

    });
    observer.observe(containerRef.current);
    const onKey = (event: KeyboardEvent) => { if (activeRef.current && event.ctrlKey && event.shiftKey && event.key.toLowerCase() === "c" && terminal.hasSelection()) { void navigator.clipboard.writeText(terminal.getSelection()).catch((reason) => !disposed && setError(formatError(reason))); event.preventDefault(); } };
    window.addEventListener("keydown", onKey);
    return () => {
      pasteRequest.current += 1;
      disposed = true; inputSubscription.dispose(); resizeSubscription.dispose(); observer.disconnect(); window.removeEventListener("keydown", onKey); container.removeEventListener("paste", onPaste, true);
      const closingSession = sessionId;
      // Closing cancels a blocked backend write. Waiting for the input queue
      // first would keep a dead session alive indefinitely after disconnect.
      if (closingSession) void api.terminalClose(closingSession).catch(() => undefined);
      sessionIdRef.current = undefined;
      terminal.dispose(); termRef.current = null; fitAddonRef.current = null; searchAddonRef.current = null;
    };
  }, [host.id, host.status]);

  React.useEffect(() => {
    const sessionId = sessionIdRef.current;
    if (sessionId) void api.terminalSetAudit(sessionId, settings?.terminalCommandLogging !== false).catch((reason) => setError(formatError(reason)));
  }, [settings?.terminalCommandLogging]);

  React.useEffect(() => {
    if (!termRef.current) return;
    termRef.current.options.theme = terminalTheme(theme.palette.mode);
    if (settings?.terminalFontSize) termRef.current.options.fontSize = settings.terminalFontSize;
    if (settings?.terminalScrollback) termRef.current.options.scrollback = settings.terminalScrollback;
    if (activeRef.current) fitAddonRef.current?.fit();
  }, [theme.palette.mode, settings?.terminalFontSize, settings?.terminalScrollback]);

  React.useEffect(() => {
    if (!active) { pasteRequest.current += 1; setMenu(null); setPastePreview(undefined); return; }
    const frame = window.requestAnimationFrame(() => {
      fitAddonRef.current?.fit();
      termRef.current?.focus();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [active]);

  const copySelection = async () => { try { if (termRef.current?.hasSelection()) await navigator.clipboard.writeText(termRef.current.getSelection()); } catch (reason) { setError(formatError(reason)); } };
  const doSearch = () => { if (search) searchAddonRef.current?.findNext(search); };
  const requestPaste = async () => {
    const terminal = termRef.current;
    if (!terminal || !activeRef.current) return;
    const request = ++pasteRequest.current;
    let text = "";
    try { text = await navigator.clipboard.readText(); } catch (reason) { if (request === pasteRequest.current && activeRef.current && termRef.current === terminal) setError(formatError(reason)); return; }
    if (!text || request !== pasteRequest.current || !activeRef.current || termRef.current !== terminal) return;
    if (pasteProtectionRef.current) setPastePreview(text); else terminal.paste(text);
  };
  return <Stack sx={{ height: "100%", minHeight: 0 }} spacing={1}>
    <Stack direction="row" alignItems="center" spacing={1} useFlexGap flexWrap="wrap"><TerminalRounded color="primary"/><Typography variant="subtitle1" fontWeight={700}>{host.name}</Typography><Typography variant="caption" color="text.secondary" className="mono">{host.username}@{host.hostname}:{host.port}</Typography><Box sx={{ flex: 1 }}/><TextField size="small" label="搜索终端" value={search} onChange={(event) => setSearch(event.target.value)} onKeyDown={(event) => event.key === "Enter" && doSearch()} slotProps={{ input: { startAdornment: <InputAdornment position="start"><SearchRounded fontSize="small"/></InputAdornment> } }}/><Tooltip title="复制选中"><IconButton aria-label="复制终端选中内容" onClick={() => void copySelection()}><ContentCopyRounded fontSize="small"/></IconButton></Tooltip></Stack>
    {error && <Alert severity="error" onClose={() => setError("")}>{error}</Alert>}
    <Paper variant="outlined" onContextMenu={(event) => { event.preventDefault(); setMenu({ x: event.clientX, y: event.clientY }); }} sx={{ flex: 1, minHeight: 0, overflow: "hidden", bgcolor: "#0A0E14", borderRadius: "12px", p: 1.5 }}><Box ref={containerRef} sx={{ width: "100%", height: "100%" }}/></Paper>
    <Menu open={active && Boolean(menu)} onClose={() => setMenu(null)} anchorReference="anchorPosition" anchorPosition={menu ? { top: menu.y, left: menu.x } : undefined}><MenuItem onClick={() => { void copySelection(); setMenu(null); }}>复制</MenuItem><MenuItem onClick={() => { void requestPaste(); setMenu(null); }}>粘贴</MenuItem><MenuItem onClick={() => { termRef.current?.selectAll(); setMenu(null); }}>全选</MenuItem><MenuItem onClick={() => { termRef.current?.clear(); setMenu(null); }}>清屏</MenuItem></Menu>
    <Dialog open={active && pastePreview !== undefined} onClose={() => setPastePreview(undefined)} fullWidth maxWidth="sm"><DialogTitle>确认粘贴到 {host.name}</DialogTitle><DialogContent><Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>多行内容可能包含会立即执行的命令，请确认目标服务器和内容。</Typography><Paper variant="outlined" sx={{ p: 1.5, maxHeight: 260, overflow: "auto", bgcolor: "#0A0E14", color: "#D8DEE9" }}><Typography component="pre" className="mono" sx={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", m: 0 }}>{pastePreview}</Typography></Paper></DialogContent><DialogActions><Button onClick={() => setPastePreview(undefined)}>取消</Button><Button variant="contained" onClick={() => { if (activeRef.current && pastePreview !== undefined) termRef.current?.paste(pastePreview); setPastePreview(undefined); }}>发送</Button></DialogActions></Dialog>
  </Stack>;
}

function terminalTheme(mode: "light" | "dark") { return { background: mode === "dark" ? "#0A0E14" : "#10141C", foreground: "#D8DEE9", cursor: "#A8C7FA", selectionBackground: "#385175" }; }
