import { Circle, CloudDownloadRounded, CloudUploadRounded, MemoryRounded, ScheduleRounded } from "@mui/icons-material";
import { Box, Card, CardContent, Chip, LinearProgress, Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography, useTheme } from "@mui/material";
import React from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api";
import { useAppStore } from "../store";
import type { HostProfile, MetricSnapshot } from "../types";
import { formatBytes, formatDuration, shortTime } from "../utils";

const EMPTY_METRICS: MetricSnapshot[] = [];

export default function MonitorView({ host }: { host: HostProfile }) {
  const theme = useTheme(); const addMetric = useAppStore((s) => s.addMetric); const points = useAppStore((s) => s.metrics[host.id] ?? EMPTY_METRICS); const current = points.at(-1);
  React.useEffect(() => {
    if (host.status !== "connected") return;
    let alive = true;
    api.monitorStart(host.id, (e) => alive && addMetric(e.payload)).catch(() => undefined);
    return () => {
      alive = false;
      void api.monitorStop(host.id).catch(() => undefined);
    };
  }, [host.id, host.status, addMetric]);
  if (host.status !== "connected") {
    return <Box sx={{ height: "100%", display: "grid", placeItems: "center" }}>
      <Paper variant="outlined" sx={{ maxWidth: 520, p: 4, textAlign: "center" }}>
        <Stack spacing={1.5} alignItems="center">
          <MemoryRounded color="disabled" sx={{ fontSize: 48 }} />
          <Typography variant="h6">服务器尚未连接</Typography>
          <Typography color="text.secondary">请先点击右上角的“连接”，连接成功后将自动开始实时资源监控。</Typography>
        </Stack>
      </Paper>
    </Box>;
  }
  const graphData = points.slice(-60).map((p) => ({ ...p, time: shortTime(p.timestamp), rx: p.rxBytesPerSec / 1_000_000, tx: p.txBytesPerSec / 1_000_000 }));
  return <Box sx={{ overflowY: "auto", height: "100%", pr: .5 }}>
    <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 2 }}><Typography variant="h6">{host.name} · 资源监控</Typography><Chip size="small" color="success" icon={<Circle className="live-dot" sx={{ fontSize: "8px!important" }} />} label="2 秒实时" variant="outlined" /><Box sx={{ flex: 1 }} />{current && <Stack direction="row" alignItems="center" spacing={.5}><ScheduleRounded fontSize="small" color="disabled" /><Typography variant="caption" color="text.secondary">运行 {formatDuration(current.uptimeSeconds)}</Typography></Stack>}</Stack>
    <Stack direction={{ xs: "column", md: "row" }} spacing={1.5}>{[
      ["CPU", current?.cpuPercent || 0, `${(current?.load1 || 0).toFixed(2)} load`, "#5B8DEF"],
      ["内存", current?.memoryPercent || 0, current ? `${formatBytes(current.memoryUsedBytes)} / ${formatBytes(current.memoryTotalBytes)}` : "—", "#8B6CE7"],
      ["磁盘", current?.diskPercent || 0, current ? `${formatBytes(current.diskUsedBytes)} / ${formatBytes(current.diskTotalBytes)}` : "—", "#E49B37"],
    ].map(([label, value, detail, color]) => <MetricCard key={String(label)} label={String(label)} value={Number(value)} detail={String(detail)} color={String(color)} />)}
      <Card variant="outlined" sx={{ flex: 1, minWidth: 220 }}><CardContent><Stack direction="row" alignItems="center" spacing={1}><MemoryRounded color="primary" /><Typography variant="subtitle2">网络与连接</Typography></Stack><Stack direction="row" spacing={2} sx={{ mt: 1.4 }}><Stack><Stack direction="row" spacing={.5}><CloudDownloadRounded fontSize="small" color="success"/><Typography variant="caption">接收</Typography></Stack><Typography variant="h6">{formatBytes(current?.rxBytesPerSec || 0, true)}</Typography></Stack><Stack><Stack direction="row" spacing={.5}><CloudUploadRounded fontSize="small" color="primary"/><Typography variant="caption">发送</Typography></Stack><Typography variant="h6">{formatBytes(current?.txBytesPerSec || 0, true)}</Typography></Stack></Stack><Typography variant="caption" color="text.secondary">{current?.connectionCount || 0} 个活动连接</Typography></CardContent></Card>
    </Stack>
    <Stack direction={{ xs: "column", lg: "row" }} spacing={1.5} sx={{ mt: 1.5 }}>
      <ChartCard title="CPU 与内存利用率" data={graphData} areas={[{ key: "cpuPercent", color: "#5B8DEF", name: "CPU %" }, { key: "memoryPercent", color: "#8B6CE7", name: "内存 %" }]} domain={[0, 100]} themeMode={theme.palette.mode} />
      <ChartCard title="网络吞吐量" data={graphData} areas={[{ key: "rx", color: "#25A56A", name: "接收 MB/s" }, { key: "tx", color: "#2E5BFF", name: "发送 MB/s" }]} themeMode={theme.palette.mode} />
    </Stack>
    <Stack direction={{ xs: "column", lg: "row" }} spacing={1.5} sx={{ mt: 1.5, pb: 2 }}>
      <TableCard title="活动连接"><Table size="small"><TableHead><TableRow><TableCell>协议</TableCell><TableCell>状态</TableCell><TableCell>本地地址</TableCell><TableCell>远程地址</TableCell><TableCell>进程</TableCell></TableRow></TableHead><TableBody>{(current?.connections || []).map((c, i) => <TableRow key={i}><TableCell className="mono">{c.protocol}</TableCell><TableCell><Chip size="small" label={c.state} color={c.state === "ESTAB" ? "success" : "default"} variant="outlined" /></TableCell><TableCell className="mono">{c.localAddress}</TableCell><TableCell className="mono">{c.remoteAddress}</TableCell><TableCell>{c.process || "权限不足"}</TableCell></TableRow>)}</TableBody></Table></TableCard>
      <TableCard title="高占用进程"><Table size="small"><TableHead><TableRow><TableCell>PID</TableCell><TableCell>进程</TableCell><TableCell>CPU</TableCell><TableCell>内存</TableCell></TableRow></TableHead><TableBody>{(current?.topProcesses || []).map((p) => <TableRow key={p.pid}><TableCell className="mono">{p.pid}</TableCell><TableCell>{p.name}</TableCell><TableCell>{p.cpuPercent.toFixed(1)}%</TableCell><TableCell>{p.memoryPercent.toFixed(1)}%</TableCell></TableRow>)}</TableBody></Table></TableCard>
    </Stack>
  </Box>;
}

function MetricCard({ label, value, detail, color }: { label: string; value: number; detail: string; color: string }) { return <Card variant="outlined" sx={{ flex: 1, minWidth: 190 }}><CardContent><Stack direction="row" justifyContent="space-between"><Typography variant="subtitle2">{label}</Typography><Typography variant="h5" sx={{ color }}>{value.toFixed(1)}%</Typography></Stack><LinearProgress variant="determinate" value={value} sx={{ my: 1.3, height: 7, borderRadius: 8, "& .MuiLinearProgress-bar": { bgcolor: color } }} /><Typography variant="caption" color="text.secondary">{detail}</Typography></CardContent></Card>; }
function ChartCard({ title, data, areas, domain, themeMode }: { title: string; data: Record<string, unknown>[]; areas: { key: string; color: string; name: string }[]; domain?: [number, number]; themeMode: string }) { return <Paper variant="outlined" sx={{ p: 2, height: 272, flex: 1, minWidth: 0 }}><Typography variant="subtitle2" sx={{ mb: 1 }}>{title}</Typography><ResponsiveContainer width="100%" height="90%"><AreaChart data={data}><defs>{areas.map((a) => <linearGradient key={a.key} id={`g-${a.key}`} x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor={a.color} stopOpacity={.32}/><stop offset="95%" stopColor={a.color} stopOpacity={0}/></linearGradient>)}</defs><CartesianGrid strokeDasharray="3 3" stroke={themeMode === "dark" ? "#29313D" : "#E8EBF0"} vertical={false}/><XAxis dataKey="time" tick={{ fontSize: 10 }} minTickGap={40}/><YAxis domain={domain} tick={{ fontSize: 10 }} width={36}/><Tooltip contentStyle={{ background: themeMode === "dark" ? "#141A24" : "#fff", borderRadius: 10, border: "1px solid #7774" }}/>{areas.map((a) => <Area key={a.key} type="monotone" dataKey={a.key} name={a.name} stroke={a.color} fill={`url(#g-${a.key})`} strokeWidth={2} isAnimationActive={false}/>)}</AreaChart></ResponsiveContainer></Paper>; }
function TableCard({ title, children }: React.PropsWithChildren<{ title: string }>) { return <Paper variant="outlined" sx={{ flex: 1, minWidth: 0, overflow: "hidden" }}><Typography variant="subtitle2" sx={{ px: 2, py: 1.5, borderBottom: 1, borderColor: "divider" }}>{title}</Typography><Box sx={{ overflowX: "auto" }}>{children}</Box></Paper>; }
