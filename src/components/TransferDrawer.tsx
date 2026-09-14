import CancelRounded from "@mui/icons-material/CancelRounded";
import CheckCircleRounded from "@mui/icons-material/CheckCircleRounded";
import CloudDownloadRounded from "@mui/icons-material/CloudDownloadRounded";
import CloudUploadRounded from "@mui/icons-material/CloudUploadRounded";
import ErrorRounded from "@mui/icons-material/ErrorRounded";
import ExpandLessRounded from "@mui/icons-material/ExpandLessRounded";
import ExpandMoreRounded from "@mui/icons-material/ExpandMoreRounded";
import FolderZipRounded from "@mui/icons-material/FolderZipRounded";
import { Box, Button, Chip, Collapse, Divider, IconButton, LinearProgress, Paper, Stack, Typography } from "@mui/material";
import React from "react";
import { api } from "../api";
import { useAppStore, type TransferTaskView } from "../store";
import { formatBytes, formatError } from "../utils";

export default function TransferDrawer() {
  const tasks = useAppStore((s) => s.transfers); const clear = useAppStore((s) => s.clearCompletedTransfers);
  const [expanded, setExpanded] = React.useState(true); const items = Object.values(tasks).sort((a, b) => b.updatedAt - a.updatedAt);
  if (!items.length) return null;
  const active = items.filter((task) => ["queued", "running"].includes(task.progress.status));
  return <Paper square variant="outlined" sx={{ borderLeft: 0, borderRight: 0, borderRadius: 0, zIndex: 2 }}>
    <Stack direction="row" alignItems="center" spacing={1} sx={{ px: 1.5, py: .7 }}><FolderZipRounded color="primary" fontSize="small"/><Typography variant="subtitle2">文件传输</Typography><Chip size="small" label={`${active.length} 个进行中`} color={active.length ? "primary" : "default"}/><Box sx={{ flex: 1 }}/><Button size="small" onClick={clear} disabled={!items.some((task) => ["completed", "error", "cancelled"].includes(task.progress.status))}>清除已完成</Button><IconButton aria-label={expanded ? "收起文件传输" : "展开文件传输"} size="small" onClick={() => setExpanded((value) => !value)}>{expanded ? <ExpandMoreRounded/> : <ExpandLessRounded/>}</IconButton></Stack>
    <Collapse in={expanded}><Divider/><Stack spacing={1} sx={{ px: 1.5, py: 1, maxHeight: 230, overflow: "auto" }}>{items.map((task) => <TransferRow key={task.progress.transferId} task={task}/>)}</Stack></Collapse>
  </Paper>;
}

function TransferRow({ task }: { task: TransferTaskView }) {
  const { progress } = task; const [error, setError] = React.useState(""); const [cancelling, setCancelling] = React.useState(false);
  React.useEffect(() => { if (["completed", "error", "cancelled"].includes(progress.status)) setCancelling(false); }, [progress.status]);
  const running = progress.status === "running" || progress.status === "queued"; const determinate = progress.total > 0; const percent = determinate ? Math.min(100, (progress.transferred / progress.total) * 100) : 0; const remaining = task.speed > 0 && determinate ? Math.max(0, (progress.total - progress.transferred) / task.speed) : 0;
  const cancel = async () => { setCancelling(true); try { await api.sftpCancel(progress.transferId); } catch (reason) { setCancelling(false); setError(formatError(reason)); } };
  const status = progress.status === "completed" ? "已完成" : progress.status === "cancelled" ? "已取消" : progress.status === "error" ? "失败" : progress.status === "queued" ? "排队中" : "传输中";
  return <Stack spacing={.4}><Stack direction="row" alignItems="center" spacing={1}><Box sx={{ display: "grid", placeItems: "center" }}>{progress.direction === "upload" ? <CloudUploadRounded color="primary" fontSize="small"/> : <CloudDownloadRounded color="primary" fontSize="small"/>}</Box><Typography variant="body2" noWrap sx={{ maxWidth: 280, flex: 1 }} title={progress.currentPath}>{progress.currentPath || "准备传输"}</Typography><Typography variant="caption" color="text.secondary">{formatBytes(progress.transferred)} / {formatBytes(progress.total)}</Typography><Chip size="small" variant="outlined" icon={progress.status === "completed" ? <CheckCircleRounded/> : progress.status === "error" ? <ErrorRounded/> : undefined} label={status}/>{running && <Button size="small" color="error" startIcon={<CancelRounded/>} disabled={cancelling} onClick={cancel}>{cancelling ? "正在取消" : "取消"}</Button>}</Stack><LinearProgress aria-label="文件传输进度" variant={determinate || !running ? "determinate" : "indeterminate"} value={progress.status === "completed" ? 100 : percent} sx={{ height: 7, borderRadius: 4 }}/><Stack direction="row" spacing={2}><Typography variant="caption" color="text.secondary">{progress.fileCount ? `文件 ${progress.fileIndex}/${progress.fileCount}` : ""}</Typography><Typography variant="caption" color="text.secondary">{running && task.speed > 0 ? `${formatBytes(task.speed, true)} · ETA ${remaining < 60 ? `${Math.ceil(remaining)} 秒` : `${Math.ceil(remaining / 60)} 分钟`}` : running ? "等待速度数据" : status}</Typography>{(error || progress.error) && <Typography role="alert" variant="caption" color="error">{error || progress.error}</Typography>}</Stack></Stack>;
}
