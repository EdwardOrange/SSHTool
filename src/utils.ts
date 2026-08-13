export const formatBytes = (value: number, perSecond = false) => {
  if (!Number.isFinite(value)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Math.max(0, value), i = 0;
  while (size >= 1000 && i < units.length - 1) { size /= 1000; i++; }
  return `${size >= 100 || i === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[i]}${perSecond ? "/s" : ""}`;
};
export const formatDuration = (seconds: number) => {
  const days = Math.floor(seconds / 86400), hours = Math.floor((seconds % 86400) / 3600), minutes = Math.floor((seconds % 3600) / 60);
  return days > 0 ? `${days}天 ${hours}小时` : `${hours}小时 ${minutes}分钟`;
};
export const shortTime = (iso: string) => new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
export const statusColor = (status: string) => status === "connected" || status === "success" ? "success.main" : status === "connecting" || status === "running" ? "warning.main" : status === "error" ? "error.main" : "text.disabled";
export const formatError = (error: unknown): string => {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  if (error && typeof error === "object") {
    const value = error as { message?: unknown; kind?: unknown; error?: unknown };
    if (typeof value.message === "string") return value.message;
    if (typeof value.error === "string") return value.error;
    try { return JSON.stringify(error); } catch { return "操作失败"; }
  }
  return String(error);
};
