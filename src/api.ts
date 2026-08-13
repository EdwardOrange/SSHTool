import { invoke, Channel } from "@tauri-apps/api/core";
import type { AppSettings, CommandRecord, CommandSuppressionRule, FirewallPlan, FirewallRuleInput, FirewallState, ForwardingProfile, HostDraft, HostProfile, MetricSnapshot, SftpEntry, StreamEnvelope, TransferProgress } from "./types";

const isTauri = () => "__TAURI_INTERNALS__" in window;
const now = () => new Date().toISOString();
export const defaultSettings = (): AppSettings => ({ version: 1, locale: "zh", theme: "system", defaultPage: "monitor", terminalFontSize: 13, terminalScrollback: 10000, terminalPasteProtection: true, terminalCommandLogging: true, monitorIntervalSeconds: 2, transferConflictPolicy: "ask", commandRetentionDays: 7, commandRetentionMb: 100, suppressionRules: [{ id: "monitor-sample", enabled: true, source: "monitor", contains: "cat /proc/stat" }] });
const demoHosts: HostProfile[] = [
  { id: "demo-prod", name: "生产网关", hostname: "10.0.1.12", port: 22, username: "ops", groupName: "生产环境", tags: ["gateway", "ubuntu"], favorite: true, authMethod: "key", jumpHosts: [], status: "connected", lastConnectedAt: now(), createdAt: now(), updatedAt: now() },
  { id: "demo-db", name: "数据节点", hostname: "10.0.1.24", port: 22, username: "admin", groupName: "生产环境", tags: ["database"], favorite: true, authMethod: "key", jumpHosts: [], status: "disconnected", createdAt: now(), updatedAt: now() },
  { id: "demo-test", name: "测试服务器", hostname: "192.168.56.10", port: 22, username: "dev", groupName: "测试环境", tags: ["debian"], favorite: false, authMethod: "password", jumpHosts: [], status: "disconnected", createdAt: now(), updatedAt: now() },
];
let mockHosts = [...demoHosts];

export const api = {
  async hostsList(): Promise<HostProfile[]> { return isTauri() ? invoke("hosts_list") : mockHosts; },
  async hostsUpsert(draft: HostDraft): Promise<HostProfile> {
    if (isTauri()) return invoke("hosts_upsert", { draft });
    const existing = mockHosts.find((h) => h.id === draft.id);
    const host: HostProfile = { ...draft, id: draft.id || crypto.randomUUID(), jumpHosts: draft.jumpHosts || [], status: existing?.status || "disconnected", createdAt: existing?.createdAt || now(), updatedAt: now() };
    delete (host as HostProfile & { password?: string }).password;
    mockHosts = existing ? mockHosts.map((h) => h.id === host.id ? host : h) : [...mockHosts, host];
    return host;
  },
  async hostsDelete(id: string) { if (isTauri()) await invoke("hosts_delete", { id }); else mockHosts = mockHosts.filter((h) => h.id !== id); },
  async sshConnect(hostId: string, password?: string) { if (isTauri()) return invoke("ssh_connect", { hostId, password }); await new Promise((r) => setTimeout(r, 500)); },
  async sshDisconnect(hostId: string) { if (isTauri()) await invoke("ssh_disconnect", { hostId }); },
  async terminalOpen(hostId: string, cols: number, rows: number, commandLogging: boolean, onData: (data: StreamEnvelope<number[]>) => void): Promise<string> {
    if (!isTauri()) { setTimeout(() => onData({ seq: 1, timestamp: now(), hostId, sessionId: "demo-term", payload: Array.from(new TextEncoder().encode("\x1b[1;34mSSH Operations Terminal\x1b[0m\r\nConnected to demo server.\r\n\x1b[32mops@server\x1b[0m:\x1b[34m~\x1b[0m$ ")) }), 180); return "demo-term"; }
    const channel = new Channel<StreamEnvelope<number[]>>(); channel.onmessage = onData;
    return invoke("terminal_open", { hostId, cols, rows, commandLogging, channel });
  },
  async terminalInput(sessionId: string, data: number[]) { if (isTauri()) await invoke("terminal_input", { sessionId, data }); },
  async terminalResize(sessionId: string, cols: number, rows: number) { if (isTauri()) await invoke("terminal_resize", { sessionId, cols, rows }); },
  async terminalClose(sessionId: string) { if (isTauri()) await invoke("terminal_close", { sessionId }); },
  async monitorStart(hostId: string, onData: (data: StreamEnvelope<MetricSnapshot>) => void): Promise<string> {
    if (!isTauri()) {
      const timer = window.setInterval(() => {
        const t = Date.now() / 1000;
        const snapshot: MetricSnapshot = { hostId, timestamp: now(), cpuPercent: 28 + Math.sin(t / 3) * 12 + Math.random() * 5, memoryPercent: 62 + Math.sin(t / 8) * 3, diskPercent: 48.7, load1: 1.35 + Math.sin(t / 5) * .35, rxBytesPerSec: 1_400_000 + Math.random() * 2_500_000, txBytesPerSec: 620_000 + Math.random() * 1_100_000, connectionCount: 42 + Math.floor(Math.random() * 8), memoryUsedBytes: 10_650_000_000, memoryTotalBytes: 17_180_000_000, diskUsedBytes: 128_000_000_000, diskTotalBytes: 256_000_000_000, uptimeSeconds: 1_248_320, connections: [{ protocol: "tcp", state: "ESTAB", localAddress: "10.0.1.12:22", remoteAddress: "10.0.0.42:54218", process: "sshd" }, { protocol: "tcp", state: "ESTAB", localAddress: "10.0.1.12:443", remoteAddress: "172.16.1.18:39120", process: "nginx" }], topProcesses: [{ pid: 1428, name: "postgres", cpuPercent: 8.7, memoryPercent: 12.4 }, { pid: 918, name: "nginx", cpuPercent: 4.2, memoryPercent: 2.1 }, { pid: 2001, name: "node", cpuPercent: 3.8, memoryPercent: 5.7 }] };
        onData({ seq: Date.now(), timestamp: now(), hostId, payload: snapshot });
      }, 2000);
      return String(timer);
    }
    const channel = new Channel<StreamEnvelope<MetricSnapshot>>(); channel.onmessage = onData;
    return invoke("monitor_start", { hostId, channel });
  },
  async monitorStop(hostId: string) { if (isTauri()) await invoke("monitor_stop", { hostId }); },
  async monitorQuery(hostId: string, range: string) { return isTauri() ? invoke<MetricSnapshot[]>("monitor_query", { hostId, range }) : []; },
  async firewallRead(hostId: string): Promise<FirewallState> {
    if (isTauri()) return invoke("firewall_read", { hostId });
    return { hostId, backend: "ufw", enabled: true, defaultInbound: "deny", defaultOutbound: "allow", stateHash: "demo-hash", rollbackAvailable: true, rules: [
      { id: "r1", direction: "in", family: "both", protocol: "tcp", ports: "22", source: "10.0.0.0/8", destination: "any", action: "allow", enabled: true, comment: "SSH 管理网络" },
      { id: "r2", direction: "in", family: "both", protocol: "tcp", ports: "80,443", source: "any", destination: "any", action: "allow", enabled: true, comment: "Web 服务" },
      { id: "r3", direction: "in", family: "both", protocol: "any", ports: "any", source: "any", destination: "any", action: "deny", enabled: true, comment: "默认拒绝", readOnly: true },
    ] };
  },
  async firewallPlan(hostId: string, rule: FirewallRuleInput, operation: "add" | "delete" = "add"): Promise<FirewallPlan> {
    if (isTauri()) return invoke("firewall_plan", { hostId, change: { operation, rule } });
    return { id: crypto.randomUUID(), hostId, stateHash: "demo-hash", summary: `允许 ${rule.protocol.toUpperCase()} ${rule.ports}`, commands: [`sudo ufw allow proto ${rule.protocol} from ${rule.source} to any port ${rule.ports} comment '${rule.comment}'`], warnings: ["将先创建 60 秒自动回滚任务，并验证新的 SSH 连接。"], risk: "medium", rollbackAvailable: true, expiresAt: new Date(Date.now() + 300_000).toISOString() };
  },
  async firewallApply(planId: string, sudoPassword?: string, rememberSudo = false) { return isTauri() ? invoke("firewall_apply", { planId, sudoPassword: sudoPassword || null, rememberSudo }) : { rollbackDeadline: new Date(Date.now() + 60_000).toISOString() }; },
  async firewallCommit(planId: string) { if (isTauri()) await invoke("firewall_commit", { planId }); },
  async firewallRollback(planId: string) { if (isTauri()) await invoke("firewall_rollback", { planId }); },
  async commandLogQuery(hostId?: string): Promise<CommandRecord[]> { return isTauri() ? invoke("command_log_query", { hostId: hostId || null }) : []; },
  async commandLogSubscribe(onData: (event: StreamEnvelope<CommandRecord>) => void): Promise<void> {
    if (!isTauri()) return;
    const channel = new Channel<StreamEnvelope<CommandRecord>>(); channel.onmessage = onData;
    await invoke("command_log_subscribe", { channel });
  },
  async commandLogExport(path: string, hostId?: string, records?: CommandRecord[]): Promise<void> {
    if (!isTauri()) { const text = (records || []).map((r) => `[${r.timestamp}] ${r.hostName || "local"} $ ${r.command}\n${r.stdout}${r.stderr}`).join("\n"); const blob = new Blob([text], { type: "text/plain" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = path || "command-log.txt"; a.click(); URL.revokeObjectURL(url); return; }
    await invoke("command_log_export", { path, hostId: hostId || null });
  },
  async commandLogClear(): Promise<void> { if (isTauri()) await invoke("command_log_clear"); },
  async sftpList(hostId: string, path: string): Promise<SftpEntry[]> { return isTauri() ? invoke("sftp_list", { hostId, path }) : [{ name: "etc", path: "/etc", kind: "directory", size: 0, permissions: "drwxr-xr-x" }, { name: "var", path: "/var", kind: "directory", size: 0, permissions: "drwxr-xr-x" }, { name: "README.txt", path: "/README.txt", kind: "file", size: 4280, permissions: "-rw-r--r--", modifiedAt: now() }]; },
  async sftpUpload(hostId: string, localPaths: string[], remoteDirectory: string, onData: (event: StreamEnvelope<TransferProgress>) => void): Promise<string> {
    if (!isTauri()) return "";
    const channel = new Channel<StreamEnvelope<TransferProgress>>(); channel.onmessage = onData;
    return invoke("sftp_start_upload", { hostId, localPaths, remoteDirectory, channel });
  },
  async sftpDownload(hostId: string, remotePaths: string[], localDirectory: string, onData: (event: StreamEnvelope<TransferProgress>) => void): Promise<string> {
    if (!isTauri()) return "";
    const channel = new Channel<StreamEnvelope<TransferProgress>>(); channel.onmessage = onData;
    return invoke("sftp_start_download", { hostId, remotePaths, localDirectory, channel });
  },
  async sftpCancel(transferId: string): Promise<void> { if (isTauri()) await invoke("sftp_cancel", { transferId }); },
  async sftpDelete(hostId: string, paths: string[]): Promise<void> { if (isTauri()) await invoke("sftp_delete", { hostId, paths }); },
  async sftpRename(hostId: string, path: string, newPath: string): Promise<void> { if (isTauri()) await invoke("sftp_rename", { hostId, path, newPath }); },
  async sftpMkdir(hostId: string, path: string): Promise<void> { if (isTauri()) await invoke("sftp_mkdir", { hostId, path }); },
  async sftpCopy(hostId: string, sources: string[], destinationDirectory: string, onData: (event: StreamEnvelope<TransferProgress>) => void): Promise<string> {
    if (!isTauri()) return "";
    const channel = new Channel<StreamEnvelope<TransferProgress>>(); channel.onmessage = onData;
    return invoke("sftp_start_copy", { hostId, sources, destinationDirectory, channel });
  },
  async settingsGet(): Promise<AppSettings> { return isTauri() ? invoke("settings_get") : defaultSettings(); },
  async settingsUpdate(settings: AppSettings): Promise<AppSettings> { return isTauri() ? invoke("settings_update", { settings }) : settings; },
  async settingsReset(): Promise<AppSettings> { return isTauri() ? invoke("settings_reset") : defaultSettings(); },
  async forwardingList(hostId: string): Promise<ForwardingProfile[]> { return isTauri() ? invoke("forward_list", { hostId }) : []; },
  async forwardingUpsert(profile: ForwardingProfile): Promise<ForwardingProfile> { return isTauri() ? invoke("forward_upsert", { profile }) : profile; },
  async forwardingToggle(id: string, active: boolean): Promise<ForwardingProfile | undefined> { return isTauri() ? invoke(active ? "forward_start" : "forward_stop", { id }) : undefined; },
  async forwardingDelete(id: string) { if (isTauri()) await invoke("forward_delete", { id }); },
};
