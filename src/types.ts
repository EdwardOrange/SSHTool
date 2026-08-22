export type AuthMethod = "password" | "key" | "agent" | "keyboardInteractive";
export type ConnectionStatus = "disconnected" | "connecting" | "connected" | "reconnecting" | "error";
export type PageId = "terminal" | "monitor" | "firewall" | "sftp" | "forwarding";

export interface CredentialRef {
  id: string;
  kind: "sshPassword" | "keyPassphrase" | "sudoPassword";
  label: string;
  stored: boolean;
}

export interface JumpHost {
  hostId: string;
  order: number;
}

export interface HostProfile {
  id: string;
  name: string;
  hostname: string;
  port: number;
  username: string;
  groupName: string;
  tags: string[];
  favorite: boolean;
  authMethod: AuthMethod;
  credentialId?: string;
  privateKeyPath?: string;
  jumpHosts: JumpHost[];
  hostKeyFingerprint?: string;
  status: ConnectionStatus;
  lastConnectedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface HostDraft extends Omit<HostProfile, "id" | "status" | "createdAt" | "updatedAt" | "jumpHosts"> {
  id?: string;
  password?: string;
  rememberPassword?: boolean;
  jumpHosts?: JumpHost[];
}

export interface TerminalSession {
  id: string;
  hostId: string;
  title: string;
  status: "opening" | "open" | "closed" | "error";
  cols: number;
  rows: number;
}

export interface MetricPoint {
  timestamp: string;
  cpuPercent: number;
  memoryPercent: number;
  diskPercent: number;
  load1: number;
  rxBytesPerSec: number;
  txBytesPerSec: number;
  connectionCount: number;
}

export interface NetworkConnection {
  protocol: string;
  state: string;
  localAddress: string;
  remoteAddress: string;
  process?: string;
}

export interface ProcessUsage {
  pid: number;
  name: string;
  cpuPercent: number;
  memoryPercent: number;
}

export interface MetricSnapshot extends MetricPoint {
  hostId: string;
  memoryUsedBytes: number;
  memoryTotalBytes: number;
  diskUsedBytes: number;
  diskTotalBytes: number;
  uptimeSeconds: number;
  connections: NetworkConnection[];
  topProcesses: ProcessUsage[];
}

export type FirewallBackend = "ufw" | "firewalld" | "nftables" | "unsupported";
export interface UnifiedFirewallRule {
  id: string;
  backendRef?: string;
  direction: "in" | "out" | "forward";
  family: "ipv4" | "ipv6" | "both";
  protocol: "tcp" | "udp" | "icmp" | "any";
  ports: string;
  source: string;
  destination: string;
  action: "allow" | "deny" | "reject";
  enabled: boolean;
  comment: string;
  zone?: string;
  readOnly?: boolean;
}
export type FirewallRuleInput = Omit<UnifiedFirewallRule, "id"> & { id?: string };

export interface FirewallState {
  hostId: string;
  backend: FirewallBackend;
  enabled: boolean;
  defaultInbound: string;
  defaultOutbound: string;
  stateHash: string;
  rollbackAvailable: boolean;
  rules: UnifiedFirewallRule[];
}

export interface FirewallPlan {
  id: string;
  hostId: string;
  stateHash: string;
  summary: string;
  commands: string[];
  warnings: string[];
  risk: "low" | "medium" | "high";
  rollbackAvailable: boolean;
  expiresAt: string;
}

export interface FirewallApplyProgress {
  planId: string;
  phase: string;
  status: "running" | "success" | "error";
  message: string;
}

export interface FirewallApplyResult {
  rollbackDeadline: string;
  verified: boolean;
}

export interface CommandRecord {
  id: string;
  timestamp: string;
  hostId?: string;
  hostName?: string;
  source: "connection" | "terminal" | "monitor" | "firewall" | "sftp" | "forward" | "system";
  command: string;
  stdout: string;
  stderr: string;
  exitCode?: number;
  durationMs: number;
  status: "running" | "success" | "error" | "cancelled";
  repeatCount: number;
  equivalent?: boolean;
  operationKind?: string;
}

export interface CommandSuppressionRule {
  id: string;
  enabled: boolean;
  source?: CommandRecord["source"];
  hostId?: string;
  operationKind?: string;
  contains?: string;
}

export interface AppSettings {
  version: number;
  locale: "zh" | "en";
  theme: "system" | "light" | "dark";
  defaultPage: PageId;
  terminalFontSize: number;
  terminalScrollback: number;
  terminalPasteProtection: boolean;
  terminalCommandLogging: boolean;
  monitorIntervalSeconds: 2 | 5 | 10 | 30;
  transferConflictPolicy: "ask" | "overwrite" | "skip" | "rename" | "resume";
  commandRetentionDays: number;
  commandRetentionMb: number;
  suppressionRules: CommandSuppressionRule[];
}

export interface SftpEntry {
  name: string;
  path: string;
  kind: "file" | "directory" | "symlink";
  size: number;
  modifiedAt?: string;
  permissions?: string;
}

export interface SftpTransfer {
  id: string;
  hostId: string;
  direction: "upload" | "download";
  source: string;
  destination: string;
  transferred: number;
  total: number;
  status: "queued" | "running" | "completed" | "error" | "cancelled";
}
export interface TransferProgress {
  transferId: string;
  hostId: string;
  direction: "upload" | "download" | "transfer";
  currentPath: string;
  transferred: number;
  total: number;
  status: "queued" | "running" | "completed" | "error" | "cancelled";
  error?: string;
  fileIndex: number;
  fileCount: number;
  currentFileTransferred: number;
  currentFileTotal: number;
}

export interface ForwardingProfile {
  id: string;
  hostId: string;
  name: string;
  kind: "local" | "remote" | "dynamic";
  bindAddress: string;
  bindPort: number;
  targetHost?: string;
  targetPort?: number;
  active: boolean;
  status?: "stopped" | "starting" | "active" | "error";
  lastError?: string;
}

export interface StreamEnvelope<T> {
  seq: number;
  timestamp: string;
  hostId: string;
  sessionId?: string;
  payload: T;
}
