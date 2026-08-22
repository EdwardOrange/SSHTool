import { create } from "zustand";
import type { AppSettings, CommandRecord, FirewallState, HostProfile, MetricSnapshot, PageId, TransferProgress } from "./types";

export interface TransferTaskView {
  progress: TransferProgress;
  startedAt: number;
  updatedAt: number;
  speed: number;
}

interface AppState {
  hosts: HostProfile[];
  selectedHostId?: string;
  page: PageId;
  metrics: Record<string, MetricSnapshot[]>;
  firewall: Record<string, FirewallState>;
  commands: CommandRecord[];
  commandPanelOpen: boolean;
  commandPanelHeight: number;
  transfers: Record<string, TransferTaskView>;
  settings: AppSettings | undefined;
  setHosts: (hosts: HostProfile[]) => void;
  upsertHost: (host: HostProfile) => void;
  removeHost: (id: string) => void;
  selectHost: (id?: string) => void;
  setPage: (page: PageId) => void;
  addMetric: (snapshot: MetricSnapshot) => void;
  setFirewall: (state: FirewallState) => void;
  addCommand: (command: CommandRecord) => void;
  setCommands: (commands: CommandRecord[]) => void;
  toggleCommandPanel: () => void;
  setCommandPanelHeight: (height: number) => void;
  upsertTransfer: (progress: TransferProgress) => void;
  clearCompletedTransfers: () => void;
  setSettings: (settings: AppSettings) => void;
}

export const useAppStore = create<AppState>((set) => ({
  hosts: [], page: "monitor", metrics: {}, firewall: {}, commands: [], commandPanelOpen: true, commandPanelHeight: 216, transfers: {}, settings: undefined,
  setHosts: (hosts) => set({ hosts: hosts.map(normalizeHost), selectedHostId: hosts[0]?.id }),
  upsertHost: (host) => set((s) => {
    const normalized = normalizeHost(host);
    return { hosts: s.hosts.some((h) => h.id === normalized.id) ? s.hosts.map((h) => h.id === normalized.id ? normalized : h) : [...s.hosts, normalized], selectedHostId: normalized.id };
  }),
  removeHost: (id) => set((s) => {
    const index = s.hosts.findIndex((host) => host.id === id);
    const hosts = s.hosts.filter((host) => host.id !== id);
    const selectedHostId = s.selectedHostId === id ? (hosts[index]?.id || hosts[index - 1]?.id) : s.selectedHostId;
    return { hosts, selectedHostId };
  }),
  selectHost: (selectedHostId) => set({ selectedHostId }),
  setPage: (page) => set({ page }),
  addMetric: (snapshot) => set((s) => ({ metrics: { ...s.metrics, [snapshot.hostId]: [...(s.metrics[snapshot.hostId] || []), snapshot].slice(-1800) } })),
  setFirewall: (state) => set((s) => ({ firewall: { ...s.firewall, [state.hostId]: state } })),
  addCommand: (command) => set((s) => {
    const exists = s.commands.some((item) => item.id === command.id);
    return { commands: exists ? s.commands.map((item) => item.id === command.id ? { ...item, ...command } : item) : [...s.commands, command].slice(-2000) };
  }),
  setCommands: (commands) => set({ commands }),
  toggleCommandPanel: () => set((s) => ({ commandPanelOpen: !s.commandPanelOpen })),
  setCommandPanelHeight: (commandPanelHeight) => set({ commandPanelHeight }),
  upsertTransfer: (progress) => set((s) => {
    const now = Date.now(); const previous = s.transfers[progress.transferId];
    const normalized = previous && ["completed", "error", "cancelled"].includes(progress.status) && progress.total === 0 ? { ...progress, direction: previous.progress.direction, transferred: previous.progress.transferred, total: previous.progress.total, currentPath: previous.progress.currentPath, fileIndex: previous.progress.fileIndex, fileCount: previous.progress.fileCount, currentFileTransferred: previous.progress.currentFileTransferred, currentFileTotal: previous.progress.currentFileTotal } : progress;
    const elapsed = previous ? Math.max(0.1, (now - previous.updatedAt) / 1000) : 0.1;
    const delta = previous ? Math.max(0, normalized.transferred - previous.progress.transferred) : normalized.transferred;
    const speed = previous ? previous.speed * 0.65 + (delta / elapsed) * 0.35 : delta / elapsed;
    return { transfers: { ...s.transfers, [normalized.transferId]: { progress: normalized, startedAt: previous?.startedAt || now, updatedAt: now, speed } } };
  }),
  clearCompletedTransfers: () => set((s) => ({ transfers: Object.fromEntries(Object.entries(s.transfers).filter(([, task]) => !["completed", "error", "cancelled"].includes(task.progress.status))) })),
  setSettings: (settings) => set({ settings }),
}));

function normalizeHost(host: HostProfile): HostProfile {
  return { ...host, tags: Array.isArray(host.tags) ? host.tags : [], jumpHosts: Array.isArray(host.jumpHosts) ? host.jumpHosts : [], groupName: host.groupName || "未分组" };
}
