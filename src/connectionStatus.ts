import type { HostProfile } from "./types";

interface ConnectionStatusPolling {
  listHosts: () => Promise<HostProfile[]>;
  getHosts: () => HostProfile[];
  updateConnection: (id: string, patch: Pick<HostProfile, "status"> & Partial<Pick<HostProfile, "lastConnectedAt">>) => void;
  operationRevision: () => number;
  operationPending: () => boolean;
}

/** Refresh backend liveness without replacing edited profiles or selections. */
export function startConnectionStatusPolling(options: ConnectionStatusPolling, intervalMs = 3000): () => void {
  let disposed = false;
  let inFlight = false;
  const refresh = async () => {
    if (disposed || inFlight || options.operationPending()) return;
    const connected = options.getHosts().filter((host) => host.status === "connected");
    if (!connected.length) return;
    const revision = options.operationRevision();
    inFlight = true;
    try {
      const remote = await options.listHosts();
      if (disposed || options.operationPending() || revision !== options.operationRevision()) return;
      for (const captured of connected) {
        // A manual reconnect or profile edit creates a new object. Its result
        // always takes precedence over a poll started against the old object.
        if (options.getHosts().find((host) => host.id === captured.id) !== captured) continue;
        const latest = remote.find((host) => host.id === captured.id);
        if (!latest || (latest.status === captured.status && latest.lastConnectedAt === captured.lastConnectedAt)) continue;
        options.updateConnection(captured.id, { status: latest.status, lastConnectedAt: latest.lastConnectedAt });
      }
    } catch {
      // A failed local status query is not evidence of an SSH disconnect.
    } finally { inFlight = false; }
  };
  const timer = globalThis.setInterval(() => void refresh(), intervalMs);
  return () => { disposed = true; globalThis.clearInterval(timer); };
}
