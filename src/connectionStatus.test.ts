import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { startConnectionStatusPolling } from "./connectionStatus";
import { useAppStore } from "./store";
import type { HostProfile } from "./types";

const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "key", jumpHosts: [], status: "connected", createdAt: "", updatedAt: "" };
const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; };
let stop: (() => void) | undefined;
function setup() {
  let revision = 0, pending = false;
  const listHosts = vi.fn().mockResolvedValue([{ ...host, status: "disconnected" }]);
  stop = startConnectionStatusPolling({ listHosts, getHosts: () => useAppStore.getState().hosts, updateConnection: (id, patch) => useAppStore.getState().updateHostConnection(id, patch), operationRevision: () => revision, operationPending: () => pending });
  return { listHosts, operation: (busy: boolean) => { revision += 1; pending = busy; } };
}
beforeEach(() => { vi.useFakeTimers(); useAppStore.setState({ hosts: [host], selectedHostId: host.id }); });
afterEach(() => { stop?.(); vi.useRealTimers(); });

describe("connection status synchronization", () => {
  it("reflects a remote disconnect without replacing configuration or selection", async () => {
    const disconnected = { ...host, id: "two", status: "disconnected" as const };
    useAppStore.setState({ hosts: [host, disconnected], selectedHostId: disconnected.id });
    const { listHosts } = setup();
    listHosts.mockResolvedValue([{ ...host, name: "stale backend name", status: "disconnected" }, { ...disconnected, status: "connected" }]);
    await vi.advanceTimersByTimeAsync(3000);
    expect(useAppStore.getState().hosts).toEqual([{ ...host, status: "disconnected" }, disconnected]);
    expect(useAppStore.getState().selectedHostId).toBe(disconnected.id);
    await vi.advanceTimersByTimeAsync(9000);
    expect(listHosts).toHaveBeenCalledTimes(1);
  });

  it("does not let a late poll overwrite a manual reconnection", async () => {
    const response = deferred<HostProfile[]>(); const { listHosts } = setup(); listHosts.mockReturnValue(response.promise);
    await vi.advanceTimersByTimeAsync(3000);
    useAppStore.getState().updateHostConnection(host.id, { status: "disconnected" });
    useAppStore.getState().updateHostConnection(host.id, { status: "connected", lastConnectedAt: "new connection" });
    response.resolve([{ ...host, status: "disconnected" }]); await Promise.resolve();
    expect(useAppStore.getState().hosts[0]).toMatchObject({ status: "connected", lastConnectedAt: "new connection" });
  });

  it("does not let a late poll overwrite a profile edited while querying", async () => {
    const response = deferred<HostProfile[]>(); const { listHosts } = setup(); listHosts.mockReturnValue(response.promise);
    await vi.advanceTimersByTimeAsync(3000);
    useAppStore.getState().upsertHost({ ...host, name: "Edited" });
    response.resolve([{ ...host, status: "disconnected" }]); await Promise.resolve();
    expect(useAppStore.getState().hosts[0]).toMatchObject({ name: "Edited", status: "connected" });
  });

  it("discards requests overlapping a connection action even if it was cancelled", async () => {
    const response = deferred<HostProfile[]>(); const { listHosts, operation } = setup(); listHosts.mockReturnValue(response.promise);
    await vi.advanceTimersByTimeAsync(3000);
    operation(true); operation(false);
    response.resolve([{ ...host, status: "disconnected" }]); await Promise.resolve();
    expect(useAppStore.getState().hosts[0].status).toBe("connected");
  });

  it("does not overlap queries and ignores responses after disposal", async () => {
    const response = deferred<HostProfile[]>(); const { listHosts } = setup(); listHosts.mockReturnValue(response.promise);
    await vi.advanceTimersByTimeAsync(12000);
    expect(listHosts).toHaveBeenCalledTimes(1);
    stop?.(); response.resolve([{ ...host, status: "disconnected" }]); await Promise.resolve();
    expect(useAppStore.getState().hosts[0].status).toBe("connected");
    await vi.advanceTimersByTimeAsync(12000);
    expect(listHosts).toHaveBeenCalledTimes(1);
  });

  it("pauses during connection actions and leaves status intact when querying fails", async () => {
    const { listHosts, operation } = setup(); listHosts.mockRejectedValue(new Error("database locked"));
    operation(true); await vi.advanceTimersByTimeAsync(6000);
    expect(listHosts).not.toHaveBeenCalled();
    operation(false); await vi.advanceTimersByTimeAsync(3000);
    expect(listHosts).toHaveBeenCalledTimes(1);
    expect(useAppStore.getState().hosts[0].status).toBe("connected");
  });
});
