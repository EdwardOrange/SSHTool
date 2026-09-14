// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FirewallPlan, FirewallState, HostProfile, MetricSnapshot, SftpEntry } from "../types";
import { useAppStore } from "../store";
import MonitorView from "./MonitorView";
import SftpView from "./SftpView";
import FirewallView from "./FirewallView";
import ForwardingView from "./ForwardingView";

const mocks = vi.hoisted(() => ({
  monitorStart: vi.fn(), monitorStop: vi.fn(), sftpList: vi.fn(), sftpRename: vi.fn(),
  firewallRead: vi.fn(), firewallPlan: vi.fn(), firewallApply: vi.fn(), firewallCommit: vi.fn(),
  forwardingList: vi.fn(), forwardingUpsert: vi.fn(),
}));
vi.mock("../api", () => ({ api: mocks }));
vi.mock("recharts", async (original) => ({ ...await original<object>(), ResponsiveContainer: () => null }));
const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "connected", createdAt: "", updatedAt: "" };
const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>((r) => { resolve = r; }); return { promise, resolve }; };

beforeEach(() => {
  vi.resetAllMocks();
  useAppStore.setState({ metrics: {}, firewall: {}, settings: undefined });
  mocks.monitorStart.mockResolvedValue("monitor-one");
  mocks.monitorStop.mockResolvedValue(undefined);
});
afterEach(() => { cleanup(); vi.useRealTimers(); });

describe("Async and operational regressions", () => {
  it("refreshes forwarding state when the SSH connection closes", async () => {
    mocks.forwardingList.mockResolvedValue([]);
    const view = render(<ForwardingView host={host}/>);
    await waitFor(() => expect(mocks.forwardingList).toHaveBeenCalledTimes(1));
    view.rerender(<ForwardingView host={{ ...host, status: "disconnected" }}/>);
    await waitFor(() => expect(mocks.forwardingList).toHaveBeenCalledTimes(2));
  });
  it("marks monitoring stale even when no further data arrives", async () => {
    vi.useFakeTimers();
    const sample = { hostId: host.id, timestamp: new Date().toISOString(), cpuPercent: 10, memoryPercent: 20, diskPercent: 30, load1: 1, rxBytesPerSec: 0, txBytesPerSec: 0, connectionCount: 0, uptimeSeconds: 60, connections: [], topProcesses: [] } as unknown as MetricSnapshot;
    useAppStore.setState({ metrics: { [host.id]: [sample] } });
    render(<MonitorView host={host}/>);
    expect(screen.getByText("2 秒实时")).toBeTruthy();
    await act(async () => { vi.advanceTimersByTime(7000); });
    expect(screen.queryByText("2 秒实时")).toBeNull();
    expect(screen.getByText("等待新的监控采样…")).toBeTruthy();
  });

  it("stops monitoring that finishes starting after unmount", async () => {
    const pending = deferred<string>(); mocks.monitorStart.mockReturnValue(pending.promise);
    const view = render(<MonitorView host={host}/>);
    view.unmount();
    await act(async () => pending.resolve("late-task"));
    expect(mocks.monitorStop).toHaveBeenCalledWith("late-task");
  });

  it("ignores the previous server's late directory response", async () => {
    const first = deferred<SftpEntry[]>(), second = deferred<SftpEntry[]>();
    mocks.sftpList.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
    const view = render(<SftpView host={host}/>);
    view.rerender(<SftpView host={{ ...host, id: "two" }}/>);
    await act(async () => second.resolve([{ name: "current.txt", path: "/current.txt", kind: "file", size: 1 }]));
    await act(async () => first.resolve([{ name: "old.txt", path: "/old.txt", kind: "file", size: 1 }]));
    expect(screen.getByText("current.txt")).toBeTruthy();
    expect(screen.queryByText("old.txt")).toBeNull();
  });

  it("does not issue SFTP requests for a disconnected server", () => {
    render(<SftpView host={{ ...host, status: "disconnected" }}/>);
    expect(mocks.sftpList).not.toHaveBeenCalled();
  });

  it("ignores a late forwarding list from the previous server", async () => {
    const first = deferred<[]>(); mocks.forwardingList.mockReturnValueOnce(first.promise).mockResolvedValueOnce([{ id: "p2", hostId: "two", name: "Current tunnel", kind: "local", bindAddress: "127.0.0.1", bindPort: 8080, targetHost: "localhost", targetPort: 80, active: false }]);
    const view = render(<ForwardingView host={host}/>);
    view.rerender(<ForwardingView host={{ ...host, id: "two" }}/>);
    await screen.findByText("Current tunnel");
    await act(async () => first.resolve([]));
    expect(screen.getByText("Current tunnel")).toBeTruthy();
  });

  it("allows closing and refreshing an expired firewall rollback dialog", async () => {
    const rule = { id: "rule", direction: "in", protocol: "tcp", ports: "22", source: "any", destination: "any", family: "both", action: "allow", enabled: true, comment: "" };
    mocks.firewallRead.mockResolvedValue({ hostId: host.id, backend: "ufw", enabled: true, defaultInbound: "deny", defaultOutbound: "allow", rules: [rule], rollbackAvailable: true, stateHash: "hash" } as FirewallState);
    mocks.firewallPlan.mockResolvedValue({ id: "plan", hostId: host.id, commands: ["ufw allow 22"], warnings: [], summary: "Plan", risk: "medium", stateHash: "hash", rollbackAvailable: true, expiresAt: "" } as FirewallPlan);
    mocks.firewallApply.mockResolvedValue({ rollbackDeadline: new Date(Date.now() - 1000).toISOString(), verified: true });
    render(<FirewallView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 22" }));
    fireEvent.click(await screen.findByRole("button", { name: "确认并执行" }));
    fireEvent.click(await screen.findByRole("button", { name: "关闭并刷新状态" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mocks.firewallRead).toHaveBeenCalledTimes(2);
    expect(mocks.firewallCommit).not.toHaveBeenCalled();
  });
});
