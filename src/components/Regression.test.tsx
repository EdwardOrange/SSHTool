// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { FirewallPlan, FirewallState, ForwardingProfile, HostProfile, MetricSnapshot, SftpEntry } from "../types";
import { useAppStore } from "../store";
import MonitorView from "./MonitorView";
import SftpView from "./SftpView";
import FirewallView from "./FirewallView";
import ForwardingView from "./ForwardingView";

const mocks = vi.hoisted(() => ({
  monitorStart: vi.fn(), monitorStop: vi.fn(), sftpList: vi.fn(), sftpRename: vi.fn(), sftpMkdir: vi.fn(), sftpDelete: vi.fn(),
  firewallRead: vi.fn(), firewallPlan: vi.fn(), firewallApply: vi.fn(), firewallCommit: vi.fn(),
  forwardingList: vi.fn(), forwardingUpsert: vi.fn(), forwardingToggle: vi.fn(),
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
  it("does not label TIME_WAIT sockets without a process as permission failures", () => {
    useAppStore.setState({ metrics: { [host.id]: [{ hostId: host.id, timestamp: new Date().toISOString(), cpuPercent: 0, memoryPercent: 0, diskPercent: 0, load1: 0, rxBytesPerSec: 0, txBytesPerSec: 0, connectionCount: 1, uptimeSeconds: 0, connections: [{ protocol: "tcp", state: "TIME_WAIT", localAddress: "127.0.0.1:22", remoteAddress: "127.0.0.1:1234" }], topProcesses: [] } as unknown as MetricSnapshot] } });
    render(<MonitorView host={host}/>);
    expect(screen.getByText("无进程信息")).toBeTruthy();
    expect(screen.queryByText("权限不足")).toBeNull();
  });

  it("keeps SFTP mkdir errors visible inside the dialog and blocks duplicate writes", async () => {
    let reject!: (reason: Error) => void;
    mocks.sftpList.mockResolvedValue([]);
    mocks.sftpMkdir.mockReturnValue(new Promise<void>((_, fail) => { reject = fail; }));
    render(<SftpView host={host}/>);
    await waitFor(() => expect(screen.getByRole("button", { name: "新建目录" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "新建目录" }));
    fireEvent.change(screen.getByRole("textbox", { name: "目录名" }), { target: { value: "protected" } });
    const button = screen.getByRole("button", { name: "创建" });
    fireEvent.click(button); fireEvent.click(button);
    expect(mocks.sftpMkdir).toHaveBeenCalledTimes(1);
    expect(button.hasAttribute("disabled")).toBe(true);
    await act(async () => reject(new Error("Permission denied")));
    expect(within(screen.getByRole("dialog")).getByRole("alert").textContent).toBe("Permission denied");
    expect(button.hasAttribute("disabled")).toBe(false);
  });

  it("shows firewall plan validation errors inside the editor", async () => {
    mocks.firewallRead.mockResolvedValue({ hostId: host.id, backend: "ufw", enabled: true, defaultInbound: "deny", defaultOutbound: "allow", rules: [], rollbackAvailable: true, stateHash: "hash" } as FirewallState);
    mocks.firewallPlan.mockRejectedValue(new Error("Invalid port"));
    render(<FirewallView host={host}/>);
    await waitFor(() => expect(screen.getByRole("button", { name: "添加规则" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "添加规则" }));
    fireEvent.click(screen.getByRole("button", { name: "生成计划" }));
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByRole("alert").textContent).toBe("Invalid port"));
  });

  it("cannot commit a firewall result whose new SSH connection was not verified", async () => {
    const rule = { id: "rule", direction: "in", protocol: "tcp", ports: "22", source: "any", destination: "any", family: "both", action: "allow", enabled: true, comment: "" };
    mocks.firewallRead.mockResolvedValue({ hostId: host.id, backend: "ufw", enabled: true, defaultInbound: "deny", defaultOutbound: "allow", rules: [rule], rollbackAvailable: true, stateHash: "hash" } as FirewallState);
    mocks.firewallPlan.mockResolvedValue({ id: "plan", hostId: host.id, commands: [], warnings: [], summary: "Plan", risk: "medium", stateHash: "hash", rollbackAvailable: true, expiresAt: "" } as FirewallPlan);
    mocks.firewallApply.mockResolvedValue({ rollbackDeadline: new Date(Date.now() + 60000).toISOString(), verified: false });
    render(<FirewallView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 22" }));
    fireEvent.click(await screen.findByRole("button", { name: "确认并执行" }));
    const commit = await screen.findByRole("button", { name: "保留更改" });
    expect(commit.hasAttribute("disabled")).toBe(true);
    expect(screen.getByText(/SSH 验证未通过/)).toBeTruthy();
    fireEvent.click(commit);
    expect(mocks.firewallCommit).not.toHaveBeenCalled();
  });

  it("refreshes forwarding state when the SSH connection closes", async () => {
    mocks.forwardingList.mockResolvedValue([]);
    const view = render(<ForwardingView host={host}/>);
    await waitFor(() => expect(mocks.forwardingList).toHaveBeenCalledTimes(1));
    view.rerender(<ForwardingView host={{ ...host, status: "disconnected" }}/>);
    await waitFor(() => expect(mocks.forwardingList).toHaveBeenCalledTimes(2));
  });

  it("ignores a late forwarding start after disconnect refreshes the profile", async () => {
    const profile: ForwardingProfile = { id: "tunnel", hostId: host.id, name: "Tunnel", kind: "local", bindAddress: "127.0.0.1", bindPort: 8080, targetHost: "localhost", targetPort: 80, active: false, status: "stopped" };
    const pending = deferred<ForwardingProfile>();
    mocks.forwardingList.mockResolvedValue([profile]);
    mocks.forwardingToggle.mockReturnValue(pending.promise);
    const view = render(<ForwardingView host={host}/>);
    fireEvent.click(await screen.findByRole("switch", { name: "启动Tunnel" }));
    view.rerender(<ForwardingView host={{ ...host, status: "disconnected" }}/>);
    await screen.findByText("已停止");
    await act(async () => pending.resolve({ ...profile, active: true, status: "active" }));
    expect(screen.queryByText("运行中")).toBeNull();
    expect(screen.getByRole("switch", { name: "启动Tunnel" }).hasAttribute("disabled")).toBe(true);
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

  it("removes the old directory before navigation and keeps writes disabled after a failed listing", async () => {
    let reject!: (reason: Error) => void;
    const next = new Promise<SftpEntry[]>((_, fail) => { reject = fail; });
    mocks.sftpList.mockResolvedValueOnce([
      { name: "private", path: "/private", kind: "directory", size: 0 },
      { name: "original.txt", path: "/original.txt", kind: "file", size: 1 },
    ]).mockReturnValueOnce(next);
    render(<SftpView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "private" }));
    expect(screen.queryByText("original.txt")).toBeNull();
    await act(async () => reject(new Error("Permission denied")));
    expect(screen.queryByText("original.txt")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(screen.getByRole("button", { name: "上传文件" }).hasAttribute("disabled")).toBe(true);
    expect(screen.getByRole("button", { name: "新建目录" }).hasAttribute("disabled")).toBe(true);
  });

  it("builds absolute SFTP breadcrumb paths without double slashes", async () => {
    mocks.sftpList.mockResolvedValueOnce([{ name: "etc", path: "/etc", kind: "directory", size: 0 }])
      .mockResolvedValueOnce([{ name: "ssh", path: "/etc/ssh", kind: "directory", size: 0 }])
      .mockResolvedValue([]);
    render(<SftpView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "etc" }));
    fireEvent.click(await screen.findByRole("button", { name: "ssh" }));
    await waitFor(() => expect(mocks.sftpList).toHaveBeenCalledWith(host.id, "/etc/ssh"));
    fireEvent.click(screen.getByRole("button", { name: "etc" }));
    await waitFor(() => expect(mocks.sftpList).toHaveBeenLastCalledWith(host.id, "/etc"));
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
