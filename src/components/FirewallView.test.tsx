// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../store";
import type { FirewallPlan, FirewallState, HostProfile } from "../types";
import FirewallView from "./FirewallView";

const mocks = vi.hoisted(() => ({ firewallRead: vi.fn(), firewallPlan: vi.fn(), firewallApply: vi.fn(), firewallCommit: vi.fn(), firewallRollback: vi.fn() }));
vi.mock("../api", () => ({ api: mocks }));
const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "connected", createdAt: "", updatedAt: "" };
const state: FirewallState = { hostId: host.id, backend: "ufw", enabled: true, defaultInbound: "deny", defaultOutbound: "allow", stateHash: "hash", rollbackAvailable: true, rules: [{ id: "rule", direction: "in", protocol: "tcp", ports: "2222", source: "any", destination: "any", family: "both", action: "allow", enabled: true, comment: "test" }] };
const plan: FirewallPlan = { id: "plan", hostId: host.id, commands: ["ufw delete allow 2222"], warnings: [], summary: "Delete test rule", risk: "medium", stateHash: "hash", rollbackAvailable: true, expiresAt: "" };
const sudoRequired = { kind: "sudoRequired", message: "需要 sudo 密码" };
const enterPassword = (password: string) => { fireEvent.change(screen.getByLabelText("sudo 密码"), { target: { value: password } }); fireEvent.click(screen.getByRole("button", { name: "继续执行" })); };

beforeEach(() => {
  vi.resetAllMocks(); useAppStore.setState({ firewall: {} });
  mocks.firewallRead.mockResolvedValue(state); mocks.firewallPlan.mockResolvedValue(plan);
  mocks.firewallApply.mockResolvedValue({ rollbackDeadline: new Date(Date.now() + 60000).toISOString(), verified: true });
  mocks.firewallCommit.mockResolvedValue(undefined);
});
afterEach(cleanup);

describe("sudo authentication across firewall operations", () => {
  it("retries reading with sudo, then uses the session credential for planning, applying and committing", async () => {
    mocks.firewallRead.mockRejectedValueOnce(sudoRequired);
    render(<FirewallView host={host}/>);
    await screen.findByText("读取防火墙状态需要 sudo 权限。");
    fireEvent.click(screen.getByRole("switch", { name: "安全记住到 Windows Credential Manager" }));
    enterPassword("sudo-secret");
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 2222" }));
    expect(mocks.firewallRead).toHaveBeenLastCalledWith(host.id, "sudo-secret", true);
    await screen.findByRole("button", { name: "确认并执行" });
    expect(mocks.firewallPlan).toHaveBeenCalledExactlyOnceWith(host.id, state.rules[0], "delete", "sudo-secret", true);
    fireEvent.click(screen.getByRole("button", { name: "确认并执行" }));
    fireEvent.click(await screen.findByRole("button", { name: "保留更改" }));
    expect(mocks.firewallApply).toHaveBeenCalledExactlyOnceWith(plan.id, "sudo-secret", true);
    expect(mocks.firewallCommit).toHaveBeenCalledExactlyOnceWith(plan.id, "sudo-secret");
  });

  it("retains the requested rule and operation when planning needs a sudo retry", async () => {
    mocks.firewallPlan.mockRejectedValueOnce(sudoRequired);
    render(<FirewallView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 2222" }));
    await screen.findByText("生成防火墙计划需要 sudo 权限。");
    enterPassword("plan-secret");
    await screen.findByRole("button", { name: "确认并执行" });
    expect(mocks.firewallPlan).toHaveBeenLastCalledWith(host.id, state.rules[0], "delete", "plan-secret", false);
    expect(mocks.firewallApply).not.toHaveBeenCalled();
  });

  it("shows an incorrect sudo password and waits for user action without an automatic retry loop", async () => {
    mocks.firewallRead.mockRejectedValueOnce(sudoRequired).mockRejectedValue({ kind: "sudoRequired", message: "sudo 验证失败" });
    render(<FirewallView host={host}/>);
    await screen.findByText("读取防火墙状态需要 sudo 权限。");
    enterPassword("wrong");
    await waitFor(() => expect(within(screen.getByRole("dialog")).getByText("sudo 验证失败")).toBeTruthy());
    expect(mocks.firewallRead).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: "继续执行" }).hasAttribute("disabled")).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "取消" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mocks.firewallRead).toHaveBeenCalledTimes(2);
    expect(mocks.firewallPlan).not.toHaveBeenCalled(); expect(mocks.firewallApply).not.toHaveBeenCalled();
  });

  it("does not reopen a sudo prompt from a previous server's late read failure", async () => {
    let reject!: (reason: unknown) => void;
    mocks.firewallRead.mockReturnValueOnce(new Promise((_, fail) => { reject = fail; }));
    const view = render(<FirewallView host={host}/>);
    const next = { ...host, id: "two" };
    mocks.firewallRead.mockResolvedValue({ ...state, hostId: next.id });
    view.rerender(<FirewallView host={next}/>);
    await screen.findByRole("button", { name: "删除规则 2222" });
    await act(async () => reject(sudoRequired));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(mocks.firewallRead).toHaveBeenLastCalledWith(next.id, undefined, false);
  });

  it.each(["commit", "rollback"] as const)("ignores the previous server's late %s result while a new plan is open", async (kind) => {
    let resolve!: () => void;
    const operation = kind === "commit" ? mocks.firewallCommit : mocks.firewallRollback;
    operation.mockReturnValueOnce(new Promise<void>((done) => { resolve = done; }));
    const view = render(<FirewallView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 2222" }));
    fireEvent.click(await screen.findByRole("button", { name: "确认并执行" }));
    fireEvent.click(await screen.findByRole("button", { name: kind === "commit" ? "保留更改" : "立即回滚" }));
    const next = { ...host, id: "two" };
    mocks.firewallRead.mockResolvedValue({ ...state, hostId: next.id });
    mocks.firewallPlan.mockResolvedValue({ ...plan, id: "next-plan", hostId: next.id, summary: "Second server plan" });
    view.rerender(<FirewallView host={next}/>);
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 2222" }));
    await screen.findByText("Second server plan");
    await act(async () => resolve());
    expect(screen.getByText("Second server plan")).toBeTruthy();
    expect(screen.getByRole("button", { name: "确认并执行" }).hasAttribute("disabled")).toBe(false);
    expect(mocks.firewallRead).toHaveBeenCalledTimes(2);
  });

  it("retries only the commit step after sudo credentials expire", async () => {
    mocks.firewallCommit.mockRejectedValueOnce({ kind: "sudoRequired", message: "sudo 验证失败" });
    render(<FirewallView host={host}/>);
    fireEvent.click(await screen.findByRole("button", { name: "删除规则 2222" }));
    fireEvent.click(await screen.findByRole("button", { name: "确认并执行" }));
    fireEvent.click(await screen.findByRole("button", { name: "保留更改" }));
    await screen.findByText("保留防火墙更改需要 sudo 权限。");
    expect(mocks.firewallCommit).toHaveBeenCalledTimes(1);
    enterPassword("new-sudo-secret");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mocks.firewallCommit).toHaveBeenCalledTimes(2);
    expect(mocks.firewallCommit).toHaveBeenLastCalledWith(plan.id, "new-sudo-secret");
    expect(mocks.firewallApply).toHaveBeenCalledTimes(1);
    expect(mocks.firewallPlan).toHaveBeenCalledTimes(1);
  });
});
