// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ForwardingProfile, HostProfile } from "../types";
import ForwardingView from "./ForwardingView";

const mocks = vi.hoisted(() => ({ forwardingList: vi.fn(), forwardingUpsert: vi.fn(), forwardingToggle: vi.fn(), forwardingDelete: vi.fn() }));
vi.mock("../api", () => ({ api: mocks }));
const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "connected", createdAt: "", updatedAt: "" };
const profile: ForwardingProfile = { id: "tunnel", hostId: host.id, name: "Tunnel", kind: "local", bindAddress: "127.0.0.1", bindPort: 8080, targetHost: "localhost", targetPort: 80, active: false, status: "stopped" };
beforeEach(() => { vi.resetAllMocks(); mocks.forwardingList.mockResolvedValue([]); mocks.forwardingUpsert.mockImplementation(async (value: ForwardingProfile) => value); });
afterEach(cleanup);

describe("ForwardingView", () => {
  it("can recover from a failed listing without leaving the page", async () => {
    mocks.forwardingList.mockRejectedValueOnce(new Error("Read failed")).mockResolvedValueOnce([profile]);
    render(<ForwardingView host={host}/>);
    await screen.findByText("Read failed");
    expect(screen.queryByText("尚未创建端口转发")).toBeNull();
    expect(screen.getByRole("button", { name: "新建转发" }).hasAttribute("disabled")).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "刷新端口转发" }));
    await screen.findByText("Tunnel");
    expect(screen.queryByText("Read failed")).toBeNull();
    expect(screen.getByRole("button", { name: "新建转发" }).hasAttribute("disabled")).toBe(false);
  });

  it("shows failed starts on the profile and clears the old error when retry succeeds", async () => {
    mocks.forwardingList.mockResolvedValue([profile]);
    mocks.forwardingToggle.mockRejectedValueOnce(new Error("Port already bound")).mockResolvedValueOnce({ ...profile, active: true, status: "active" });
    render(<ForwardingView host={host}/>);
    fireEvent.click(await screen.findByRole("switch", { name: "启动Tunnel" }));
    await screen.findByText("启动失败");
    expect(screen.getByRole("alert").textContent).toContain("Port already bound");
    fireEvent.click(screen.getByRole("switch", { name: "启动Tunnel" }));
    await screen.findByText("运行中");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("trims pasted addresses and resets a saved form for the next forwarding profile", async () => {
    render(<ForwardingView host={host}/>);
    await waitFor(() => expect(screen.getByRole("button", { name: "新建转发" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "新建转发" }));
    fireEvent.change(screen.getByRole("textbox", { name: "名称" }), { target: { value: "  Test tunnel  " } });
    fireEvent.change(screen.getByRole("textbox", { name: "监听地址" }), { target: { value: "  127.0.0.1  " } });
    fireEvent.change(screen.getByRole("textbox", { name: "目标主机" }), { target: { value: "  localhost  " } });
    fireEvent.click(screen.getByRole("button", { name: "保存" }));
    await screen.findByText("Test tunnel");
    expect(mocks.forwardingUpsert).toHaveBeenCalledWith(expect.objectContaining({ name: "Test tunnel", bindAddress: "127.0.0.1", targetHost: "localhost" }));
    fireEvent.click(screen.getByRole("button", { name: "新建转发" }));
    expect((screen.getByRole("textbox", { name: "名称" }) as HTMLInputElement).value).toBe("");
  });

  it("locks duplicate save events before React renders the busy state", async () => {
    let resolve!: (value: ForwardingProfile) => void;
    mocks.forwardingUpsert.mockReturnValue(new Promise<ForwardingProfile>((done) => { resolve = done; }));
    render(<ForwardingView host={host}/>);
    await waitFor(() => expect(screen.getByRole("button", { name: "新建转发" }).hasAttribute("disabled")).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "新建转发" }));
    fireEvent.change(screen.getByRole("textbox", { name: "名称" }), { target: { value: "Tunnel" } });
    const save = screen.getByRole("button", { name: "保存" });
    act(() => { save.click(); save.click(); });
    expect(mocks.forwardingUpsert).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "刷新端口转发" }).hasAttribute("disabled")).toBe(true);
    await act(async () => resolve(profile));
    await screen.findByText("Tunnel");
  });
});
