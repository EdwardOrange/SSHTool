// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, defaultSettings } from "./api";

afterEach(() => vi.useRealTimers());

describe("browser preview connection state", () => {
  it("reports connect and disconnect changes to connection polling", async () => {
    vi.useFakeTimers();
    const hostId = "demo-db";
    const connecting = api.sshConnect(hostId);
    await vi.advanceTimersByTimeAsync(500);
    await connecting;
    expect((await api.hostsList()).find((host) => host.id === hostId)).toMatchObject({ status: "connected", lastConnectedAt: expect.any(String) });
    await api.sshDisconnect(hostId);
    expect((await api.hostsList()).find((host) => host.id === hostId)?.status).toBe("disconnected");
  });
});

describe("browser preview state", () => {
  it("retains forwarding profiles across page reloads and stops them on disconnect", async () => {
    const saved = await api.forwardingUpsert({ id: "preview-forward", hostId: "demo-prod", name: "Preview", kind: "local", bindAddress: "127.0.0.1", bindPort: 8080, targetHost: "127.0.0.1", targetPort: 80, active: false, status: "stopped" });
    expect(await api.forwardingList(saved.hostId)).toContainEqual(saved);
    expect(await api.forwardingToggle(saved.id, true)).toMatchObject({ active: true, status: "active" });
    await api.sshDisconnect(saved.hostId);
    expect((await api.forwardingList(saved.hostId))[0]).toMatchObject({ active: false, status: "stopped" });
    await expect(api.forwardingToggle(saved.id, true)).rejects.toThrow("请先连接服务器");
    await api.forwardingDelete(saved.id);
    expect(await api.forwardingList(saved.hostId)).toEqual([]);
  });

  it("returns saved settings and resets them without sharing mutable references", async () => {
    const draft = { ...defaultSettings(), terminalFontSize: 19 };
    await api.settingsUpdate(draft);
    draft.terminalFontSize = 24;
    expect((await api.settingsGet()).terminalFontSize).toBe(19);
    await api.settingsReset();
    expect(await api.settingsGet()).toEqual(defaultSettings());
  });
});
