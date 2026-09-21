// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";

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
