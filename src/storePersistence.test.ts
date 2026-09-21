import { afterEach, describe, expect, it, vi } from "vitest";

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });

describe("optional panel preference storage", () => {
  it("still initializes and operates the panel when localStorage is unavailable", async () => {
    vi.resetModules();
    vi.stubGlobal("window", { get localStorage() { throw new Error("Storage blocked"); } });
    const { useAppStore } = await import("./store");
    expect(useAppStore.getState().commandPanelOpen).toBe(false);
    expect(useAppStore.getState().commandPanelHeight).toBe(216);
    useAppStore.getState().toggleCommandPanel();
    useAppStore.getState().setCommandPanelHeight(320);
    expect(useAppStore.getState().commandPanelOpen).toBe(true);
    expect(useAppStore.getState().commandPanelHeight).toBe(320);
  });
});
