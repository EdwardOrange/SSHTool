import { beforeEach, describe, expect, it } from "vitest";
import { useAppStore } from "./store";
import type { CommandRecord, HostProfile } from "./types";

const host: HostProfile = { id: "one", name: "Original", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "disconnected", createdAt: "", updatedAt: "" };

describe("host connection updates", () => {
  beforeEach(() => useAppStore.setState({ hosts: [host], selectedHostId: host.id }));

  it("preserves profile changes made while connecting", () => {
    useAppStore.getState().upsertHost({ ...host, name: "Renamed", favorite: true });
    useAppStore.getState().updateHostConnection(host.id, { status: "connected", lastConnectedAt: "now" });
    expect(useAppStore.getState().hosts[0]).toMatchObject({ name: "Renamed", favorite: true, status: "connected", lastConnectedAt: "now" });
  });

  it("does not recreate a host deleted before a connection response arrives", () => {
    useAppStore.getState().removeHost(host.id);
    useAppStore.getState().updateHostConnection(host.id, { status: "error" });
    expect(useAppStore.getState().hosts).toEqual([]);
    expect(useAppStore.getState().selectedHostId).toBeUndefined();
  });
});

describe("audit clear reconciliation", () => {
  it("does not restore deleted IDs from late live events or a pre-clear snapshot", () => {
    const old: CommandRecord = { id: "cleared-id", timestamp: "2026-09-21T00:00:00Z", source: "system", command: "old", stdout: "", stderr: "", durationMs: 0, status: "success", repeatCount: 1 };
    const current = { ...old, id: "new-id" };
    useAppStore.setState({ commands: [old, current], clearedCommandIds: new Set() });
    useAppStore.getState().removeCommands([old.id]);
    useAppStore.getState().addCommand(old);
    expect(useAppStore.getState().commands).toEqual([current]);
    useAppStore.getState().setCommands([old, current]);
    expect(useAppStore.getState().commands).toEqual([current]);
  });
});
