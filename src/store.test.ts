import { beforeEach, describe, expect, it } from "vitest";
import { useAppStore } from "./store";
import type { HostProfile } from "./types";

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
