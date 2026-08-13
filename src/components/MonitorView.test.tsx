// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { HostProfile } from "../types";
import { useAppStore } from "../store";
import MonitorView from "./MonitorView";

const apiMocks = vi.hoisted(() => ({
  monitorStart: vi.fn(),
  monitorStop: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("../api", () => ({ api: apiMocks }));

const host: HostProfile = {
  id: "host-1",
  name: "Test server",
  hostname: "127.0.0.1",
  port: 22,
  username: "root",
  groupName: "Default",
  tags: [],
  favorite: false,
  authMethod: "password",
  jumpHosts: [],
  status: "disconnected",
  createdAt: new Date(0).toISOString(),
  updatedAt: new Date(0).toISOString(),
};

describe("MonitorView", () => {
  beforeEach(() => {
    apiMocks.monitorStart.mockClear();
    apiMocks.monitorStop.mockClear();
    useAppStore.setState({ metrics: {} });
  });

  it("does not mount live monitoring or charts for a disconnected host", () => {
    render(<MonitorView host={host} />);
    expect(screen.getByText("服务器尚未连接")).toBeTruthy();
    expect(apiMocks.monitorStart).not.toHaveBeenCalled();
  });
});
