// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { useAppStore } from "./store";
import type { AppSettings, HostProfile } from "./types";

const mocks = vi.hoisted(() => ({
  hostsList: vi.fn(), settingsGet: vi.fn(), commandLogSubscribe: vi.fn(), commandLogQuery: vi.fn(),
  i18n: { language: "zh", changeLanguage: vi.fn() },
}));
vi.mock("./api", () => ({ api: mocks }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key, i18n: mocks.i18n }) }));
vi.mock("./components/ServerSidebar", () => ({ default: () => null }));
vi.mock("./components/CommandLedger", () => ({ default: () => null }));
vi.mock("./components/TransferDrawer", () => ({ default: () => null }));
vi.mock("./components/HostDialog", () => ({ default: () => null }));
vi.mock("./components/SettingsView", () => ({ default: () => null }));

const host: HostProfile = { id: "one", name: "Saved server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "disconnected", createdAt: "", updatedAt: "" };
const settings: AppSettings = { version: 1, locale: "zh", theme: "light", defaultPage: "terminal", terminalFontSize: 13, terminalScrollback: 10000, terminalPasteProtection: true, terminalCommandLogging: true, monitorIntervalSeconds: 2, transferConflictPolicy: "ask", commandRetentionDays: 7, commandRetentionMb: 100, suppressionRules: [] };

beforeEach(() => {
  vi.resetAllMocks();
  useAppStore.setState({ hosts: [], selectedHostId: undefined, settings: undefined, commands: [], page: "terminal" });
  mocks.hostsList.mockResolvedValue([host]);
  mocks.settingsGet.mockResolvedValue(settings);
  mocks.commandLogSubscribe.mockResolvedValue(undefined);
  mocks.commandLogQuery.mockResolvedValue([]);
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("application startup isolation", () => {
  it("loads database settings even when browser preference storage is unavailable", async () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("Storage denied", "SecurityError"); });
    render(<App mode="light" setMode={vi.fn()}/>);
    expect(await screen.findByText("Saved server")).toBeTruthy();
    expect(await screen.findByText("服务器尚未连接")).toBeTruthy();
    expect(useAppStore.getState().settings).toEqual(settings);
  });

  it("keeps saved servers usable when audit history fails", async () => {
    mocks.commandLogQuery.mockRejectedValue(new Error("History unavailable"));
    render(<App mode="light" setMode={vi.fn()}/>);
    expect(await screen.findByText("Saved server")).toBeTruthy();
    expect(await screen.findByText("服务器尚未连接")).toBeTruthy();
    expect(screen.getByText("命令历史加载失败：History unavailable")).toBeTruthy();
    expect(screen.queryByText("无法加载本地数据")).toBeNull();
    expect(useAppStore.getState().settings).toEqual(settings);
  });

  it("does not wait for a pending audit subscription to load servers", async () => {
    mocks.commandLogSubscribe.mockReturnValue(new Promise(() => {}));
    render(<App mode="light" setMode={vi.fn()}/>);
    expect(await screen.findByText("Saved server")).toBeTruthy();
    expect(await screen.findByText("服务器尚未连接")).toBeTruthy();
  });

  it("still reports a core configuration failure and offers reload", async () => {
    mocks.hostsList.mockRejectedValue(new Error("Database unavailable"));
    render(<App mode="light" setMode={vi.fn()}/>);
    expect(await screen.findByText("无法加载本地数据")).toBeTruthy();
    expect(screen.getByText("Database unavailable")).toBeTruthy();
    expect(screen.getByRole("button", { name: "重新加载" })).toBeTruthy();
  });
});
