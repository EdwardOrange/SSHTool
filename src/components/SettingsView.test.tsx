// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../store";
import type { AppSettings } from "../types";
import SettingsView from "./SettingsView";

const apiMocks = vi.hoisted(() => ({
  settingsUpdate: vi.fn().mockImplementation(async (settings: AppSettings) => settings),
  settingsReset: vi.fn(),
}));

vi.mock("../api", () => ({ api: apiMocks }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ i18n: { changeLanguage: vi.fn() } }),
}));

const settings: AppSettings = {
  version: 1,
  locale: "zh",
  theme: "system",
  defaultPage: "monitor",
  terminalFontSize: 13,
  terminalScrollback: 10000,
  terminalPasteProtection: true,
  terminalCommandLogging: true,
  monitorIntervalSeconds: 2,
  transferConflictPolicy: "ask",
  commandRetentionDays: 7,
  commandRetentionMb: 100,
  suppressionRules: [],
};

describe("SettingsView", () => {
  beforeEach(() => {
    apiMocks.settingsUpdate.mockReset().mockImplementation(async (value: AppSettings) => value);
    useAppStore.setState({ settings });
  });
  afterEach(cleanup);

  it("renders as a dialog and can close without changing workspace state", () => {
    const onClose = vi.fn();
    useAppStore.setState({ page: "terminal", selectedHostId: "host-1" });
    render(<SettingsView open onClose={onClose} onTheme={vi.fn()} />);

    expect(screen.getByRole("dialog")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));

    expect(onClose).toHaveBeenCalledOnce();
    expect(useAppStore.getState().page).toBe("terminal");
    expect(useAppStore.getState().selectedHostId).toBe("host-1");
  });

  it("keeps a requested close pending only until a failed save can be shown", async () => {
    let reject!: (reason: Error) => void;
    apiMocks.settingsUpdate.mockReturnValue(new Promise<AppSettings>((_, fail) => { reject = fail; }));
    const onClose = vi.fn();
    render(<SettingsView open onClose={onClose} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "终端" }));
    fireEvent.click(screen.getByRole("switch", { name: "粘贴前确认" }));
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
    expect(onClose).not.toHaveBeenCalled();
    await act(async () => reject(new Error("disk full")));
    expect(await screen.findByText("disk full")).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
    expect(useAppStore.getState().settings?.terminalPasteProtection).toBe(true);
  });
});
