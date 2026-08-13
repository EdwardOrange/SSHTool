// @vitest-environment jsdom
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
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
    useAppStore.setState({ settings });
  });

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
});
