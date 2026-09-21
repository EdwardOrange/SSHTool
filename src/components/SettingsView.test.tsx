// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("does not persist intermediate retention values while the user replaces a number", async () => {
    render(<SettingsView open onClose={vi.fn()} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "命令记录" }));
    const input = screen.getByRole("spinbutton", { name: "保留天数" }) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "" } });
    expect(input.value).toBe("");
    fireEvent.change(input, { target: { value: "3" } });
    fireEvent.change(input, { target: { value: "30" } });
    expect(apiMocks.settingsUpdate).not.toHaveBeenCalled();
    expect(useAppStore.getState().settings?.commandRetentionDays).toBe(7);
    fireEvent.blur(input);
    await waitFor(() => expect(apiMocks.settingsUpdate).toHaveBeenCalledOnce());
    expect(apiMocks.settingsUpdate).toHaveBeenCalledWith(expect.objectContaining({ commandRetentionDays: 30 }));
  });

  it("rejects invalid integer settings and keeps the dialog open for correction", async () => {
    const onClose = vi.fn();
    render(<SettingsView open onClose={onClose} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "终端" }));
    const input = screen.getByRole("spinbutton", { name: "滚动缓冲行数" });
    for (const value of ["", "100.5", "100001"]) {
      fireEvent.change(input, { target: { value } });
      fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
      expect(screen.getByText("请输入 100–100000 之间的整数")).toBeTruthy();
      expect(onClose).not.toHaveBeenCalled();
      expect(apiMocks.settingsUpdate).not.toHaveBeenCalled();
    }
    fireEvent.change(input, { target: { value: "20000" } });
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(apiMocks.settingsUpdate).toHaveBeenCalledWith(expect.objectContaining({ terminalScrollback: 20000 }));
  });

  it("commits a numeric draft before leaving its settings section", async () => {
    render(<SettingsView open onClose={vi.fn()} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "命令记录" }));
    fireEvent.change(screen.getByRole("spinbutton", { name: "最大容量 MB" }), { target: { value: "500" } });
    fireEvent.click(screen.getByRole("tab", { name: "常规" }));
    await waitFor(() => expect(apiMocks.settingsUpdate).toHaveBeenCalledWith(expect.objectContaining({ commandRetentionMb: 500 })));
    expect(screen.getByRole("combobox", { name: "主题" })).toBeTruthy();
  });

  it("waits for a numeric blur save before closing and submits it only once", async () => {
    let resolve!: (value: AppSettings) => void;
    apiMocks.settingsUpdate.mockReturnValue(new Promise<AppSettings>((done) => { resolve = done; }));
    const onClose = vi.fn();
    render(<SettingsView open onClose={onClose} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "终端" }));
    const input = screen.getByRole("spinbutton", { name: "滚动缓冲行数" });
    fireEvent.change(input, { target: { value: "20000" } });
    fireEvent.blur(input);
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
    expect(onClose).not.toHaveBeenCalled();
    await waitFor(() => expect(apiMocks.settingsUpdate).toHaveBeenCalledOnce());
    await act(async () => resolve({ ...settings, terminalScrollback: 20000 }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("keeps the numeric save failure visible after a blur and close request", async () => {
    let reject!: (error: Error) => void;
    apiMocks.settingsUpdate.mockReturnValue(new Promise<AppSettings>((_, fail) => { reject = fail; }));
    const onClose = vi.fn();
    render(<SettingsView open onClose={onClose} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "终端" }));
    const input = screen.getByRole("spinbutton", { name: "滚动缓冲行数" }) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "20000" } });
    fireEvent.blur(input);
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
    await act(async () => reject(new Error("Cannot save settings")));
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole("alert").textContent).toBe("Cannot save settings");
    expect(input.value).toBe("10000");
  });

  it("does not discard a new numeric draft while a requested close waits for a prior save", async () => {
    let resolve!: (value: AppSettings) => void;
    apiMocks.settingsUpdate.mockReturnValueOnce(new Promise<AppSettings>((done) => { resolve = done; }));
    const onClose = vi.fn();
    render(<SettingsView open onClose={onClose} onTheme={vi.fn()}/>);
    fireEvent.click(screen.getByRole("tab", { name: "终端" }));
    const input = screen.getByRole("spinbutton", { name: "滚动缓冲行数" }) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "20000" } });
    fireEvent.blur(input);
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
    fireEvent.change(input, { target: { value: "30000" } });
    await act(async () => resolve({ ...settings, terminalScrollback: 20000 }));
    expect(onClose).not.toHaveBeenCalled();
    expect(input.value).toBe("30000");
    fireEvent.click(screen.getByRole("button", { name: "关闭设置" }));
    await waitFor(() => expect(onClose).toHaveBeenCalledOnce());
    expect(apiMocks.settingsUpdate).toHaveBeenLastCalledWith(expect.objectContaining({ terminalScrollback: 30000 }));
  });
});
