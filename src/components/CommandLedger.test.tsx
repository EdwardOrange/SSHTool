// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../store";
import CommandLedger from "./CommandLedger";

const mocks = vi.hoisted(() => ({ commandLogClear: vi.fn() }));
vi.mock("../api", () => ({ api: mocks }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
afterEach(cleanup);

describe("command details", () => {
  it("shows stderr alongside stdout so partial success does not hide the failure", () => {
    useAppStore.setState({ settings: undefined, commandPanelOpen: true, commands: [{
      id: "mixed", timestamp: new Date().toISOString(), source: "system", command: "partial-command",
      stdout: "first step succeeded", stderr: "second step failed", durationMs: 5, status: "error", repeatCount: 1,
    }] });
    render(<CommandLedger/>);
    fireEvent.click(screen.getByText("$ partial-command"));
    expect(screen.getByText(/first step succeeded[\s\S]*second step failed/)).toBeTruthy();
  });

  it("retains new audit events arriving before a clear response and prevents duplicate clearing", async () => {
    let resolve!: (ids: string[]) => void;
    mocks.commandLogClear.mockReturnValue(new Promise<string[]>((done) => { resolve = done; }));
    const old = { id: "old", timestamp: "2026-09-21T00:00:00Z", source: "system" as const, command: "old-command", stdout: "", stderr: "", durationMs: 1, status: "success" as const, repeatCount: 1 };
    useAppStore.setState({ settings: undefined, commandPanelOpen: true, commands: [old] });
    render(<CommandLedger/>);
    fireEvent.click(screen.getByRole("button", { name: "永久清空" }));
    const confirm = within(screen.getByRole("dialog")).getByRole("button", { name: "永久清空" });
    fireEvent.click(confirm); fireEvent.click(confirm);
    expect(mocks.commandLogClear).toHaveBeenCalledTimes(1);
    act(() => useAppStore.getState().addCommand({ ...old, id: "after-clear", command: "new-command" }));
    await act(async () => resolve(["old"]));
    expect(useAppStore.getState().commands.map((command) => command.id)).toEqual(["after-clear"]);
    expect(screen.getByText("$ new-command")).toBeTruthy();
  });

  it("shows a failed clear inside the confirmation dialog and retains history", async () => {
    mocks.commandLogClear.mockRejectedValue(new Error("Database is locked"));
    const old = { id: "old", timestamp: "2026-09-21T00:00:00Z", source: "system" as const, command: "old-command", stdout: "", stderr: "", durationMs: 1, status: "success" as const, repeatCount: 1 };
    useAppStore.setState({ settings: undefined, commandPanelOpen: true, commands: [old] });
    render(<CommandLedger/>);
    fireEvent.click(screen.getByRole("button", { name: "永久清空" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "永久清空" }));
    expect(await within(screen.getByRole("dialog")).findByRole("alert")).toHaveProperty("textContent", "Database is locked");
    expect(useAppStore.getState().commands).toEqual([old]);
  });

  it("clears displayed records already pruned from the database while preserving newly received records", async () => {
    let resolve!: (ids: string[]) => void;
    mocks.commandLogClear.mockReturnValue(new Promise<string[]>((done) => { resolve = done; }));
    const old = { id: "retention-pruned", timestamp: "2026-09-21T00:00:00Z", source: "system" as const, command: "pruned-command", stdout: "", stderr: "", durationMs: 1, status: "success" as const, repeatCount: 1 };
    useAppStore.setState({ settings: undefined, commandPanelOpen: true, commands: [old], clearedCommandIds: new Set() });
    render(<CommandLedger/>);
    fireEvent.click(screen.getByRole("button", { name: "永久清空" }));
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "永久清空" }));
    act(() => useAppStore.getState().addCommand({ ...old, id: "after-pruning-clear", command: "new-command" }));
    await act(async () => resolve([]));
    expect(useAppStore.getState().commands.map((command) => command.id)).toEqual(["after-pruning-clear"]);
  });
});
