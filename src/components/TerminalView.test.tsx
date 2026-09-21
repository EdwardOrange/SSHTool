// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useAppStore } from "../store";
import type { HostProfile, StreamEnvelope } from "../types";
import TerminalView from "./TerminalView";

const mocks = vi.hoisted(() => ({
  terminalOpen: vi.fn(), terminalClose: vi.fn(), terminalInput: vi.fn(), terminalResize: vi.fn(), terminalSetAudit: vi.fn(),
  terminals: [] as { element: HTMLElement; data: (text: string) => void; write: ReturnType<typeof vi.fn>; paste: ReturnType<typeof vi.fn> }[],
}));
vi.mock("../api", () => ({ api: mocks }));
vi.mock("@xterm/xterm", () => ({ Terminal: class {
  cols = 80; rows = 24; options = {}; element!: HTMLElement; data = (_text: string) => {};
  write = vi.fn(); writeln = vi.fn(); paste = vi.fn();
  constructor() { mocks.terminals.push(this); }
  open(element: HTMLElement) { this.element = element; }
  loadAddon() {} focus() {} dispose() {} hasSelection() { return false; }
  onData(callback: (text: string) => void) { this.data = callback; return { dispose() {} }; }
  onResize() { return { dispose() {} }; }
} }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));
vi.mock("@xterm/addon-search", () => ({ SearchAddon: class {} }));
vi.mock("@xterm/addon-web-links", () => ({ WebLinksAddon: class {} }));

const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "connected", createdAt: "", updatedAt: "" };
const deferred = <T,>() => { let resolve!: (value: T) => void; const promise = new Promise<T>((done) => { resolve = done; }); return { promise, resolve }; };

beforeEach(() => {
  vi.resetAllMocks(); mocks.terminals.length = 0;
  useAppStore.setState({ settings: undefined });
  mocks.terminalOpen.mockResolvedValue("session-one");
  for (const mock of [mocks.terminalClose, mocks.terminalInput, mocks.terminalResize, mocks.terminalSetAudit]) mock.mockResolvedValue(undefined);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("terminal lifecycle and input safety", () => {
  it("closes immediately when an input is blocked and discards unsent keystrokes", async () => {
    const blocked = deferred<void>(); mocks.terminalInput.mockReturnValue(blocked.promise);
    const view = render(<TerminalView host={host}/>);
    await act(async () => {});
    await act(async () => { mocks.terminals[0].data("a"); mocks.terminals[0].data("b"); });
    expect(mocks.terminalInput).toHaveBeenCalledTimes(1);
    view.unmount();
    expect(mocks.terminalClose).toHaveBeenCalledWith("session-one");
    await act(async () => blocked.resolve());
    expect(mocks.terminalInput).toHaveBeenCalledTimes(1);
  });

  it("closes a session that finishes opening after unmount", async () => {
    const opening = deferred<string>(); mocks.terminalOpen.mockReturnValue(opening.promise);
    const view = render(<TerminalView host={host}/>);
    mocks.terminals[0].data("never send this\r");
    view.unmount();
    await act(async () => opening.resolve("late-session"));
    expect(mocks.terminalClose).toHaveBeenCalledWith("late-session");
    expect(mocks.terminalInput).not.toHaveBeenCalled();
  });

  it("intercepts native paste until the user confirms the target and content", async () => {
    render(<TerminalView host={host}/>);
    const terminal = mocks.terminals[0];
    const paste = new Event("paste", { bubbles: true, cancelable: true });
    Object.defineProperty(paste, "clipboardData", { value: { getData: () => "printf test\n" } });
    fireEvent(terminal.element, paste);
    expect(paste.defaultPrevented).toBe(true);
    expect(terminal.paste).not.toHaveBeenCalled();
    fireEvent.click(await screen.findByRole("button", { name: "发送" }));
    expect(terminal.paste).toHaveBeenCalledExactlyOnceWith("printf test\n");
  });

  it("decodes multibyte terminal output across separate backend frames", async () => {
    render(<TerminalView host={host}/>);
    await act(async () => {});
    const onData = mocks.terminalOpen.mock.calls[0][4] as (event: StreamEnvelope<number[]>) => void;
    const bytes = Array.from(new TextEncoder().encode("你好"));
    const envelope = { seq: 1, timestamp: "", hostId: host.id };
    act(() => { onData({ ...envelope, payload: bytes.slice(0, 2) }); onData({ ...envelope, payload: bytes.slice(2) }); });
    expect(mocks.terminals[0].write.mock.calls.map(([text]) => text).join("")).toBe("你好");
  });
});
