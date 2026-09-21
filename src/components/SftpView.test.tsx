// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppSettings, HostProfile, StreamEnvelope, TransferProgress } from "../types";
import { useAppStore } from "../store";
import SftpView from "./SftpView";

const mocks = vi.hoisted(() => ({ sftpList: vi.fn(), sftpCopy: vi.fn(), sftpUpload: vi.fn(), open: vi.fn() }));
vi.mock("../api", () => ({ api: mocks }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: mocks.open }));
const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "agent", jumpHosts: [], status: "connected", createdAt: "", updatedAt: "" };
const deferred = <T,>() => { let resolve!: (value: T) => void; let reject!: (error: Error) => void; const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; }); return { promise, resolve, reject }; };

beforeEach(() => {
  vi.resetAllMocks();
  useAppStore.setState({ transfers: {}, settings: { transferConflictPolicy: "overwrite" } as AppSettings });
  mocks.sftpList.mockResolvedValue([{ name: "file.txt", path: "/file.txt", kind: "file", size: 1 }]);
});
afterEach(cleanup);

async function copyFile() {
  fireEvent.click(await screen.findByRole("checkbox", { name: "选择 file.txt" }));
  fireEvent.click(screen.getByRole("button", { name: "复制" }));
}

describe("SFTP transfer initiation", () => {
  it("locks repeated paste requests while the copy is starting", async () => {
    const copying = deferred<string>(); mocks.sftpCopy.mockReturnValue(copying.promise);
    render(<SftpView host={host}/>);
    await copyFile();
    const paste = screen.getByRole("button", { name: "粘贴" });
    fireEvent.click(paste); fireEvent.click(paste);
    expect(mocks.sftpCopy).toHaveBeenCalledTimes(1);
    expect(paste.hasAttribute("disabled")).toBe(true);
    await act(async () => copying.resolve("copy-one"));
    expect(paste.hasAttribute("disabled")).toBe(true); // Clipboard was consumed.
  });

  it("ignores a previous host's copy failure", async () => {
    const copying = deferred<string>(); mocks.sftpCopy.mockReturnValue(copying.promise);
    const view = render(<SftpView host={host}/>);
    await copyFile();
    fireEvent.click(screen.getByRole("button", { name: "粘贴" }));
    view.rerender(<SftpView host={{ ...host, id: "two" }}/>);
    await act(async () => copying.reject(new Error("Old server copy failed")));
    expect(screen.queryByText("Old server copy failed")).toBeNull();
  });

  it("keeps tracking a completed copy without refreshing a different server", async () => {
    mocks.sftpCopy.mockResolvedValue("copy-one");
    const view = render(<SftpView host={host}/>);
    await copyFile();
    fireEvent.click(screen.getByRole("button", { name: "粘贴" }));
    await act(async () => {});
    const receive = mocks.sftpCopy.mock.calls[0][3] as (event: StreamEnvelope<TransferProgress>) => void;
    view.rerender(<SftpView host={{ ...host, id: "two" }}/>);
    await act(async () => {});
    const count = mocks.sftpList.mock.calls.length;
    const progress: TransferProgress = { transferId: "copy-one", hostId: host.id, direction: "transfer", status: "completed", transferred: 1, total: 1, currentPath: "/file.txt", fileIndex: 1, fileCount: 1, currentFileTransferred: 1, currentFileTotal: 1 };
    act(() => receive({ seq: 1, timestamp: "", hostId: host.id, payload: progress }));
    expect(mocks.sftpList).toHaveBeenCalledTimes(count);
    expect(useAppStore.getState().transfers["copy-one"].progress.status).toBe("completed");
  });

  it("opens only one file picker and drops its result if the server changes", async () => {
    const picker = deferred<string[]>(); mocks.open.mockReturnValue(picker.promise);
    const view = render(<SftpView host={host}/>);
    await waitFor(() => expect(screen.getByRole("button", { name: "上传文件" }).hasAttribute("disabled")).toBe(false));
    const upload = screen.getByRole("button", { name: "上传文件" });
    fireEvent.click(upload); fireEvent.click(upload);
    expect(mocks.open).toHaveBeenCalledTimes(1);
    view.rerender(<SftpView host={{ ...host, id: "two" }}/>);
    await act(async () => picker.resolve(["C:\\source.txt"]));
    expect(mocks.sftpUpload).not.toHaveBeenCalled();
  });
});
