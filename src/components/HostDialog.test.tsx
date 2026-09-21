// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HostProfile } from "../types";
import HostDialog from "./HostDialog";

const mocks = vi.hoisted(() => ({ hostsUpsert: vi.fn() }));
vi.mock("../api", () => ({ api: mocks }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
afterEach(cleanup);

const host: HostProfile = { id: "one", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: ["first"], favorite: false, authMethod: "agent", jumpHosts: [], status: "disconnected", createdAt: "", updatedAt: "" };

describe("host editing", () => {
  beforeEach(() => mocks.hostsUpsert.mockReset().mockImplementation(async (draft) => ({ ...host, ...draft })));

  it("saves an optional encrypted-key passphrase with the secure storage choice", async () => {
    render(<HostDialog open initialHost={{ ...host, authMethod: "key", privateKeyPath: "C:\\keys\\encrypted" }} onClose={vi.fn()}/>);
    fireEvent.change(screen.getByLabelText("私钥口令（可选）"), { target: { value: "key-secret" } });
    fireEvent.click(screen.getByRole("switch", { name: "安全保存私钥口令到 Windows Credential Manager" }));
    fireEvent.click(screen.getByRole("button", { name: "save" }));
    await waitFor(() => expect(mocks.hostsUpsert).toHaveBeenCalledWith(expect.objectContaining({ authMethod: "key", password: "key-secret", rememberPassword: true })));
  });

  it("discards password text and secure storage selection when authentication changes", async () => {
    render(<HostDialog open initialHost={{ ...host, authMethod: "password", credentialId: "saved-password", privateKeyPath: "C:\\keys\\key" }} onClose={vi.fn()}/>);
    fireEvent.change(screen.getByLabelText("SSH 密码"), { target: { value: "password-for-ssh" } });
    fireEvent.mouseDown(screen.getByRole("combobox", { name: "auth" }));
    fireEvent.click(screen.getByRole("option", { name: "私钥" }));
    expect((screen.getByLabelText("私钥口令（可选）") as HTMLInputElement).value).toBe("");
    expect((screen.getByRole("switch", { name: "安全保存私钥口令到 Windows Credential Manager" }) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "save" }));
    await waitFor(() => expect(mocks.hostsUpsert).toHaveBeenCalledWith(expect.objectContaining({ authMethod: "key", password: undefined, credentialId: undefined, rememberPassword: false })));
  });

  it("allows an unencrypted key to be saved without any passphrase", async () => {
    render(<HostDialog open initialHost={{ ...host, authMethod: "key", privateKeyPath: "C:\\keys\\unencrypted" }} onClose={vi.fn()}/>);
    fireEvent.click(screen.getByRole("button", { name: "save" }));
    await waitFor(() => expect(mocks.hostsUpsert).toHaveBeenCalledWith(expect.objectContaining({ authMethod: "key", rememberPassword: false })));
    expect(mocks.hostsUpsert.mock.calls[0][0].password).toBeUndefined();
  });

  it("requires a fresh passphrase choice after the private-key path changes", async () => {
    render(<HostDialog open initialHost={{ ...host, authMethod: "key", privateKeyPath: "C:\\keys\\old", credentialId: "saved-key-passphrase" }} onClose={vi.fn()}/>);
    expect(screen.getByText("留空保留已保存的口令；取消安全保存可移除。")).toBeTruthy();
    fireEvent.change(screen.getByLabelText("私钥口令（可选）"), { target: { value: "old-secret" } });
    fireEvent.change(screen.getByRole("textbox", { name: "私钥路径" }), { target: { value: "C:\\keys\\new" } });
    expect(screen.queryByText("留空保留已保存的口令；取消安全保存可移除。")).toBeNull();
    expect((screen.getByLabelText("私钥口令（可选）") as HTMLInputElement).value).toBe("");
    expect((screen.getByRole("switch", { name: "安全保存私钥口令到 Windows Credential Manager" }) as HTMLInputElement).checked).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "save" }));
    await waitFor(() => expect(mocks.hostsUpsert).toHaveBeenCalledWith(expect.objectContaining({ privateKeyPath: "C:\\keys\\new", password: undefined, credentialId: undefined, rememberPassword: false })));
  });

  it("preserves typed separators until multiple tags are saved", async () => {
    mocks.hostsUpsert.mockImplementation(async (draft) => ({ ...host, ...draft }));
    render(<HostDialog open initialHost={host} onClose={vi.fn()}/>);
    const input = screen.getByRole("textbox", { name: "标签" }) as HTMLInputElement;
    fireEvent.change(input, { target: { value: "first," } });
    expect(input.value).toBe("first,");
    fireEvent.change(input, { target: { value: "first, second, " } });
    fireEvent.click(screen.getByRole("button", { name: "save" }));
    await waitFor(() => expect(mocks.hostsUpsert).toHaveBeenCalledWith(expect.objectContaining({ tags: ["first", "second"] })));
  });
});
