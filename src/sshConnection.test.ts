import { describe, expect, it, vi } from "vitest";
import type { HostProfile } from "./types";
import { connectWithPrompts } from "./sshConnection";

const host: HostProfile = { id: "key-host", name: "Server", hostname: "example.test", port: 22, username: "ops", groupName: "Test", tags: [], favorite: false, authMethod: "key", jumpHosts: [], status: "disconnected", createdAt: "", updatedAt: "" };
const keyRequired = { kind: "keyPassphraseRequired", message: "请输入私钥口令" };
const backend = () => ({ sshConnect: vi.fn().mockResolvedValue(undefined), sshHostKeyPending: vi.fn().mockResolvedValue(null), sshTrustHostKey: vi.fn().mockResolvedValue(undefined) });

describe("SSH credential prompts", () => {
  it("connects an unencrypted or already remembered key without a password prompt", async () => {
    const api = backend(), password = vi.fn();
    expect(await connectWithPrompts(host, api, password, vi.fn())).toBe(true);
    expect(api.sshConnect).toHaveBeenCalledExactlyOnceWith(host.id, undefined);
    expect(password).not.toHaveBeenCalled();
  });

  it("retries once with a supplied passphrase only when the backend requests it", async () => {
    const api = backend(), password = vi.fn().mockResolvedValue("private-passphrase");
    api.sshConnect.mockRejectedValueOnce(keyRequired);
    expect(await connectWithPrompts(host, api, password, vi.fn())).toBe(true);
    expect(password).toHaveBeenCalledExactlyOnceWith(host);
    expect(api.sshConnect).toHaveBeenLastCalledWith(host.id, "private-passphrase");
    expect(api.sshConnect).toHaveBeenCalledTimes(2);
  });

  it("stops after a wrong passphrase without reopening the prompt indefinitely", async () => {
    const api = backend(), password = vi.fn().mockResolvedValue("wrong");
    api.sshConnect.mockRejectedValue(keyRequired);
    await expect(connectWithPrompts(host, api, password, vi.fn())).rejects.toEqual(keyRequired);
    expect(password).toHaveBeenCalledTimes(1);
    expect(api.sshConnect).toHaveBeenCalledTimes(2);
  });

  it("cancels an encrypted key prompt without trying to connect again", async () => {
    const api = backend(); api.sshConnect.mockRejectedValueOnce(keyRequired);
    expect(await connectWithPrompts(host, api, vi.fn().mockResolvedValue(undefined), vi.fn())).toBe(false);
    expect(api.sshConnect).toHaveBeenCalledTimes(1);
  });

  it("handles a first host-key confirmation followed by the encrypted key prompt", async () => {
    const api = backend(), password = vi.fn().mockResolvedValue("secret"), trust = vi.fn().mockResolvedValue(true);
    api.sshConnect.mockRejectedValueOnce({ kind: "permission", message: "untrusted host" }).mockRejectedValueOnce(keyRequired);
    api.sshHostKeyPending.mockResolvedValueOnce("SHA256:test");
    expect(await connectWithPrompts(host, api, password, trust)).toBe(true);
    expect(api.sshTrustHostKey).toHaveBeenCalledExactlyOnceWith(host.id, "SHA256:test");
    expect(api.sshConnect).toHaveBeenCalledTimes(3);
    expect(api.sshConnect).toHaveBeenLastCalledWith(host.id, "secret");
  });

  it("does not ask for a key passphrase when the backend reports a network failure", async () => {
    const api = backend(), password = vi.fn();
    const networkError = { kind: "ssh", message: "Connection refused" }; api.sshConnect.mockRejectedValue(networkError);
    await expect(connectWithPrompts(host, api, password, vi.fn())).rejects.toEqual(networkError);
    expect(password).not.toHaveBeenCalled();
    expect(api.sshConnect).toHaveBeenCalledTimes(1);
  });
});
