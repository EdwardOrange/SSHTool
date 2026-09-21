import type { HostProfile } from "./types";

interface ConnectionBackend {
  sshConnect: (hostId: string, password?: string) => Promise<unknown>;
  sshHostKeyPending: (hostId: string) => Promise<string | null>;
  sshTrustHostKey: (hostId: string, fingerprint: string) => Promise<void>;
}

/** Returns false for a cancelled prompt; every prompt permits only one retry. */
export async function connectWithPrompts(
  host: HostProfile,
  backend: ConnectionBackend,
  askPassword: (host: HostProfile) => Promise<string | undefined>,
  askHostKeyTrust: (host: HostProfile, fingerprint: string) => Promise<boolean>,
): Promise<boolean> {
  let password: string | undefined;
  if ((host.authMethod === "password" || host.authMethod === "keyboardInteractive") && !host.credentialId) {
    password = await askPassword(host);
    if (!password) return false;
  }
  let passphraseRequested = false;
  let hostKeyTrusted = false;
  for (;;) {
    try {
      await backend.sshConnect(host.id, password);
      return true;
    } catch (error) {
      if (host.authMethod === "key" && (error as { kind?: string } | null)?.kind === "keyPassphraseRequired") {
        if (passphraseRequested) throw error;
        passphraseRequested = true;
        password = await askPassword(host);
        if (!password) return false;
        continue;
      }
      if (!hostKeyTrusted) {
        const fingerprint = await backend.sshHostKeyPending(host.id);
        if (fingerprint) {
          if (!(await askHostKeyTrust(host, fingerprint))) return false;
          await backend.sshTrustHostKey(host.id, fingerprint);
          hostKeyTrusted = true;
          continue;
        }
      }
      throw error;
    }
  }
}
