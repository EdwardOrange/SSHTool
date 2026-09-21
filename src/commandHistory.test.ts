import { describe, expect, it, vi } from "vitest";
import { loadCommandHistory } from "./commandHistory";
import type { CommandRecord, StreamEnvelope } from "./types";

const record = (id: string, status: CommandRecord["status"] = "success"): CommandRecord => ({ id, timestamp: "2026-09-20T10:00:00Z", source: "terminal", command: "true", stdout: "", stderr: "", durationMs: 0, status, repeatCount: 1 });
const event = (payload: CommandRecord): StreamEnvelope<CommandRecord> => ({ seq: 1, timestamp: payload.timestamp, hostId: "one", payload });

describe("command history initialization", () => {
  it("preserves commands and completed updates arriving while the initial query loads", async () => {
    let receive!: (event: StreamEnvelope<CommandRecord>) => void;
    let resolve!: (records: CommandRecord[]) => void;
    const query = vi.fn(() => new Promise<CommandRecord[]>((done) => { resolve = done; }));
    const replace = vi.fn(), append = vi.fn();
    const loading = loadCommandHistory({ subscribe: async (callback) => { receive = callback; }, query }, replace, append, () => true);
    await Promise.resolve();
    receive(event(record("existing", "success")));
    receive(event(record("new")));
    resolve([record("existing", "running")]);
    await loading;
    expect(replace).toHaveBeenCalledExactlyOnceWith([record("existing", "success"), record("new")]);
    expect(append).not.toHaveBeenCalled();
    receive(event(record("live")));
    expect(append).toHaveBeenCalledExactlyOnceWith(record("live"));
  });

  it("ignores the snapshot and streamed events after the application unmounts", async () => {
    let alive = true;
    let receive!: (event: StreamEnvelope<CommandRecord>) => void;
    let resolve!: (records: CommandRecord[]) => void;
    const replace = vi.fn(), append = vi.fn();
    const loading = loadCommandHistory({ subscribe: async (callback) => { receive = callback; }, query: () => new Promise((done) => { resolve = done; }) }, replace, append, () => alive);
    await Promise.resolve();
    alive = false;
    receive(event(record("late"))); resolve([record("old")]);
    await loading;
    expect(replace).not.toHaveBeenCalled(); expect(append).not.toHaveBeenCalled();
  });

  it("keeps live logging working when the initial history query fails", async () => {
    let receive!: (event: StreamEnvelope<CommandRecord>) => void;
    let reject!: (error: Error) => void;
    const replace = vi.fn(), append = vi.fn();
    const loading = loadCommandHistory({ subscribe: async (callback) => { receive = callback; }, query: () => new Promise((_, fail) => { reject = fail; }) }, replace, append, () => true);
    const failed = expect(loading).rejects.toThrow("History unavailable");
    await Promise.resolve();
    receive(event(record("buffered")));
    reject(new Error("History unavailable"));
    await failed;
    expect(replace).not.toHaveBeenCalled();
    expect(append).toHaveBeenCalledWith(record("buffered"));
    receive(event(record("live")));
    expect(append).toHaveBeenLastCalledWith(record("live"));
    expect(append).toHaveBeenCalledTimes(2);
  });
});
