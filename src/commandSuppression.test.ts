import { describe, expect, it } from "vitest";
import { commandMatchesSuppression } from "./commandSuppression";
import type { CommandRecord } from "./types";

const command: CommandRecord = {
  id: "1", timestamp: "2026-01-01T00:00:00Z", hostId: "host-1", source: "monitor",
  operationKind: "monitor.sample", command: "CAT /PROC/STAT", stdout: "", stderr: "",
  durationMs: 1, status: "success", repeatCount: 1,
};

describe("command suppression matching", () => {
  it("requires all populated conditions and matches text case-insensitively", () => {
    expect(commandMatchesSuppression(command, { id: "r", enabled: true, source: "monitor", hostId: "host-1", operationKind: "MONITOR.SAMPLE", contains: "proc/stat" })).toBe(true);
    expect(commandMatchesSuppression(command, { id: "r", enabled: true, source: "terminal", operationKind: "monitor.sample" })).toBe(false);
    expect(commandMatchesSuppression(command, { id: "r", enabled: false, source: "monitor" })).toBe(false);
  });
});
