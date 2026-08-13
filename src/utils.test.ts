import { describe, expect, it } from "vitest";
import { formatBytes, formatDuration, formatError } from "./utils";

describe("display formatters", () => {
  it("formats bytes and throughput", () => {
    expect(formatBytes(1_500_000)).toBe("1.5 MB");
    expect(formatBytes(2_000_000, true)).toBe("2.0 MB/s");
  });
  it("formats uptime", () => {
    expect(formatDuration(90_000)).toBe("1天 1小时");
  });
  it("formats structured IPC errors", () => {
    expect(formatError({ kind: "sudoRequired", message: "需要 sudo 密码" })).toBe("需要 sudo 密码");
    expect(formatError({ message: "端口被占用" })).toBe("端口被占用");
  });
});
