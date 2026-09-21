// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import { copyText } from "./clipboard";

afterEach(() => { vi.unstubAllGlobals(); document.body.replaceChildren(); });

describe("clipboard fallback", () => {
  it("does not report success when both clipboard mechanisms fail", async () => {
    vi.stubGlobal("navigator", { clipboard: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    const button = document.createElement("button"); document.body.append(button); button.focus();
    Object.defineProperty(document, "execCommand", { configurable: true, value: vi.fn(() => false) });
    await expect(copyText("record")).rejects.toThrow("复制失败");
    expect(document.querySelector("textarea")).toBeNull();
    expect(document.activeElement).toBe(button);
  });

  it("cleans up the fallback when the command throws", async () => {
    vi.stubGlobal("navigator", {});
    Object.defineProperty(document, "execCommand", { configurable: true, value: vi.fn(() => { throw new Error("unsupported"); }) });
    await expect(copyText("record")).rejects.toThrow("复制失败");
    expect(document.querySelector("textarea")).toBeNull();
  });

  it("copies the requested value and restores focus when fallback succeeds", async () => {
    vi.stubGlobal("navigator", {});
    const button = document.createElement("button"); document.body.append(button); button.focus();
    Object.defineProperty(document, "execCommand", { configurable: true, value: vi.fn(() => {
      expect((document.activeElement as HTMLTextAreaElement).value).toBe("准确的记录"); return true;
    }) });
    await expect(copyText("准确的记录")).resolves.toBeUndefined();
    expect(document.activeElement).toBe(button);
    expect(document.querySelector("textarea")).toBeNull();
  });
});
