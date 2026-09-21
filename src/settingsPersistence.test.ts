import { describe, expect, it, vi } from "vitest";
import { defaultSettings } from "./api";
import { createSettingsPersistence } from "./settingsPersistence";
import type { AppSettings } from "./types";

const deferred = <T,>() => {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

function setup(initial = defaultSettings()) {
  let current = initial;
  const update = vi.fn(async (value: AppSettings) => value);
  const reset = vi.fn(async () => defaultSettings());
  const persistence = createSettingsPersistence({ get: () => current, set: (value) => { current = value; }, update, reset });
  return { persistence, update, reset, current: () => current };
}

describe("settings persistence", () => {
  it("rolls consecutive failed writes back to the last saved settings", async () => {
    const { persistence, update, current } = setup();
    update.mockRejectedValue(new Error("disk full"));
    const first = persistence.update({ theme: "dark" });
    const second = persistence.update({ locale: "en" });
    expect(current()).toMatchObject({ theme: "dark", locale: "en" });
    await Promise.allSettled([first, second]);
    expect(current()).toEqual(defaultSettings());
    expect(update.mock.calls[1][0]).toMatchObject({ theme: "system", locale: "en" });
  });

  it("keeps later edits when reset completes and writes them on the reset defaults", async () => {
    const { persistence, reset, update, current } = setup({ ...defaultSettings(), terminalFontSize: 20 });
    const response = deferred<AppSettings>();
    reset.mockReturnValue(response.promise);
    const resetting = persistence.reset();
    const editing = persistence.update({ locale: "en" });
    response.resolve(defaultSettings());
    await Promise.all([resetting, editing]);
    expect(current()).toMatchObject({ locale: "en", terminalFontSize: 13 });
    expect(update).toHaveBeenCalledWith({ ...defaultSettings(), locale: "en" });
  });

  it("serializes independent callers and retains backend normalization", async () => {
    const { persistence, update, current } = setup();
    const response = deferred<AppSettings>();
    update.mockReturnValueOnce(response.promise);
    const toolbarWrite = persistence.update({ theme: "dark" });
    const dialogWrite = persistence.update({ terminalFontSize: 18 });
    await Promise.resolve(); await Promise.resolve();
    expect(update).toHaveBeenCalledTimes(1);
    response.resolve({ ...defaultSettings(), theme: "dark", version: 3 });
    await Promise.all([toolbarWrite, dialogWrite]);
    expect(current()).toMatchObject({ theme: "dark", terminalFontSize: 18, version: 3 });
    expect(update.mock.calls[1][0].version).toBe(3);
  });
});
