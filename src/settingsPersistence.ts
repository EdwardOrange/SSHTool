import { api } from "./api";
import { useAppStore } from "./store";
import type { AppSettings } from "./types";

interface SettingsBackend {
  get: () => AppSettings | undefined;
  set: (settings: AppSettings) => void;
  update: (settings: AppSettings) => Promise<AppSettings>;
  reset: () => Promise<AppSettings>;
}

// All settings entry points share this queue. Rebase pending patches on the last
// successful response so failed writes and resets cannot resurrect stale values.
export function createSettingsPersistence(backend: SettingsBackend) {
  let committed: AppSettings | undefined;
  let chain: Promise<unknown> = Promise.resolve();
  const pending: { patch?: Partial<AppSettings> }[] = [];
  const publish = () => {
    if (committed) backend.set(pending.reduce((value, operation) => ({ ...value, ...operation.patch }), committed));
  };
  const enqueue = (patch?: Partial<AppSettings>) => {
    if (pending.length === 0) committed = backend.get();
    if (!committed) return Promise.reject(new Error("设置尚未加载"));
    const operation = { patch };
    pending.push(operation);
    publish();
    const result = chain.catch(() => undefined).then(async () => {
      try {
        committed = patch ? await backend.update({ ...committed!, ...patch }) : await backend.reset();
        return committed;
      } finally {
        pending.splice(pending.indexOf(operation), 1);
        publish();
      }
    });
    chain = result;
    return result;
  };
  return { update: (patch: Partial<AppSettings>) => enqueue(patch), reset: () => enqueue() };
}

export const settingsPersistence = createSettingsPersistence({
  get: () => useAppStore.getState().settings,
  set: (settings) => useAppStore.getState().setSettings(settings),
  update: (settings) => api.settingsUpdate(settings),
  reset: () => api.settingsReset(),
});
