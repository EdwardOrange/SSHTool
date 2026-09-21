// This is only a startup/UI cache. The local database remains authoritative,
// so an unavailable WebView storage area must not prevent using the app.
export function readLocalPreference(key: string): string | null {
  try { return window.localStorage.getItem(key); } catch { return null; }
}

export function writeLocalPreference(key: string, value: string | null): void {
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch { /* Keep using the database-backed settings. */ }
}
