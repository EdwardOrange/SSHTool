import type { CommandRecord, StreamEnvelope } from "./types";

interface CommandHistoryBackend {
  subscribe: (onData: (event: StreamEnvelope<CommandRecord>) => void) => Promise<void>;
  query: () => Promise<CommandRecord[]>;
}

// Subscribe before taking the snapshot and merge events received while it is
// loading. A command can finish between querying history and opening a stream.
export async function loadCommandHistory(
  backend: CommandHistoryBackend,
  replace: (records: CommandRecord[]) => void,
  append: (record: CommandRecord) => void,
  alive: () => boolean,
) {
  let loaded = false;
  const buffered = new Map<string, CommandRecord>();
  await backend.subscribe((event) => {
    if (!alive()) return;
    if (loaded) append(event.payload);
    else {
      buffered.set(event.payload.id, event.payload);
      if (buffered.size > 2000) buffered.delete(buffered.keys().next().value!);
    }
  });
  if (!alive()) return;
  const records = await backend.query();
  if (!alive()) return;
  const merged = new Map(records.map((record) => [record.id, record]));
  for (const [id, record] of buffered) merged.set(id, record);
  replace([...merged.values()].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp)).slice(-2000));
  buffered.clear();
  loaded = true;
}
