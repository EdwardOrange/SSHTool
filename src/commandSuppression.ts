import type { CommandRecord, CommandSuppressionRule } from "./types";

/** Returns true when every condition in an enabled suppression rule matches. */
export function commandMatchesSuppression(command: CommandRecord, rule: CommandSuppressionRule): boolean {
  if (!rule.enabled) return false;
  const contains = rule.contains?.trim().toLocaleLowerCase();
  return (!rule.source || rule.source === command.source)
    && (!rule.hostId || rule.hostId === command.hostId)
    && (!rule.operationKind || rule.operationKind.toLocaleLowerCase() === (command.operationKind || "").toLocaleLowerCase())
    && (!contains || command.command.toLocaleLowerCase().includes(contains));
}
