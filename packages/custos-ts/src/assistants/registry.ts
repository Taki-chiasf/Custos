// Assistant / Inspector registry — IR_CONTRACT  (H11).

// Name-keyed registries that resolve `assist:<name>` and `inspect:<name>`
// policy actions to the correct assistant / inspector instance. An
// unresolved name fails closed — the gateway returns a safe `deny`.
// The air-gapped profile (`localOnly`) refuses to register any entity
// with `exfiltratesArgs=true` upfront (C4 regression, council 2026-07-22).

import type { Assistant } from "./base.ts";

export class AssistantRegistry {
  private byName: Map<string, Assistant> = new Map();
  private localOnly: boolean;

  constructor(assistants?: Assistant[], localOnly = false) {
    this.localOnly = localOnly;
    if (assistants) {
      for (const a of assistants) this.register(a);
    }
  }

  register(assistant: Assistant): void {
    if (this.localOnly && assistant.exfiltratesArgs) {
      throw new Error(
        `air-gapped profile (localOnly) refuses to register ` +
        `exfiltrating assistant ${assistant.name} (exfiltratesArgs=true)`
      );
    }
    this.byName.set(assistant.name, assistant);
  }

  get(name: string): Assistant | undefined {
    return this.byName.get(name);
  }

  get default(): Assistant | undefined {
    for (const a of this.byName.values()) return a;
    return undefined;
  }

  get size(): number {
    return this.byName.size;
  }
}
