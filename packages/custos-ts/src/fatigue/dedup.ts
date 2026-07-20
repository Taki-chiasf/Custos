// Fatigue dedup cache — IR_CONTRACT  ;  .

// Per D17 the TS `@custos/core` ships the **deterministic subset**: A8
// batched summarization routes via the  gRPC sidecar, so there is no
// `BatchWindow` in the in-process TS surface.

// State is single-process: a `Map` guarded by a single-thread JS event
// loop (JS is single-threaded per isolant; no lock needed). The cache
// key is `(user_id, tool, _args_hash(args))` and the deadline is a
// monotonic-clock value (`performance.now` converted to seconds to
// match the Python `time.monotonic` unit — IR_CONTRACT).

import { argsHash } from "../canonicalize.ts";
import type { Invocation, SubjectContext } from "../schema.ts";
import type { Decision } from "../decision.ts";
import type { FatigueLayer } from "./base.ts";

interface CacheEntry {
  decision: Decision;
  expiresAt: number; // monotonic seconds
}

export interface FatigueDecision {
  decision: Decision | "defer";
  reasoning: string;
  cacheable: boolean;
}

export const OK: FatigueDecision = { decision: "defer", reasoning: "", cacheable: false };
// Sentinel: "no fatigue opinion, proceed with the pipeline."

export class InMemoryFatigueLayer implements FatigueLayer {
  private cache = new Map<string, CacheEntry>();
  dedupTtlS: number;

  constructor(opts: { dedupTtlS?: number } = {}) {
    this.dedupTtlS = opts.dedupTtlS ?? 300;
  }

  lookup(inv: Invocation): FatigueDecision {
    const now = monotonicSeconds();
    const key = cacheKey(inv.context, inv.tool, inv.args);
    const e = this.cache.get(key);
    if (e === undefined) return OK;
    if (e.expiresAt <= now) {
      this.cache.delete(key);
      return OK;
    }
    return { decision: e.decision, reasoning: "dedup", cacheable: false };
  }

  afterPrompt(inv: Invocation, decision: Decision, ttlS: number | null): void {
    if (decision === "defer") return; // don't cache DEFER
    const key = cacheKey(inv.context, inv.tool, inv.args);
    const ttl = ttlS ?? this.dedupTtlS;
    this.cache.set(key, {
      decision,
      expiresAt: monotonicSeconds() + ttl,
    });
  }

  clear(): void {
    this.cache.clear();
  }
}

function cacheKey(
  ctx: SubjectContext,
  tool: string,
  args: Record<string, unknown>
): string {
  return `${ctx.user_id}|${tool}|${argsHash(args)}`;
}

// Per IR_CONTRACT : TS uses `performance.now / 1000` to get seconds
// (matching Python's `time.monotonic` unit). In Node this is
// `process.hrtime.bigint / 1e9` for monotonic guarantee but
// `performance.now` is sufficient and matches browser too.
function monotonicSeconds(): number {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const perf = (globalThis as { performance?: { now(): number } }).performance;
  if (perf) return perf.now() / 1000;
  return Date.now() / 1000;
}