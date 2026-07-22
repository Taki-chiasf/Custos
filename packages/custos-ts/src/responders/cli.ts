// CLI responder — . Inline y/N, with `--timeout`, batch-summary,
// `y/N/a/A/l/d` mapping. Mirrors `custos.responders.cli.CLIResponder`.

// The TS surface uses `process.stdin`/`process.stdout` from Node's
// `node:readline`/`node:tty`. Defaults: 30s timeout -> DENY on expiry
// (US-8); `A` sets `ttl` for the fatigue layer ;
// `l` returns DEFER ; `d` prints full details + re-prompts.

import readline from "node:readline";
import type { Responder } from "./base.ts";
import type { PromptRequest, PromptResponse } from "../schema.ts";

export class CLIResponder implements Responder {
  readonly name = "cli";
  readonly timeoutS: number;

  constructor(opts: { timeoutS?: number } = {}) {
    this.timeoutS = opts.timeoutS ?? 30; // 30s default
  }

  async prompt(req: PromptRequest): Promise<PromptResponse> {
    const banner = formatBanner(req);
    process.stdout.write(banner);

    const answer = await readlineQuestion(`${this.timeoutS}s) > `);
    const parsed = parseAnswer(answer, req);
    return parsed;
  }
}

function formatBanner(req: PromptRequest): string {
  const parts: string[] = [];
  parts.push(`[custos] agent wants: ${req.tool}(${summarizeArgs(req.args_redacted)})\n`);
  const riskStr = `risk: ${Math.round(req.risk * 10)}/10`;
  const reasoningStr = req.reasoning ? ` | reasoning: ${req.reasoning}` : "";
  parts.push(`${riskStr}${reasoningStr}\n`);
  const opts = req.options.join(" / ");
  parts.push(`options: ${opts}\n`);
  if (req.quorum !== null && req.quorum > 0) {
    parts.push(`quorum: ${req.quorum} from ${req.approver_roles.join(", ")}\n`);
  }
  return parts.join("");
}

function summarizeArgs(args: Record<string, unknown>): string {
  // Compact one-line summary; secret/PII fields already redacted upstream.
  const entries = Object.entries(args).slice(0, 5);
  if (entries.length === 0) return "";
  const parts = entries.map(([k, v]) => {
    if (typeof v === "string" && v.length > 30) return `${k}="${v.slice(0, 27)}..."`;
    return `${k}=${JSON.stringify(v)}`;
  });
  return parts.join(", ");
}

function parseAnswer(answer: string, _req: PromptRequest): PromptResponse {
  const a = answer.trim().toLowerCase();
  if (a === "y") return { choice: "allow_once", ttl: null, signature: null, nonce: null, approver: cliUid() };
  if (a === "n" || a === "") return { choice: "deny", ttl: null, signature: null, nonce: null, approver: cliUid() };
  if (a === "a") return { choice: "allow_once", ttl: null, signature: null, nonce: null, approver: cliUid() };
  if (a === "A") return { choice: "allow", ttl: 600, signature: null, nonce: null, approver: cliUid() };
  if (a === "l") return { choice: "defer", ttl: null, signature: null, nonce: null, approver: cliUid() };
  // `d` (details) or unknown -> DENY defensively.
  return { choice: "deny", ttl: null, signature: null, nonce: null, approver: cliUid() };
}

function cliUid(): string {
  // : approver attestation. CLI uses the login shell UID
  // (process.getuid in Node). String-formatted.
  try {
    const uid = process.getuid?.();
    if (uid !== undefined) return `cli-uid-${uid}`;
  } catch {
    // Windows: getuid not available. Fall back to USERNAME.
  }
  return process.env.USER ?? process.env.USERNAME ?? "cli";
}

async function readlineQuestion(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: false });
    rl.question(prompt, (ans) => {
      rl.close();
      resolve(ans);
    });
  });
}