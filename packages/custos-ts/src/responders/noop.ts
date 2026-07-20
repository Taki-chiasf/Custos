// Noop responder — . Logs the prompt and auto-denies (for tests /
// headless). Mirrors `custos.responders.noop.NoopResponder`.

import type { Responder } from "./base.ts";
import type { PromptRequest, PromptResponse } from "../schema.ts";

export class NoopResponder implements Responder {
  readonly name = "noop";

  async prompt(_req: PromptRequest): Promise<PromptResponse> {
    // Log + auto-deny. : a responder down-fail (incl. `noop` here)
    // is treated as a safe `deny` — the  floor holds.
    return {
      choice: "deny",
      ttl: null,
      signature: null,
      nonce: null,
      approver: null,
    };
  }
}