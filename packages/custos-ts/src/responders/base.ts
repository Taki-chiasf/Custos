// Responder Protocol — IR_CONTRACT  (Responder interface).

import type { PromptRequest, PromptResponse } from "../schema.ts";

export interface Responder {
  readonly name: string;
  prompt(req: PromptRequest): Promise<PromptResponse>;
}