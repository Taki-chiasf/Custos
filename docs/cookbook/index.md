# Policy cookbook

Five runnable policy recipes that cover the common 90% of agent permission
needs . Each recipe is a complete YAML policy plus the
minimum wiring needed to make it work end-to-end. Recipes compose; you can
mix and match overlays from several recipes in the same policy file.

| Recipe | Posture | Notes |
|---|---|---|
| [Read-only auto-allow](read-allow.md) | Permissive read, every write prompted | The default-allow-read layer most agents start from. |
| [Network-egress prompt](network-egress-prompt.md) | Anything that crosses the network asks first | `SideEffect.NETWORK`-aware. |
| [Payment quorum (separation of duties)](payment-quorum.md) | Two distinct approver roles must say yes | Provides the  quorum demo end-to-end. |
| [Learned-policy opt-out](learned-policy-opt-out.md) | Opt A10 into read-only mode |  A10-poisoning mitigation; safe default for the assistant. |
| [Air-gapped profile](air-gapped-profile.md) | Refuse LLM-backed assistants entirely |  air-gapped deployments. |

Canonical policy schema lives in [`custos/policy/schema.py`](https://github.com/Taki-chiasf/Custos/blob/main/src/custos/policy/schema.py)
(`PolicyFile`, `PolicyOverlaySpec`, `PolicyRuleSpec`) — these recipes are
plain YAML instances of that schema. A full match-criteria reference is in
the [Quickstart](../quickstart.md#policy-file-yaml) and [](https://github.com/Taki-chiasf/Custos).

The [threat model](../THREAT_MODEL.md) maps each recipe's mitigations to
 bullets via the STRIDE table.