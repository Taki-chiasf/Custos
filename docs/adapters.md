# Adapters

Framework adapters wrap each tool on an existing agent framework so every
tool call goes through `Gateway.decide` first. Each is an optional extra
(— the runtime stays dep-free). Each follows the
vendor-imports-inside-function-bodies invariant; each ships a
`test_import_custos_does_not_import_<vendor>` regression test.

## Catalog

| Adapter | Extra | API | Notes |
|---|---|---|---|
| LangChain | `custos-middleware[langchain]` | `wrap_langchain_tools` | Sync; preserves name/description/args_schema. |
| MCP in-process | `custos-middleware[mcp]` | `gated_tool` decorator + `wrap_mcp_tools` | Native-async-first; `@mcp.tool` re-registration via `add_tool`. Filename `mcp_` (Anthropic-shadowing rule). |
| OpenAI Agents SDK | `custos-middleware[openai-agents]` | `gated_function_tool` + `wrap_openai_agent_tools` | Native-async-first; SDK's failure-wrapper preserved so DENY surfaces as a model-visible tool-error string. |
| Anthropic messages-API | `custos-middleware[anthropic]` | `gated_anthropic_tool` + `wrap_anthropic_tool_handlers` | Handler-side gating; the LLM owns tool args. Filename `anthropic_`. |
| AutoGen | `custos-middleware[autogen]` | `gated_autogen_tool` + `wrap_autogen_tools` |  carry-forward; native-async-first. |
| Google ADK (Gemini) | `custos-middleware[google-adk]` | `gated_adk_tool` + `wrap_adk_tools` |  carry-forward; native-async-first. |
| LlamaIndex | `custos-middleware[llamaindex]` | `gated_function_tool` (LlamaIndex `FunctionTool`) |  carry-forward; handler-side gating. |

All follow the convention: `deny`/`defer` raises
`custos.exceptions.PermissionDenied`; the host decides how to surface it
to the LLM.

## Async / sync

`AsyncGateway` is the recommended pairing for any adapter that is natively
async (MCP, OpenAI Agents, AutoGen, Google ADK). Sync impls are bridged
through `asyncio.to_thread` so the existing sync `Gateway` + its 350-test
suite keep working unchanged .

## Common surface

```python
from custos import AsyncGateway, Policy
from custos.integrations.mcp_ import gated_tool

gw = AsyncGateway(policy=Policy.from_dict({...}))
mcp = FastMCP("my-server")

@gated_tool(mcp, gw, risk_tier=2, side_effects=frozenset({SideEffect.WRITE}))
def fs_write(path: str, content: str) -> str:
    return f"wrote {len(content)} bytes to {path}"
```

The  floor is enforced at the boundary — a policy `deny` is final; an
assistant `allow` never relaxes it. See the [`assistants`](assistants.md)
catalog.