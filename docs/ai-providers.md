# AI providers

`openre-ai` abstracts model access behind a `ModelProvider` trait (`crates/openre-ai/src/providers.rs`). Providers register in a `ProviderRegistry`; the `AiService` and `ModelRouter` select among them per request. Every provider reports `ProviderCapabilities` (chat, completion, embedding, tools, vision, audio, json_mode, structured_output), a context-window size, and streaming/tool support; the router uses these to filter candidates.

## Local providers

### llama.cpp (`LlamaCppProvider`)

- Backed by `llama-cpp-2`; loads a GGUF model from a path.
- Provider id: `llama.cpp`.
- Capabilities: chat, completion, embedding, streaming. No tool calls, no vision, no JSON mode.
- Config (`[ai.llama_cpp]`): `gpu_layers` (default `0`, CPU-only), `context_size` (default `4096`), `use_mlock` (default `false`), `use_mmap` (default `true`). Models load with mmap; mlock is opt-in.
- Chat formatting: a plain `system`/`user`/`assistant` template compiled per message role. No model-specific chat template is applied, so pick a model that tolerates this or set prompts accordingly.

### ONNX Runtime (`OnnxProvider`)

- Backed by `ort` (load-dynamic feature) plus a HuggingFace `tokenizers` tokenizer from `tokenizer_path`.
- Provider id: `onnx`.
- Capabilities: chat, completion, streaming. `embedding` is advertised via config but `embed()` currently returns "Embeddings not supported". No tools, no vision.
- Decoding is greedy (argmax over logits) regardless of requested temperature.
- Config (`[ai.onnx]`): `threads` (default `4`, must be non-zero), `providers` (execution providers, default `["cpu"]`, with `cuda` and `tensorrt` recognized as values).

## Remote providers (`RemoteProvider`)

One implementation covers every OpenAI-compatible HTTP API. It posts to `<base_url>/chat/completions`, `<base_url>/embeddings`, and health-checks `<base_url>/models`, with Bearer auth when an API key is set, SSE streaming, and tool-call delta parsing. Constructors:

| Constructor | Base URL | Default model | Vision | Context |
| --- | --- | --- | --- | --- |
| `openai` | `https://api.openai.com/v1` | `gpt-4` | yes | 128,000 |
| `anthropic` | `https://api.anthropic.com/v1` | `claude-3-opus-20240229` | yes | 200,000 |
| `vllm` | your server URL | `default` | no | 4,096 |
| `custom` | your endpoint URL | `custom` | no | 4,096 |

The Anthropic constructor uses the OpenAI-compatible shape at `api.anthropic.com/v1`. `RemoteConfig` (`[ai]`-side) carries `base_url`, `api_key`, `model`, `timeout_secs` (default 30, 60 for anthropic/vllm), `max_retries` (default 3), `supports_vision`, `max_context_tokens`, and `embedding_model`.

### Ollama

There is no dedicated Ollama provider in `openre-ai`. Ollama servers speak the OpenAI-compatible API, so they are reachable through a `RemoteProvider` pointed at the local endpoint (the `vllm` registration below is exactly that: a base URL plus optional API key).

## Registration

`AiService::new` populates the registry from config + environment (`register_providers` in `service.rs`). Today only remote providers are registered; the ONNX and llama.cpp registration blocks are present but commented out in `service.rs`, so the local provider implementations are library code waiting on a config surface. A remote provider registers when its name is listed in `ai.allowed_remote_providers` **and** its credentials are in the environment:

| `allowed_remote_providers` entry | Required env | Optional env |
| --- | --- | --- |
| `openai` | `OPENAI_API_KEY` | none |
| `anthropic` | `ANTHROPIC_API_KEY` | none |
| `vllm` | `VLLM_BASE_URL` | `VLLM_API_KEY` |

Missing env vars are logged and skipped, not fatal. `ai.allow_remote` and `ai.models_dir` exist in `AiConfig` but are not consumed by `openre-ai` code yet.

## Routing

`ModelRouter::select_provider` filters registry entries by the request: tool support, streaming support, estimated token count (content length / 4 + max_tokens) against `max_context_tokens`, and privacy (when `ai.privacy.local_only_mode` is true, only providers whose type is `onnx` or `llama.cpp` qualify).

Two strategies, chosen by `ai.local_first` (default `true`):

- **local-first**: first qualifying local provider; remote only if `local_only_mode` is off.
- **cost-optimized**: local first (free), otherwise the remote with the lowest estimated per-1k-token cost: OpenAI `0.03`, Anthropic `0.015`, vLLM `0.001` (self-hosted), other `0.01`.

Per-provider usage stats (requests, tokens, latency, success/failure counts) are recorded on every call.

## Configuration

`AiConfig` (`crates/openre-config/src/config.rs`), TOML section `[ai]`:

```toml
[ai]
enabled = true
local_first = true
allow_remote = false            # declared in config; see Registration for the gate actually enforced
allowed_remote_providers = []   # allowlist that drives provider registration
models_dir = "./models"

[ai.onnx]
threads = 4
providers = ["cpu"]

[ai.llama_cpp]
gpu_layers = 0
context_size = 4096
use_mlock = false
use_mmap = true

[ai.cache]
enabled = true
memory_max_entries = 1000
disk_max_size_mb = 100
ttl_secs = 3600

[ai.privacy]
redact_sensitive = true
sensitive_patterns = [
  "(?i)(password|secret|key|token|api_key)",
  "[A-Za-z0-9+/]{40,}",
  "[0-9a-f]{32,}",
]
custom_redaction_patterns = []
max_context_tokens = 8192
audit_log = true
local_only_mode = false
allow_restricted_data = false
```

Defaults matter for air-gapped use: with `allowed_remote_providers = []` nothing registers and no request can leave the machine, `local_only_mode = true` additionally restricts routing to local providers once they are registered, and `redact_sensitive = true` scrubs credentials from outgoing prompts.

## Supporting services

- **Cache** (`cache.rs`): two-level response cache keyed by SHA-256 of the request. In-memory LRU-capped by `memory_max_entries`, disk-backed under `data/cache/ai_cache.json` capped by `disk_max_size_mb`, entries expiring after `ttl_secs`.
- **Privacy** (`privacy.rs`): `PrivacyController` rewrites messages and tool parameters through the configured redaction patterns (built-ins plus `custom_redaction_patterns`) and keeps an in-memory audit log of redactions.
- **Prompt compiler** (`prompt_compiler.rs`): named prompt templates with few-shot example sets.
- **Tools** (`tools.rs`): `AiTool` trait plus project/object/global store traits exposing functions, basic blocks, instructions, strings, symbols, xrefs, and search to tool-calling providers.
- **Grounded service** (`grounded.rs`): evidence-grounded responses. Every claim must cite an evidence ID in `[Evidence: <id>]` form, checked against the finding's evidence set.

## CLI surface

`openre ai` subcommands (see [cli.md](cli.md)): `chat`, `analyze`, `explain`, `remediate`, `correlate`, `providers`, `test`. The commands build an `AiService` from the loaded `[ai]` config on first use (`Context::ai_client`), so `ai providers` lists whatever `Registration` above produced, with per-provider health status, and `ai test` health-checks registered providers filtered by `--provider`/`--model`. The library entry points behind them are `AiService::complete`, `stream`, `execute_template`, and `execute_with_tools`.
