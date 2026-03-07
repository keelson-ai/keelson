# OpenClaw → Keelson Adoption Plan

What to take from [OpenClaw](https://github.com/openclaw/openclaw) (a multi-channel AI assistant platform) and adapt for Keelson (an AI agent security scanner).

---

## 1. Plugin SDK with Subpath Exports

**OpenClaw pattern:** Plugins are npm packages that register via a typed API. Each plugin gets its own SDK subpath export (`openclaw/plugin-sdk/telegram`).

**Keelson adoption:** Create a `keelson.plugin` SDK so third parties can write custom adapters, detection rules, and attack packs without forking.

```python
# keelson-plugin-my-adapter/plugin.py
from keelson.plugin import KeelsonPlugin, register_adapter

class MyPlugin(KeelsonPlugin):
    id = "my-custom-target"

    def register(self, api):
        api.register_adapter("my-target", MyCustomAdapter)
        api.register_attack_pack("my-attacks", Path("./attacks"))
```

**What to build:**
- `src/keelson/plugin/sdk.py` — Plugin base class + registration API
- `src/keelson/plugin/discovery.py` — Discover plugins via entry points (`[project.entry-points."keelson.plugins"]`)
- Extension points: adapters, attack packs, detection rules, report formats

**Priority: High** — This is the biggest architectural gap. OpenClaw scales to 27 channels because of this.

---

## 2. Hook/Event System for Scanner Pipeline

**OpenClaw pattern:** 20+ hook events (`before-agent-start`, `chat-before-invoke`, `message-outbound`, etc.) with sync/async handlers. Hooks can modify, block, or augment behavior.

**Keelson adoption:** Add scanner lifecycle hooks so users can inject custom logic without modifying core.

```python
# Hook events for the scanning pipeline
@keelson.hook("before-attack")      # Modify prompts, skip attacks dynamically
@keelson.hook("after-response")     # Custom detection logic, logging
@keelson.hook("before-verdict")     # Override/augment verdicts
@keelson.hook("after-finding")      # Real-time alerting (Slack, PagerDuty)
@keelson.hook("scan-complete")      # Post-scan actions (upload, notify)
```

**What to build:**
- `src/keelson/core/hooks.py` — Hook registry with typed events
- Integration in `scanner.py` and `engine.py` at key pipeline stages
- Plugin API method: `api.register_hook("after-finding", my_handler)`

**Priority: High** — Enables real-time alerting, custom detection, and CI/CD integrations without code changes.

---

## 3. Structured Subsystem Logging

**OpenClaw pattern:** Hierarchical loggers namespaced by subsystem (`channels/discord`, `gateway`, `agents`). Per-subsystem filtering via env var.

**Keelson adoption:** Replace scattered `rich.Console` prints with structured logging.

```python
from keelson.logging import get_logger

log = get_logger("scanner/engine")
log.info("attack_started", template_id="GA-001", target="https://...")
log.warn("rate_limited", retry_after=5)
log.error("adapter_failed", adapter="langgraph", error=str(e))
```

**What to build:**
- `src/keelson/logging.py` — Subsystem logger factory
- JSON output mode for CI/service (`KEELSON_LOG_FORMAT=json`)
- Human-readable mode for CLI (colored, with Rich)
- Per-subsystem filtering (`KEELSON_LOG_SUBSYSTEM=scanner/*`)
- Auto-redaction of API keys and secrets in logs

**Priority: Medium** — Improves debuggability significantly, especially for service mode.

---

## 4. Configuration File Support

**OpenClaw pattern:** JSON5 config file (`~/.openclaw/openclaw.json`) with modular sections, Zod validation, and migrations.

**Keelson adoption:** Support a `keelson.yaml` config file for persistent scan profiles.

```yaml
# keelson.yaml or ~/.keelson/config.yaml
profiles:
  production:
    url: https://api.example.com/v1/chat/completions
    api_key: ${OPENAI_API_KEY}  # env var interpolation
    adapter: openai
    model: gpt-4
    categories: [goal-adherence, tool-safety]
    delay: 2.0

  staging:
    url: https://staging.example.com/v1/chat/completions
    adapter: langgraph
    assistant_id: docs_agent

defaults:
  format: markdown
  fail_on_vuln: true
  debug: false
```

**Usage:** `keelson scan --profile production` instead of 10 CLI flags.

**What to build:**
- `src/keelson/config.py` — YAML config loader with env var interpolation
- Profile selection in CLI: `--profile` flag
- Config validation with Pydantic or dataclass schemas
- `keelson config init` command to generate starter config

**Priority: Medium** — Reduces CLI verbosity for repeated scans.

---

## 5. Adapter Interface Expansion (OpenClaw's Channel Adapter Pattern)

**OpenClaw pattern:** Each channel implements multiple sub-adapters: `setup`, `config`, `auth`, `messaging`, `outbound`, `security`, `heartbeat`, `threading`.

**Keelson adoption:** Expand `BaseAdapter` beyond just `send_messages` to support richer target interaction.

```python
class BaseAdapter(ABC):
    # Required
    async def send_messages(self, messages, model) -> tuple[str, int]: ...
    async def close(self) -> None: ...

    # Optional capabilities (adapters override what they support)
    async def health_check(self) -> bool: ...
    async def list_tools(self) -> list[dict] | None: ...
    async def get_system_prompt(self) -> str | None: ...
    async def list_sessions(self) -> list[str] | None: ...
    async def new_session(self) -> str | None: ...

    @property
    def capabilities(self) -> set[str]:
        """Return supported capabilities for smart attack filtering."""
        return {"chat"}  # base only supports chat
```

**What to build:**
- Expand `BaseAdapter` with optional capability methods
- Auto-skip attacks that require capabilities the adapter doesn't support
- Adapter capability reporting in scan reports

**Priority: Low** — Current adapter interface works, but this enables smarter attack selection.

---

## 6. Markdown-Based Skill/Attack Distribution

**OpenClaw pattern:** Skills are pure markdown (`SKILL.md`) with YAML frontmatter for metadata. No compilation needed.

**Keelson adoption:** We already use markdown playbooks! But adopt the distribution model:

```yaml
# attacks/goal-adherence/PACK.yaml
name: goal-adherence
version: 1.2.0
author: keelson-team
description: OWASP LLM01 prompt injection attacks
requires:
  keelson: ">=0.4.0"
attacks:
  - GA-001.md
  - GA-002.md
  # ...
```

**What to build:**
- `PACK.yaml` manifest per attack category for versioning
- `keelson pack install <url/path>` — Install third-party attack packs
- `keelson pack list` — Show installed packs
- Attack pack discovery from PyPI or GitHub

**Priority: Low** — Future extensibility. Current bundled playbooks work fine for now.

---

## 7. Web Dashboard (Control UI)

**OpenClaw pattern:** Lit-based web dashboard with session management, channel status, agent routing, model selection.

**Keelson adoption:** Build a scan dashboard on top of the existing FastAPI service skeleton.

**Endpoints needed:**
```
GET  /api/scans              — List scans
GET  /api/scans/:id          — Scan detail + findings
POST /api/scans              — Submit new scan
GET  /api/scans/:id/report   — Download report
GET  /api/attacks             — List available attacks
GET  /api/health              — Health check (exists)
```

**Dashboard views:**
- Scan history with vuln/safe/inconclusive counts
- Finding detail with prompt/response/reasoning
- Trend charts (vuln rate over time)
- Attack coverage matrix

**What to build:**
- REST endpoints in `src/keelson_service/routers/`
- Static HTML+JS dashboard (or React/Lit SPA)
- WebSocket for live scan progress streaming

**Priority: Medium** — The FastAPI skeleton exists. REST endpoints are quick wins. Full dashboard is larger effort.

---

## 8. Doctor/Diagnostics Command

**OpenClaw pattern:** `openclaw doctor` validates config, auth, model reachability, dependencies.

**Keelson adoption:** `keelson doctor` for pre-scan validation.

```
$ keelson doctor --target https://api.example.com/v1/chat/completions
✓ Python 3.11+
✓ keelson v0.4.0
✓ 105 attack playbooks loaded
✓ Target reachable (200 OK, 142ms)
✓ Auth valid (model: gpt-4)
✗ Optional: crewai not installed (keelson[crewai])
✗ Optional: langchain not installed (keelson[langchain])
```

**What to build:**
- `keelson doctor` command in CLI
- Check: Python version, package version, playbook count, target reachability, adapter health
- Optional dependency checks

**Priority: Low** — Nice UX improvement, not critical.

---

## 9. Pairing/Auth Allowlist for Multi-User Service Mode

**OpenClaw pattern:** Unknown senders get a pairing code. Operator approves once. Simple allowlist.

**Keelson adoption:** For the service mode, add API key auth + role-based access.

**What to build:**
- API key middleware for FastAPI endpoints
- `keelson apikey create/revoke` commands
- Rate limiting per API key
- Audit log of scan submissions

**Priority: Low** — Only needed when service mode is used in production.

---

## Implementation Priority Order

| # | Feature | Priority | Effort | Impact |
|---|---------|----------|--------|--------|
| 1 | Plugin SDK + discovery | High | Large | Enables ecosystem |
| 2 | Hook/event system | High | Medium | Enables alerting + custom detection |
| 3 | Structured logging | Medium | Small | Better debugging |
| 4 | Config file support | Medium | Small | Better UX |
| 5 | Web dashboard REST API | Medium | Medium | Visual scan management |
| 6 | Adapter capabilities | Low | Small | Smarter attack selection |
| 7 | Attack pack distribution | Low | Medium | Community contributions |
| 8 | Doctor command | Low | Small | Pre-scan validation |
| 9 | Service auth | Low | Small | Multi-user service |

---

## What NOT to Adopt

- **Multi-channel messaging** — Keelson is a scanner, not a messaging platform
- **Voice/TTS/STT** — Not relevant to security scanning
- **Canvas/A2UI** — Agent-driven UI not needed
- **Session routing** — Keelson already handles multi-target via adapter instances
- **Native apps (macOS/iOS/Android)** — CLI + service is the right model
- **JSON5 config** — YAML is better for the Python ecosystem
- **pnpm/TypeScript** — Keelson is Python, keep it Python
