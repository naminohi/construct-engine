# AGENTS.md — construct-engine

This file provides context for AI agents working in this repository.

---

## What is construct-engine?

`construct-engine` is the **integration layer** between `construct-core` (Rust crypto) and
non-iOS client applications (Desktop, TUI, Android). It wraps the I/O-free
`OrchestratorCore` from `construct-core` and adds:

- **Transport**: QUIC/H3 gRPC connection to the Construct server
- **ICE proxy**: obfs4/WebTunnel DPI evasion (via `construct-ice`)
- **P2P**: Direct QUIC peer-to-peer connections (STUN/ICE NAT traversal) — Tier 3 of the network model
- **Message-passing API**: `UiEvent` (client → engine) and `PlatformAction` (engine → client)
- **UniFFI bindings**: Swift/Kotlin bindings for iOS/Android (feature-gated)

iOS uses `construct-core` directly via UniFFI. All other platforms use `construct-engine`.

---

## Three-Tier Network Model

`construct-engine` implements a tiered connectivity model:

```
Tier 1 — Federated Servers (gRPC/H3/QUIC)
   Клиент ↔ construct-server
   Всегда используется когда сервер достижим

Tier 2 — Community Relay Nodes (ICE/obfs4/WebTunnel)
   Клиент ↔ construct-relay ↔ construct-server
   DPI evasion в цензурируемых регионах

Tier 3 — Full P2P (прямой QUIC через STUN/ICE)
   Клиент ↔ Клиент (сервер не участвует)
   Минимальная latency для Desktop/TUI/Android
```

### Target platforms per tier

| Tier | macOS Desktop | TUI | Linux Desktop | Android | iOS |
|------|:---:|:---:|:---:|:---:|:---:|
| Tier 1 (gRPC) | ✅ | ✅ | 🔮 | ✅ | ✅ |
| Tier 2 (ICE) | ✅ | ✅ | 🔮 | 🟡 | ✅ |
| Tier 3 (P2P QUIC) | ✅ | ✅ | 🔮 | 🟡 | ❌ |

iOS не использует engine для крипто-операций (прямой UniFFI-путь через `ConstructCore.xcframework`).
P2P на iOS затруднён ограничениями ОС (UDP нестабилен в фоне).

---

## Architecture

```
Client app (TUI / Desktop / Android)
    │
    ▼  UiEvent
ConstructEngine  ──────────────────────────────────────────
    │                                                       │
    ├── core_bridge.rs  → OrchestratorCore (construct-core) │ crypto + sessions
    ├── transport/      → gRPC over QUIC/H3                 │ server comms
    ├── p2p/            → P2PManager (WebRTC/ICE)           │ calls
    └── events.rs       → PlatformAction → callback         │
    │
    ▼  PlatformAction (via EngineCallback trait)
Client app handles result
```

### Key modules

| Module | File | Purpose |
|--------|------|---------|
| Engine | `src/engine.rs` | `ConstructEngine` main struct, event dispatch loop |
| Events | `src/events.rs` | `UiEvent` and `PlatformAction` enums — the full API surface |
| Core bridge | `src/core_bridge.rs` | Wraps `OrchestratorCore` from `construct-core` |
| Transport | `src/transport/` | gRPC channel, auth, messaging stream |
| P2P | `src/p2p/` | P2PManager, ICE candidates, STUN client, QUIC P2P connection |
| UniFFI | `src/construct_engine.udl` | Binding definitions for Swift/Kotlin |

### UiEvent → PlatformAction pattern

Every client action is a `UiEvent` sent to `ConstructEngine::dispatch()`.
The engine processes it and fires zero or more `PlatformAction`s via the `EngineCallback`.
This is the sole communication channel — no direct function calls into the engine.

Example session init flow:
```
UiEvent::InitSession { contact_id, bundle_json }
    → core_bridge: OrchestratorCore::init_session()
    → PlatformAction::SessionInitialised { contact_id }
  (or)
    → PlatformAction::SessionInitFailed { contact_id, error }
```

---

## Build

```bash
cargo build                        # default (no bindings)
cargo build --features ios         # with UniFFI Swift/Kotlin scaffolding
cargo test                         # all tests
cargo clippy                       # lint
```

Feature flags:
- `ios` — enables UniFFI scaffolding for Swift/Kotlin binding generation

---

## Key conventions

- Never call `OrchestratorCore` directly from client code — always go through `ConstructEngine::dispatch()`
- `UiEvent` and `PlatformAction` in `events.rs` are the public API — changing them is a breaking change for all clients
- `construct_engine.udl` is the UniFFI source of truth — update it when the public API changes
- Engine must reach `Ready` state (authenticated + PQ keys loaded) before crypto UiEvents are accepted

---
---

## Shared Construct Docs Workflow

These instructions apply to GitHub Copilot, Codex, OpenCode, and similar coding agents.

### Division of labour — read this first

| Role | Tool | Responsibility |
|------|------|----------------|
| **Coding agent** (you) | Copilot / Codex | Write code + drop raw session notes into `wiki/sessions/` and `wiki/decisions/`. That is all. |
| **Wiki pipeline** | `obsidian-llm-wiki-local` (olw) | Reads `raw/`, synthesizes concepts, creates/updates wiki articles, generates cross-links. |
| **Developer** | Human + Obsidian | Reviews wiki draft articles, approves/rejects. Curates `raw/`. |

**Your job is code.** olw handles article synthesis. Write plain-markdown session notes; let the pipeline do the rest.

### Shared knowledge base

- Vault: `~/Code/construct-docs`
- `raw/` — source corpus. Do **not** rewrite or reorganize.
- `wiki/` — canonical curated knowledge base. **Read** from here before architectural work.
- `wiki/.drafts/` — **reserved for olw**. Never write here manually.
- `wiki/sessions/` — where coding agents write session notes.
- `wiki/decisions/` — where coding agents write long-lived decision records.

### Where to save durable reasoning

After any session involving architectural changes, design decisions, API changes, or non-obvious implementation choices:

1. **Always** create or update `wiki/sessions/YYYY-MM-DD-<topic>.md`.
2. **Always** fill in `# Why` — reasoning, alternatives considered, why rejected. Most important section.
3. If the decision constrains future work, also create `wiki/decisions/<topic>.md`.
4. Session notes: plain markdown, **no YAML frontmatter, no `[[wikilinks]]`** — olw adds those.

Required note sections: `# Context`, `# What Changed`, `# Why`, `# Intended Outcome`, `# Decisions`, `# Open Questions`

### Operational logging

Append a one-line entry to `wiki/log.md` after writing a note.
Format: `[YYYY-MM-DD HH:MM] note | <topic>`

