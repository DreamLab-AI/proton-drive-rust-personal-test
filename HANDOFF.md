# Rust Port — Handoff to Linux Workstation

You're picking up the Rust port of the Proton Drive SDK + `pdtui` TUI on the user's Linux machine, where they have access to their live Proton Drive account.

**Read these first, in order:**

1. [`docs/PRD-rust-port-and-tui.md`](docs/PRD-rust-port-and-tui.md) — Product requirements, milestones M0–M7, risks
2. [`docs/adr/README.md`](docs/adr/README.md) — Architecture decisions (port source, crypto choice, scope)
3. [`docs/domain-model.md`](docs/domain-model.md) — Bounded contexts, ubiquitous language, aggregate→module map
4. [`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) — **What's done, what's stubbed, what needs live validation**

## TL;DR — where things stand

| Layer | State | Trustable? |
|---|---|---|
| Workspace + traits + error model | Complete | Yes |
| JSON DTOs for list/upload/download/events | Complete (happy-path subset) | Yes — schema roundtrips, untested against live API |
| `ReqwestHttpClient` (retry/backoff/headers) | Complete | Yes — compiles, lint-clean, unverified against live API |
| Crypto — passphrase + AEAD rejection | Complete | Yes |
| Crypto — encrypt/decrypt/sign/verify | Stubbed | **No** — needs live fixtures |
| SRP auth | Trait shape only | **No** — needs live endpoint to validate |
| Upload/download block protocol | DTOs only | **No** — needs M2 + auth |
| Events subscription | DTOs only | **No** — needs auth |
| `pdtui` local pane | Real filesystem nav | Yes |
| `pdtui` remote pane | Shows "auth not configured" placeholder | n/a |

## What you need to make progress on the Linux box

You need exactly **one** of these to unblock M2 crypto bodies and M3 auth:

**Option A (lowest risk):** Capture a HAR of an existing logged-in JS-SDK session against the user's account. Endpoints in `scripts/capture-fixtures.sh`. Sanitise to remove tokens before storing under `rust/fixtures/`.

**Option B:** Run the JS SDK's CLI (`js/cli`) against the user's account once, save the captured network traffic, then port from observed bytes.

**Option C:** Implement SRP from scratch against the live `/auth/v4` endpoint with the user's credentials. Burns rate budget on failure; have backoff in place.

Either way, **never commit real account secrets** — the `.gitignore` already excludes `rust/.env` and `rust/fixtures/auth/*`.

## Recommended order on the Linux box

1. Run `scripts/setup.sh` — verifies toolchain, installs rust if missing, runs the full QE pass to prove the repo builds cleanly on the target machine.
2. Run `scripts/smoke.sh` — boots `pdtui`, verifies local pane navigates, exits cleanly.
3. **Decide auth strategy** (A/B/C above). The PRD already includes a `KeyringAccount` design — finishing it requires SRP working first.
4. Land M2 crypto bodies. Use `pgp` 0.16 ops mirroring `js/sdk/src/crypto/openPGPCrypto.ts` exactly. Self-roundtrip-test each op before declaring done.
5. Land M3 SRP. Pure-Rust crates: `srp` or `num-bigint`. Validate against a live login.
6. Land M4 upload — port `js/sdk/src/internal/upload/` faithfully; the block-content-key + per-block manifest pattern is the structural anchor.
7. Land M5 download — inverse of M4.
8. Land M6 events — port `js/sdk/src/internal/events/`; assert no timer-driven listings in production paths (lint).
9. Land M7 — wire `pdtui` remote pane to the SDK.

## How to talk to the agents on the Linux machine

This handoff doc is the entry point. Reference it from any new agent invocation:

```
Read HANDOFF.md, then docs/IMPLEMENTATION-STATUS.md.
The current task is: <thing you want>
The constraint is: <verifiable, no fabrication; ask for fixtures if needed>
```

Skills/agents already wired into the user's setup:
- `claude-code-guide` for Claude Code itself
- `agentic-qe` (broken in container, working on host — try it on Linux)
- ruflo / ruvector swarm tools (`mcp__ruvector__*`)

There is an active mesh swarm from the prior session: ID `swarm_1779915934241_4kdqcse`. Five agents spawned (`m1-protobuf-codegen`, `m2-rpgp-impl`, `m3-http-account`, `tui-wiring`, `qe-reviewer`). `m1-protobuf-codegen` is **stale** — protobuf was the wrong target (see `IMPLEMENTATION-STATUS.md` correction). Either retire it or rebrand to `m1-json-dtos`.

## Guardrails worth keeping

- `unwrap_used`/`expect_used`/`panic` are **denied workspace-wide**. Tests opt out with `#[allow(...)]` on the test module.
- `cargo fmt --check` is part of CI. Run `cargo fmt --all` before committing.
- The crypto trait seam is non-negotiable — direct `pgp::*` references outside `proton-drive-crypto` are a bug.
- No protobuf codegen. The DTOs are JSON. The `cs/sdk/src/protos/` files are for C-ABI marshalling to kt/swift only.
- No polling. The PRD invariants say "event subscription is the only sync mechanism" — keep it that way.
- `x-pm-appversion = external-drive-pdtui@{semver}-stable`. Never spoof a first-party header. The middleware enforces this; don't bypass.
- Personal use only. No publishing to crates.io, no binary releases, no fork-promotion. See ADR-0007.
