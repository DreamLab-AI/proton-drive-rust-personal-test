# Rust Port — Handoff to Linux Workstation

You're picking up the Rust port of the Proton Drive SDK + `pdtui` TUI on the user's Linux machine, where they have access to their live Proton Drive account.

**Read these first, in order:**

1. [`docs/PRD-rust-port-and-tui.md`](docs/PRD-rust-port-and-tui.md) — Product requirements, milestones M0–M7, risks
2. [`docs/adr/README.md`](docs/adr/README.md) — Architecture decisions (port source, crypto choice, scope)
3. [`docs/domain-model.md`](docs/domain-model.md) — Bounded contexts, ubiquitous language, aggregate→module map
4. [`docs/IMPLEMENTATION-STATUS.md`](docs/IMPLEMENTATION-STATUS.md) — **What's done, what's stubbed, what needs live validation**

## TL;DR — where things stand (2026-05-28)

All M0–M7 milestones now have a real implementation. 85 tests pass; the crypto
layer is validated against JS-encoded wire fixtures. What's left is **live-API
interop**, not scaffolding. Full detail in `docs/IMPLEMENTATION-STATUS.md`.

| Layer | State | Trustable? |
|---|---|---|
| Workspace + traits + error model | Complete | Yes |
| JSON DTOs (list/upload/download/events) | Complete (happy-path subset) | Yes — roundtrips; live API untested |
| `ReqwestHttpClient` (retry/backoff/headers) | Complete | Yes — lint-clean; live API untested |
| Crypto — encrypt/decrypt/sign/verify | Complete | Yes — passes JS-encoded wire fixtures + tamper/wrong-signer rejection |
| SRP auth (`proton-srp` 0.8.2) | Complete | Yes — unit-tested; live login untested |
| `SessionManager` refresh (ADR-0010) | Complete | Yes — unit-tested |
| Upload block protocol | Complete | **Partial** — blocked live by B1 (HMAC name hash → 422) |
| Download block protocol | Complete | **Partial** — works for root-level files (B2) |
| Events subscription | DTOs only | n/a — pull-on-focus for MVP |
| `pdtui` local + remote panes | Complete | Yes — remote pane wired to real `PdtuiAccount` |

## The one thing that blocks a live upload

**B1 — name hash.** `upload.rs:~330` uses `SHA256(name)`; Proton wants
`HMAC-SHA256(NodeHashKey, name)` where `NodeHashKey` comes from the parent
folder's decrypted `FolderProperties`. Until this lands, file-create returns
422. This is the highest-value next task. See `docs/IMPLEMENTATION-STATUS.md`
§"Known blockers" for the full list (B1–B7), including B4 (zeroize recovered
passphrases — security).

**Never commit real account secrets** — `.gitignore` excludes `rust/.env` and
`rust/fixtures/auth/*`.

## Recommended order on the Linux box

1. Run the gate: `cargo fmt --all --check && cargo clippy --workspace --all-targets && cargo test --workspace` — expect 85 pass / 6 ignored.
2. Boot `pdtui`, log in with real credentials (SRP is live), confirm the remote pane lists MyFiles root.
3. **Fix B1** — decrypt parent `NodeHashKey`, compute `HMAC-SHA256` name hash. This unblocks the first real upload. Verify against the account.
4. **Fix B4** alongside — wrap recovered passphrases in `Zeroizing`.
5. Verify round-trip: upload a small file, download it, assert byte-identical.
6. Then B2 (nested folders), B3 (XAttr mtime), B6 (partial-write cleanup), B7 (delete dead stub) as polish.
7. M6 events consumer if live sync is wanted post-MVP.

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

DTOs are JSON, not protobuf (see Guardrails below). M0–M7 are implemented and
committed on `rust-port` (see `git log`: MB–MH waves). Remaining work is the
B1–B7 live-interop blockers in `docs/IMPLEMENTATION-STATUS.md`, not new
milestones — the agent mesh + QE pass that produced this state is complete.

## Guardrails worth keeping

- `unwrap_used`/`expect_used`/`panic` are **denied workspace-wide**. Tests opt out with `#[allow(...)]` on the test module.
- `cargo fmt --check` is part of CI. Run `cargo fmt --all` before committing.
- The crypto trait seam is non-negotiable — direct `pgp::*` references outside `proton-drive-crypto` are a bug.
- No protobuf codegen. The DTOs are JSON. The `cs/sdk/src/protos/` files are for C-ABI marshalling to kt/swift only.
- No polling. The PRD invariants say "event subscription is the only sync mechanism" — keep it that way.
- `x-pm-appversion = external-drive-pdtui@{semver}-stable`. Never spoof a first-party header. The middleware enforces this; don't bypass.
- Personal use only. No publishing to crates.io, no binary releases, no fork-promotion. See ADR-0007.
