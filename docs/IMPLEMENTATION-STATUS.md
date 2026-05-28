# Implementation Status — MVP upload/download + auth

Date: 2026-05-28. Branch: `rust-port`.

Supersedes the 2026-05-27 milestone snapshot. Every M0–M7 milestone now has a
real implementation (no `NotImplemented` on the happy path). What remains are
**live-account interop gaps** found by the QE pass — code that compiles, is
unit/wire-tested, but has not been proven against the production API.

## Milestone state

| M | Goal | State | Evidence |
|---|---|---|---|
| M0 | Workspace + CI + traits | Done | `cargo check/clippy/fmt/test/doc` green; deny-lints active |
| M1 | JSON API DTOs | Done | serde round-trip tests; happy-path subset for list/upload/download/events |
| M2 | Crypto (rpgp 0.16) | Done | `decrypt_session_key`, `encrypt_and_sign`, `decrypt_and_verify`, manifest sign/verify, `generate_passphrase`, AEAD rejection; validated by JS-encoded wire fixtures |
| M3 | HTTP + SRP auth | Done | `ReqwestHttpClient` (retry/backoff/jitter/`x-pm-appversion`); SRP login via `proton-srp` 0.8.2 (`auth/info → SRP → auth`); `SessionManager` proactive + reactive refresh (ADR-0010) |
| M4 | Upload block protocol | Done (interop gaps) | create file → request revision → 4 MiB chunk → encrypt+sign → block tokens → PUT BareURL → commit. See blockers below |
| M5 | Download block protocol | Done (interop gaps) | get revision → decrypt content key → manifest verify → per-block GET/hash/decrypt-verify → stream. See blockers below |
| M6 | Events | DTOs only | `proton-drive-api::events` shapes present; no consumer wired (pull-only listing for MVP, per domain-model-mvp.md) |
| M7 | pdtui TUI | Done | local + remote panes, F3-upload/F2-download, progress gauge, `PdtuiAccount` key-unlock bootstrap, session persistence |

## Test gate (end state)

- `cargo fmt --all --check` — clean
- `cargo clippy --workspace --all-targets` — clean (2 benign warnings: `session::logout` dead-code, `transfer.rs` `type_complexity`)
- `cargo test --workspace` — **85 passing, 0 failing, 6 ignored**
  - Ignored: live `auth_integration` (needs account), `wire_rust_encrypted_decryptable_by_node` (needs `node`+`openpgp` npm), `pdtui` spawn_upload/spawn_download live paths.
- Wire-format fixtures (ADR-0012): JS→Rust decrypt+verify, tamper rejection, **wrong-signer rejection** all pass.

## Known blockers — require a live Proton account to close

These gate a *successful live upload/download*. Severity is "will the happy path
work against production today".

| # | Blocker | Where | Effect | Severity |
|---|---|---|---|---|
| B1 | Name hash is `SHA256(name)`, not `HMAC-SHA256(NodeHashKey, name)` | `upload.rs:~330` (FIXME) | Server 422 on file create — needs parent `FolderProperties.NodeHashKey` decrypted | **Blocking upload** |
| B2 | Nested-folder key derivation deferred | `download.rs` `decrypt_node_private_key` works for share-root children only | Files outside MyFiles root can't derive node key | High (MVP = root files) |
| B3 | XAttr modification-time decrypt is a TODO; size-mismatch logs, not fatal | `download.rs:~355`, `~393` | Restored mtime not applied; corrupted-size XAttr not caught | Medium |
| B4 | Recovered address-key + node passphrases held as plain `String`/`Vec<u8>` | `account.rs:~206`, `download.rs:~540` | Secret material not zeroized on drop (violates ADR-0011 spirit) | Medium (security) |
| B5 | Detached per-block `enc_signature` fetched but not independently verified | `download.rs` | Inline block signature *is* verified (see C1 fix); detached sig is not a second gate | Low (manifest + inline cover integrity) |
| B6 | Download partial-write leaves a truncated file on mid-stream failure | `download.rs:~148` | No cleanup of the caller's writer on error | Low |
| B7 | Dead `decrypt_node_key` public stub returns `NotImplemented` | `download.rs:517` | Confusing API surface; real path is `decrypt_node_private_key` | Trivial (delete) |

## Fixed this pass (QE triage)

- **C1 — signature-verification bypass (CRITICAL):** `decrypt_and_verify`
  mapped any non-empty `verify_nested` result to `Ok`, including all-`Invalid`
  vectors. A forged/wrong-signer signature verified as valid. Now inspects
  `VerificationResult` variants → `SignatureWrongSigner` on present-but-invalid,
  `NoSignature` on bare payloads. This also hardens the download path: blocks
  with a bad signature now abort instead of silently passing.
- **CDN block-URL mangling (blocking):** `request_blob` joined every path
  against the API base, turning absolute `BareURL`s into
  `…/api/https://upload.proton.me/…` 404s. Now uses `http(s)://` paths verbatim.

## What's deliberately not done

- Full OpenAPI surface — only list/upload/download/events DTOs. Mechanical to extend.
- Events consumer / live sync — DTOs exist, listing is pull-on-focus for MVP.
- SEIPDv2 / AEAD — rejected by ADR-0006, deferred to M2.5.
- SQLite cache — in-memory only, ADR-0003.

## Honest verdict

The MVP is **code-complete and unit/wire-verified end-to-end**, but a first live
upload will fail at file-create until **B1 (HMAC name hash)** is fixed, which
needs the parent folder's `NodeHashKey`. That is the single highest-value next
task. B4 (zeroize passphrases) should land alongside as a security cleanup.
Everything else is either MVP-scoped-out (B2) or non-blocking polish (B3, B5–B7).
