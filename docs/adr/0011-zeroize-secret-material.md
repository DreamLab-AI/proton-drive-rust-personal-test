# ADR-0011: Zeroize all credential and key material on drop

**Status:** accepted, 2026-05-28.
**Context milestone:** MA.
**Driver:** code-quality audit `[HIGH]` finding — secrets remain in heap after drop, observable by post-mortem RAM inspection or by stale pages making it to swap.

## Decision

All types holding credential or key material implement `ZeroizeOnDrop` (via the `zeroize` crate, derive-feature). The convention:

- `String` holding a secret → `Zeroizing<String>`
- `Vec<u8>` holding a secret → `Zeroizing<Vec<u8>>`
- A struct whose fields are all secret → `#[derive(ZeroizeOnDrop)]` plus `#[derive(Zeroize)]` so manual zeroing on `clear()` is available
- Public-key material is **not** zeroized (public).
- `PrivateKey.armored` is **not** zeroized because rpgp's armor format wraps the key material in encoded text and the unlocking passphrase is the actual secret; we zeroize `passphrase` instead.

## Types affected

| Type | Crate | Change |
|---|---|---|
| `Credentials` | `apps/pdtui/src/auth.rs` | `Zeroizing<String>` on access_token / refresh_token / key_password / uid stays plain |
| `PrivateKey.passphrase` | `proton-drive-crypto` | `Zeroizing<String>` |
| `SessionKey.data` | `proton-drive-crypto` | `Zeroizing<Vec<u8>>` |
| `LoginForm.password` | `apps/pdtui/src/app.rs` | `Zeroizing<String>` |
| `SrpExchange.client_proof`, `expected_server_proof`, `client_ephemeral` | `proton-drive-crypto` | leave plain — public over the wire after use; not worth complexity |
| `SessionState` (new) | `apps/pdtui/src/session.rs` | derive `ZeroizeOnDrop`; individual `Zeroizing<…>` fields |

## What is NOT done

- `subtle::ConstantTimeEq` on the server-proof comparison (`apps/pdtui/src/auth.rs:109`) — this is a separate concern (timing-side-channel hygiene). Doing it here too because the cost is one line and the audit flagged it: change `expected != actual` to `expected.as_bytes().ct_eq(actual.as_bytes()).into()`.
- Memory-locking (`mlock`) to keep pages out of swap. Linux desktop scope; we accept the swap risk for personal use.
- Stack-allocated secrets — rpgp owns its own buffers internally; we trust them not to leak.

## Quality gates

- Add `zeroize = { version = "1.8", features = ["zeroize_derive", "derive"] }` and `subtle = "2.6"` to the workspace.
- Existing tests must still pass — zeroize is invisible at the type level for `Zeroizing<T>` because it derefs to `&T`.
- **New test** in `proton-drive-crypto/tests/zeroize_smoke.rs`: drop a SessionKey, verify (via raw-pointer inspection) the buffer was zeroed. (This is a deliberately gnarly test — gate behind `#[cfg(target_os = "linux")]` and `--features test-zeroize`. Not a CI gate but a once-and-confirm sanity check.)

## What this does and does not protect against

| Threat | Mitigated? |
|---|---|
| Core dump / post-mortem RAM dump after process exit | Yes, for the protected fields |
| Swap-out of secret page during long idle | Partially — Linux may have already paged it; `mlock` would be needed |
| Hostile process with same UID reading our memory | No — root or same-UID attackers have ptrace |
| Coredump *during* a request while secrets are live | No — fundamentally cannot mitigate |
| Compiler reordering / DCE of the zeroize call | No — `zeroize` crate uses volatile writes specifically to defeat this |

## References

- Audit finding: code-quality review of `fdc9db7`, `[HIGH]` "No zeroize on credential material"
- `zeroize` crate documentation
