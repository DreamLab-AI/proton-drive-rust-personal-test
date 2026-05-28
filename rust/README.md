# Rust port — `proton-drive` + `pdtui`

Personal-use Rust port of the Proton Drive SDK plus a two-pane tmux-ready TUI.
Scope and decisions live in [`../docs/PRD-rust-port-and-tui.md`](../docs/PRD-rust-port-and-tui.md),
[`../docs/adr/`](../docs/adr/), and [`../docs/domain-model.md`](../docs/domain-model.md).

## Layout

```
rust/
├─ crates/
│  ├─ proton-drive             # public facade (re-exports)
│  ├─ proton-drive-core        # client, nodes, events, transfer
│  ├─ proton-drive-api         # HTTP DTOs (M1: codegen from cs/sdk protos)
│  ├─ proton-drive-crypto      # OpenPgpCrypto trait + rpgp impl (M2)
│  ├─ proton-drive-cache       # ProtonDriveCache trait + MemoryCache
│  └─ proton-drive-telemetry   # Telemetry trait + NullTelemetry
└─ apps/
   └─ pdtui                    # two-pane TUI binary
```

## Build

```bash
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build -p pdtui
```

## Current state (M0)

- ✅ Workspace scaffolded, all crates compile
- ✅ Trait surface mirrors JS `interface/` 1:1
- ✅ Error taxonomy, config, value objects in place
- ✅ pdtui skeleton with keymap dispatch and ratatui rendering
- ⏳ M1: protobuf + OpenAPI codegen in `proton-drive-api`
- ⏳ M2: `rpgp` bodies in `proton-drive-crypto` (SEIPDv1 path)
- ⏳ M3: real `my_files_root` / `iter_folder_children` against the API
- ⏳ M4/M5: upload + download
- ⏳ M6: event subscription
- ⏳ M7: pdtui v0.1.0

See PRD §8 for the milestone table.
