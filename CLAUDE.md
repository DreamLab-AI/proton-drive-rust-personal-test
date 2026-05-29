# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Layout

Multi-language monorepo for the Proton Drive SDK. Four sibling trees, two implementations:

- `js/sdk/` — **TypeScript native SDK** (`@protontech/drive-sdk` on npm). Independent implementation.
- `cs/sdk/` — **C# native SDK** (.NET 10, AOT-capable). Independent implementation.
- `kt/sdk/` — **Kotlin bindings** wrapping the C# SDK via JNI (`src/main/jni/*.c` + `jniLibs/`).
- `swift/ProtonDriveSDK/` — **Swift bindings** wrapping the C# SDK via the C ABI (`cs/headers/*.h`).

The C SDK exposes a C ABI via `cs/sdk/src/Proton.{Drive.,}Sdk.CExports/` and `cs/headers/proton_*.h`. Kotlin/Swift do not duplicate business logic — they marshal calls into the AOT-compiled C# native library. JS is fully independent.

Cross-language wire types are defined as protobufs in `cs/sdk/src/protos/`.

The C# changelog (`cs/CHANGELOG.md`) is the source of truth for kt/swift releases; JS has its own (`js/CHANGELOG.md`).

## Build & Test Commands

### TypeScript (`js/sdk/`)
```bash
npm install
npm run build              # tsc -> dist/
npm run check-types        # type-check only
npm test                   # jest
npm test -- path/to/file.test.ts                  # single file
npm test -- -t "test name pattern"                # by test name
npm run test:watch
npm run lint
npm run lint:ttag          # validate ttag i18n usage
npm run generate-types     # regenerate OpenAPI client types from ../../api/openapi-*.json
npm run generate-doc:interface  # OUTPUT_PATH=./doc required
```
OpenAPI source files (`api/openapi-drive.json`, `api/openapi-core.json`) live outside this repo — `generate-types` will fail in a standalone checkout.

### C# (`cs/`)
```bash
dotnet build cs/Proton.Drive.Sdk.slnx
dotnet test cs/Proton.Drive.Sdk.slnx
dotnet test --filter "FullyQualifiedName~SomeTestClass"   # single test/class
```
Release builds treat warnings as errors (`cs/Directory.Build.props`). Target framework `net10.0`, AOT publishing enabled.

### Kotlin (`kt/`)
```bash
./gradlew :sdk:build
./gradlew :sdk:test
```
JNI sources in `kt/sdk/src/main/jni/` bind to the C# native library shipped under `jniLibs/`.

### Swift (`swift/ProtonDriveSDK/`)
Standard SwiftPM (`swift build`, `swift test`). Links against the C# AOT artifact via `cs/headers/module.modulemap`.

## Architecture

### TypeScript SDK (`js/sdk/src/`)
Entry point is `ProtonDriveClient` (`protonDriveClient.ts`), plus `ProtonDrivePhotosClient` and `ProtonDrivePublicLinkClient`. Only symbols re-exported from `src/index.ts` are public API — everything under `internal/` can change without warning.

- `interface/` — public types & contracts the embedding app implements (`httpClient`, `account`, `featureFlags`, etc.). The SDK does **not** provide authentication, session management, or user-address resolution; the host wires these in.
- `internal/` — implementation. Subdirectories mirror domain concerns: `nodes/`, `shares/`, `sharing/`, `sharingPublic/`, `devices/`, `events/`, `upload/`, `download/`, `photos/`, `apiService/`.
- `internal/apiService/{drive,core}Types.ts` — generated; do not hand-edit (excluded from lint).
- `crypto/` — `OpenPGPCrypto` interface + `OpenPGPCryptoWithCryptoProxy` adapter. Crypto module is injected by the host.
- `cache/` — pluggable cache (`MemoryCache` ships; hosts can implement persistent variants). Two caches required: `entitiesCache` and `cryptoCache`.
- Construction requires `{ httpClient, entitiesCache, cryptoCache, account, openPGPCryptoModule }`.
- Sync is **event-based** (`internal/events/`, `sdkEvents.ts`); never poll or recursively traverse the tree.
- i18n via `ttag`; `npm run lint:ttag` enforces correct usage.

### C# SDK (`cs/sdk/src/`)
Two layered projects:
- `Proton.Sdk` / `Proton.Sdk.CExports` — base Proton SDK primitives (HTTP, crypto, telemetry, resilience).
- `Proton.Drive.Sdk` / `Proton.Drive.Sdk.CExports` — Drive-specific client (`ProtonDriveClient`, `ProtonPhotosClient`, nodes, shares, uploads/downloads).

The `*.CExports` projects produce the C ABI consumed by Kotlin/Swift. `Interop*` types adapt managed APIs to flat C-callable shapes. Native library lookup is centralised in `NativeLibraryResolver.cs`.

### Operational constraints (apply to all implementations)
- Set `x-pm-appversion` header as `external-drive-{name}@{semver}-{channel}[+suffix]`.
- All HTTP must hit official Proton endpoints — no proxying.
- Rate limits are shared with first-party clients; respect caching, backoff, parallelism limits.
- A breaking cryptographic-model migration is targeted late-2026/early-2027 (see root README).

## When Modifying

- TS public surface: if changes affect `src/index.ts` re-exports or anything under `src/interface/`, update `js/CHANGELOG.md`.
- C# public surface or anything exposed via `*.CExports`: update `cs/CHANGELOG.md` (covers kt + swift releases).
- Touching `internal/apiService/*Types.ts` by hand is wrong — regenerate via `npm run generate-types`.
- Touching the C ABI (`cs/headers/*.h` or `*.CExports/Interop*.cs`) requires coordinated updates to `kt/sdk/src/main/jni/*.c` and the Swift `Plumbing/`/`Client/` layers.
