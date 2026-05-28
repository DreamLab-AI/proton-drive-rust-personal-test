# ADR-0009: Block-download protocol — port JS happy path

**Status:** accepted, 2026-05-28.
**Context milestone:** ME.
**Depends on:** ADR-0008 (block-upload symmetry), ADR-0011 (zeroize), ADR-0012 (wire-format validation).

## Decision

Port `js/sdk/src/internal/download/` happy path 1:1 into `proton-drive-core::download`. Sequential block fetch, signature verify per block, write to async stream. Seekable/parallel download deferred.

## The protocol (as derived from the JS SDK)

```
1. Client: GET /drive/v2/volumes/{volumeID}/files/{linkID}/revisions/{revisionID}
   → returns: { Revision: { ID, State, Blocks: [{ Index, BareURL, Token,
                            EncSignature, Hash, Size }], ManifestSignature,
                            ContentKeyPacket, XAttr, SignatureAddress } }
   (Active revision id obtained from the Link's ActiveRevision field, fetched
   via GET /drive/shares/{shareID}/links/{linkID}.)

2. Client: derive content session key from ContentKeyPacket using the
   node's private key. Verify ContentKeyPacketSignature with the
   SignatureAddress public key, context = "drive.file.content-key".

3. Client: verify ManifestSignature over concatenated block hashes in
   ascending Index order. Context = "drive.file.manifest". If verification
   fails, abort.

4. Client: for each block in Index order:
     a. GET BareURL with Authorization: Bearer Token  → ciphertext_i
     b. assert sha256(ciphertext_i) == Block.Hash, else IntegrityCheckFailed
     c. (plaintext_i, sig_status) = decrypt_and_verify(ciphertext_i,
                                                       session_key,
                                                       [SignatureAddress.pub])
        - sig_status must be Ok or NoSignature (legacy revisions).
        - SignatureWrongSigner / SignatureInvalid → abort.
     d. write plaintext_i to caller-supplied AsyncWrite
```

## Implementation constraints

- **Concurrency: 1 block at a time** (matches MD).
- **No retry mid-block:** transient HTTP errors during a block GET fail the whole download. MVP user can re-invoke. Retries belong to a later "robust transfer" milestone.
- **No range requests:** full block, full file. No seek.
- **XAttr is informational** for MVP — used to set the local file's modification time, not size-checked (the JS SDK does verify the assembled size matches XAttr.Common.Size; we should too, cheap).

## What is NOT ported

- `seekableStream.ts` — random-access download
- `blockIndex.ts` — block-skip optimisation
- Thumbnail download (`thumbnailDownloader.ts`)
- `queue.ts` parallel orchestration
- Telemetry

## Rust API shape

```rust
// crates/proton-drive-core/src/download.rs
pub struct FileDownloader { /* http, crypto, account */ }

impl FileDownloader {
    pub async fn download_to_writer(
        &self,
        node: NodeUid,
        writer: impl AsyncWrite + Unpin,
    ) -> Result<DownloadStats, Error> {
        // Resolves active revision, then drives 4-step protocol.
    }
}

pub struct DownloadStats {
    pub bytes: u64,
    pub blocks: u32,
    pub last_modification_time: Option<DateTime<Utc>>,
}
```

## Quality gates specific to this milestone

- **Round-trip test (gates merge):** upload `tests/fixtures/small.txt` via MD, immediately download via ME, assert plaintext bytes match.
- **Negative-path tests required:**
  - Tampered block (flip one byte in `tests/fixtures/tampered_block.bin`) → `Error::IntegrityCheckFailed`
  - Manifest-signature mismatch → `Error::SignatureInvalid` before any block fetched
  - Server returns 404 on revision lookup → `Error::NotFound`

## References

- `js/sdk/src/internal/download/fileDownloader.ts`
- `js/sdk/src/internal/download/apiService.ts`
- `js/sdk/src/internal/download/cryptoService.ts`
- `js/sdk/src/internal/download/controller.ts`
