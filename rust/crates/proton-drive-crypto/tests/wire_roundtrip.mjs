#!/usr/bin/env node
/**
 * wire_roundtrip.mjs — JS helper for the Rust encrypt→JS decrypt roundtrip test.
 *
 * Usage (from the Rust #[ignore] test or manually):
 *   node wire_roundtrip.mjs < ciphertext.bin > plaintext.bin
 *
 * Reads binary OpenPGP ciphertext from stdin, decrypts with key_priv.asc,
 * verifies the embedded signature against signer_pub.asc, and writes the
 * raw plaintext bytes to stdout.  Exits 0 on success, non-zero on any error.
 *
 * Keys are resolved relative to this file:
 *   ../../../tests/fixtures/wire/key_priv.asc
 *   ../../../tests/fixtures/wire/signer_pub.asc
 *
 * Requires: openpgp npm package in tests/fixtures/wire/node_modules/
 */

import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = resolve(join(HERE, '../../../tests/fixtures/wire'));

// ── dependency guard ──────────────────────────────────────────────────────────

let openpgp;
try {
  // Use createRequire to find openpgp relative to the fixture dir where it
  // was installed by generate.mjs.
  const req = createRequire(join(FIXTURE_DIR, 'package.json'));
  openpgp = await import(req.resolve('openpgp'));
} catch {
  process.stderr.write(
    'ERROR: openpgp not found.\n' +
    `Run: cd ${FIXTURE_DIR} && npm i openpgp\n`
  );
  process.exit(1);
}

// ── read ciphertext from stdin ────────────────────────────────────────────────

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

const ciphertextBuf = await readStdin();
if (ciphertextBuf.length === 0) {
  process.stderr.write('ERROR: no ciphertext on stdin\n');
  process.exit(1);
}

// ── load keys ─────────────────────────────────────────────────────────────────

let privKey, signerPubKey;
try {
  const privArmored = readFileSync(join(FIXTURE_DIR, 'key_priv.asc'), 'utf8');
  privKey = await openpgp.readPrivateKey({ armoredKey: privArmored });
} catch (e) {
  process.stderr.write(`ERROR loading key_priv.asc: ${e.message}\n`);
  process.exit(1);
}

try {
  const signerArmored = readFileSync(join(FIXTURE_DIR, 'signer_pub.asc'), 'utf8');
  signerPubKey = await openpgp.readKey({ armoredKey: signerArmored });
} catch (e) {
  process.stderr.write(`ERROR loading signer_pub.asc: ${e.message}\n`);
  process.exit(1);
}

// ── decrypt + verify ──────────────────────────────────────────────────────────

let result;
try {
  const message = await openpgp.readMessage({ binaryMessage: ciphertextBuf });
  result = await openpgp.decrypt({
    message,
    decryptionKeys: privKey,
    verificationKeys: signerPubKey,
    config: { allowInsecureDecryptionWithSigningKeys: false },
    format: 'binary',
  });
} catch (e) {
  process.stderr.write(`ERROR decrypting: ${e.message}\n`);
  process.exit(1);
}

// Verify signature — this throws if not verified.
try {
  for (const sig of result.signatures) {
    await sig.verified; // throws on invalid signature
  }
  if (result.signatures.length === 0) {
    process.stderr.write('ERROR: no signatures found in message\n');
    process.exit(1);
  }
} catch (e) {
  process.stderr.write(`ERROR: signature verification failed: ${e.message}\n`);
  process.exit(1);
}

// ── write plaintext to stdout ─────────────────────────────────────────────────

process.stdout.write(Buffer.from(result.data));
process.exit(0);
