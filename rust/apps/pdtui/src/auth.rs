//! Account impl for personal use. M3 wires SRP via Proton's auth endpoints
//! and persists a refresh token in the OS keyring (`secret-service` on Linux,
//! Keychain on macOS), falling back to an encrypted file.

#![allow(dead_code)]
