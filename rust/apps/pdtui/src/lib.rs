//! Library target — exposes internal modules so `tests/` integration tests
//! can import them. Not published; binary entry point stays in `main.rs`.

#![forbid(unsafe_code)]

pub mod auth;
pub mod http;
pub mod session;
