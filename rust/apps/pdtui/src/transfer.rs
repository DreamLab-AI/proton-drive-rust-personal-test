//! Transfer queue. Wired in M4/M5 once `FileUploader` / `FileDownloader`
//! have real bodies.

#![allow(dead_code)]

use std::sync::Arc;
use tokio::sync::Semaphore;

pub struct TransferQueue {
    pub permits: Arc<Semaphore>,
}

impl TransferQueue {
    pub fn new(parallelism: usize) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(parallelism)),
        }
    }
}
