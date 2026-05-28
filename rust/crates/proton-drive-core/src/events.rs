//! Event subscription aggregate. Mirrors `js/sdk/src/interface/events.ts`.

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use crate::error::Result;
use crate::nodes::NodeUid;

#[derive(Debug, Clone)]
pub enum DriveEvent {
    Node(NodeEvent),
    TreeRefresh(TreeRefreshEvent),
    TreeRemoval(TreeRemovalEvent),
    FastForward(FastForwardEvent),
    SharedWithMeUpdated,
}

#[derive(Debug, Clone)]
pub struct NodeEvent {
    pub uid: NodeUid,
    pub kind: NodeEventKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeEventKind {
    Created,
    Updated,
    Trashed,
    Restored,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone)]
pub struct TreeRefreshEvent {
    pub root: NodeUid,
}

#[derive(Debug, Clone)]
pub struct TreeRemovalEvent {
    pub root: NodeUid,
}

#[derive(Debug, Clone)]
pub struct FastForwardEvent {
    pub new_event_id: String,
}

/// Host-installed sink for drive events. Mirrors JS `DriveListener`.
#[async_trait]
pub trait DriveListener: Send + Sync {
    async fn on_event(&self, event: DriveEvent);
}

/// Lifetime handle for an event subscription. Dropping cancels the feed.
pub struct EventSubscription {
    pub(crate) cancel: CancellationToken,
}

impl EventSubscription {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Host-supplied storage for the last-seen event id (resume cursor).
/// Mirrors JS `LatestEventIdProvider`.
#[async_trait]
pub trait LatestEventIdProvider: Send + Sync {
    async fn get(&self) -> Result<Option<String>>;
    async fn set(&self, event_id: &str) -> Result<()>;
}
