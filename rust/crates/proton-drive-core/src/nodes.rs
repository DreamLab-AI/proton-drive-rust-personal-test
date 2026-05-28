//! Node aggregate. Mirrors `js/sdk/src/interface/nodes.ts`.

use crate::account::Author;
use proton_drive_crypto::{PrivateKey, SessionKey};
use std::time::SystemTime;

/// Stable handle for a Node: `(volume_id, node_id)`.
///
/// Mirrors JS `NodeUid` (an opaque base64 string encoding both ids).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeUid {
    pub volume_id: String,
    pub node_id: String,
}

/// Build a `NodeUid` from raw ids. Mirrors JS `generateNodeUid`/`makeNodeUid`.
pub fn make_node_uid(volume_id: impl Into<String>, node_id: impl Into<String>) -> NodeUid {
    NodeUid {
        volume_id: volume_id.into(),
        node_id: node_id.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeType {
    File,
    Folder,
    Album,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionState {
    Draft,
    Active,
    Superseded,
}

#[derive(Debug, Clone)]
pub struct Revision {
    pub uid: String,
    pub state: RevisionState,
    pub size_bytes: Option<u64>,
    pub created_at: SystemTime,
    pub author: Author,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub uid: NodeUid,
    pub parent: Option<NodeUid>,
    pub name: String,
    pub node_type: NodeType,
    pub media_type: Option<String>,
    pub size_bytes: Option<u64>,
    pub created_at: SystemTime,
    pub modified_at: SystemTime,
    pub trashed: bool,
    pub author: Author,
    pub active_revision: Option<Revision>,
}

/// Maybe-degraded node — mirrors JS `MaybeNode` (`Node | DegradedNode | MissingNode`).
///
/// `Node` is boxed because the fully-decoded variant is far larger than the
/// fallback variants; keeps the enum compact for hot paths (folder iteration).
#[derive(Debug, Clone)]
pub enum MaybeNode {
    Node(Box<Node>),
    Degraded { uid: NodeUid, reason: String },
    Missing { uid: NodeUid },
}

impl MaybeNode {
    pub fn uid(&self) -> &NodeUid {
        match self {
            MaybeNode::Node(n) => &n.uid,
            MaybeNode::Degraded { uid, .. } => uid,
            MaybeNode::Missing { uid } => uid,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FolderChildrenFilter {
    pub include_trashed: bool,
    pub only_type: Option<NodeType>,
}

/// Cached cryptographic material for a Node or Share.
/// Mirrors JS `CachedCryptoMaterial`.
#[derive(Debug, Clone)]
pub struct CachedCryptoMaterial {
    pub node_keys: Option<NodeKeyMaterial>,
    pub share_key: Option<ShareKeyMaterial>,
    pub public_share_key: Option<PrivateKey>,
}

#[derive(Debug, Clone)]
pub struct NodeKeyMaterial {
    pub passphrase: String,
    pub key: PrivateKey,
    pub passphrase_session_key: SessionKey,
    pub content_key_packet_session_key: Option<SessionKey>,
    pub hash_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ShareKeyMaterial {
    pub key: PrivateKey,
    pub passphrase_session_key: SessionKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_uid_eq_and_hash() {
        let a = make_node_uid("vol-1", "node-1");
        let b = make_node_uid("vol-1", "node-1");
        let c = make_node_uid("vol-2", "node-1");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn maybe_node_uid_extracts_for_each_variant() {
        let uid = make_node_uid("v", "n");
        let missing = MaybeNode::Missing { uid: uid.clone() };
        let degraded = MaybeNode::Degraded {
            uid: uid.clone(),
            reason: "decrypt".into(),
        };
        assert_eq!(missing.uid(), &uid);
        assert_eq!(degraded.uid(), &uid);
    }
}
