//! Happy-path JSON DTOs for the Proton Drive API.
//!
//! Anti-corruption layer (domain-model.md §4): the domain types in
//! `proton-drive-core` never see these wire structs. Translators live next
//! to the call sites that issue HTTP requests.
//!
//! **Coverage**: only the endpoints needed for list/upload/download/events.
//! The full OpenAPI surface (40K LoC in JS) is out of scope until proven
//! necessary.
//!
//! Field names use Proton's `PascalCase` convention — preserved via `serde
//! rename_all` so debugging captured traffic stays readable.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod common {
    use super::*;

    /// Standard envelope of Proton API responses.
    #[derive(Debug, Clone, Deserialize)]
    pub struct ResponseEnvelope<T> {
        #[serde(rename = "Code")]
        pub code: u32,
        #[serde(flatten)]
        pub inner: T,
        #[serde(default)]
        #[serde(rename = "Error")]
        pub error: Option<String>,
    }

    pub const CODE_OK: u32 = 1000;
}

pub mod user {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetUserResponse {
        pub user: User,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct User {
        #[serde(rename = "ID")]
        pub id: String,
        pub name: String,
        pub email: String,
        pub keys: Vec<UserKey>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct UserKey {
        #[serde(rename = "ID")]
        pub id: String,
        pub primary: u8,
        pub private_key: String,
    }
}

pub mod shares {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetShareResponse {
        pub share: Share,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Share {
        #[serde(rename = "ShareID")]
        pub share_id: String,
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
        #[serde(rename = "LinkID")]
        pub link_id: String,
        pub r#type: u8,
        pub key: String,
        pub passphrase: String,
        pub passphrase_signature: String,
        pub address_id: String,
        pub address_key_id: String,
    }
}

pub mod nodes {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetLinkResponse {
        pub link: Link,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetChildrenResponse {
        pub links: Vec<Link>,
    }

    /// A link is Proton's wire name for what the domain calls a Node.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Link {
        #[serde(rename = "LinkID")]
        pub link_id: String,
        #[serde(rename = "ParentLinkID")]
        pub parent_link_id: Option<String>,
        pub r#type: u8, // 1 = folder, 2 = file
        pub name: String,
        pub name_signature_email: Option<String>,
        pub hash: String,
        #[serde(rename = "MIMEType")]
        pub mime_type: String,
        pub state: u8, // 1 = active, 2 = trashed, 3 = deleted
        pub size: u64,
        pub created_time: i64,
        pub modify_time: i64,
        pub trashed: Option<i64>,
        pub node_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub signature_email: Option<String>,
        #[serde(default)]
        pub file_properties: Option<FileProperties>,
        #[serde(default)]
        pub folder_properties: Option<FolderProperties>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FileProperties {
        pub content_key_packet: String,
        pub content_key_packet_signature: Option<String>,
        pub active_revision: Option<Revision>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FolderProperties {
        pub node_hash_key: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Revision {
        #[serde(rename = "ID")]
        pub id: String,
        pub state: u8,
        pub created_time: i64,
        pub size: u64,
        pub manifest_signature: Option<String>,
        pub signature_email: Option<String>,
    }
}

pub mod upload {
    use super::*;

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateFileRequest {
        pub name: String,
        pub hash: String,
        pub parent_link_id: String,
        pub node_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub signature_address: String,
        pub content_key_packet: String,
        pub content_key_packet_signature: String,
        pub mime_type: String,
        pub client_uid: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreateFileResponse {
        pub file: CreatedFile,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CreatedFile {
        #[serde(rename = "ID")]
        pub link_id: String,
        #[serde(rename = "RevisionID")]
        pub revision_id: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RequestBlockUploadRequest {
        pub block_list: Vec<BlockUploadEntry>,
        pub address_id: String,
        #[serde(rename = "LinkID")]
        pub link_id: String,
        #[serde(rename = "RevisionID")]
        pub revision_id: String,
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockUploadEntry {
        pub index: u32,
        pub hash: String,
        pub encrypted_signature: String,
        pub size: u64,
        pub verifier: BlockVerifier,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockVerifier {
        pub token: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RequestBlockUploadResponse {
        pub upload_links: Vec<UploadLink>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct UploadLink {
        pub index: u32,
        pub bare_url: String,
        pub token: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CommitRevisionRequest {
        pub manifest_signature: String,
        pub signature_address: String,
        pub extended_attributes: Option<String>,
    }
}

pub mod download {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetRevisionResponse {
        pub revision: RevisionWithBlocks,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RevisionWithBlocks {
        #[serde(rename = "ID")]
        pub id: String,
        pub blocks: Vec<Block>,
        pub manifest_signature: Option<String>,
        pub signature_email: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Block {
        pub index: u32,
        pub bare_url: String,
        pub token: String,
        pub hash: String,
        pub encrypted_signature: Option<String>,
        pub size: u64,
    }
}

pub mod events {
    use super::*;

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetLatestEventIdResponse {
        #[serde(rename = "EventID")]
        pub event_id: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetEventsResponse {
        #[serde(rename = "EventID")]
        pub event_id: String,
        pub events: Vec<EventEntry>,
        pub more: u8,
        pub refresh: u8,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct EventEntry {
        #[serde(rename = "EventID")]
        pub event_id: String,
        pub event_type: u8, // 0 delete, 1 create, 2 update, 3 update_metadata
        pub created_time: i64,
        #[serde(default)]
        pub link: Option<super::nodes::Link>,
    }
}

pub mod auth {
    use super::*;

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthInfoRequest {
        pub username: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthInfoResponse {
        pub version: u32,
        pub modulus: String,
        pub server_ephemeral: String,
        pub salt: String,
        #[serde(rename = "SRPSession")]
        pub srp_session: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthRequest {
        pub username: String,
        pub client_ephemeral: String,
        pub client_proof: String,
        #[serde(rename = "SRPSession")]
        pub srp_session: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AuthResponse {
        #[serde(rename = "UID")]
        pub uid: String,
        pub access_token: String,
        pub refresh_token: String,
        pub server_proof: String,
        // Proton returns LocalID (int) on some API versions and omits or nulls UserID.
        #[serde(rename = "UserID", default, deserialize_with = "null_to_empty")]
        pub user_id: String,
        #[serde(rename = "2FA", default)]
        pub two_factor: TwoFactor,
    }

    fn null_to_empty<'de, D>(d: D) -> Result<String, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
    }

    #[derive(Debug, Clone, Deserialize, Default)]
    #[serde(rename_all = "PascalCase")]
    pub struct TwoFactor {
        pub enabled: u32,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RefreshRequest {
        pub response_type: String,
        pub grant_type: String,
        pub refresh_token: String,
        pub redirect_uri: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RefreshResponse {
        #[serde(rename = "UID")]
        pub uid: String,
        pub access_token: String,
        pub refresh_token: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct KeySaltsResponse {
        pub key_salts: Vec<KeySalt>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct KeySalt {
        #[serde(rename = "ID")]
        pub id: String,
        // Proton returns null for keys that have no passphrase (e.g. hardware keys).
        #[serde(default, deserialize_with = "null_to_empty")]
        pub key_salt: String,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_get_user_envelope() {
        let body = r#"{
            "Code": 1000,
            "User": {
                "ID": "u1",
                "Name": "alice",
                "Email": "alice@proton.me",
                "Keys": [{ "ID": "k1", "Primary": 1, "PrivateKey": "-----BEGIN PGP----- ..." }]
            }
        }"#;
        let env: common::ResponseEnvelope<user::GetUserResponse> =
            serde_json::from_str(body).expect("parse");
        assert_eq!(env.code, common::CODE_OK);
        assert_eq!(env.inner.user.email, "alice@proton.me");
        assert_eq!(env.inner.user.keys.len(), 1);
    }

    #[test]
    fn deserialize_children_response() {
        let body = r#"{
            "Links": [{
                "LinkID": "l1", "ParentLinkID": "root",
                "Type": 1, "Name": "encrypted-name", "Hash": "hex",
                "MIMEType": "Folder", "State": 1, "Size": 0,
                "CreatedTime": 1, "ModifyTime": 2,
                "NodeKey": "armored", "NodePassphrase": "armored",
                "NodePassphraseSignature": "armored",
                "FolderProperties": { "NodeHashKey": "armored" }
            }]
        }"#;
        let resp: nodes::GetChildrenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.links.len(), 1);
        assert_eq!(resp.links[0].r#type, 1);
        assert!(resp.links[0].folder_properties.is_some());
    }
}
