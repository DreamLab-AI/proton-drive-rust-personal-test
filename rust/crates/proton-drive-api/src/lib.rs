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
        /// On modern accounts the user key is locked with a per-key passphrase
        /// stored in this Token (armored PGP message encrypted to another key).
        /// `None` on legacy accounts where key_password unlocks directly.
        #[serde(default)]
        pub token: Option<String>,
    }
}

pub mod addresses {
    use super::*;

    /// Response from `GET /core/v4/addresses`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetAddressesResponse {
        pub addresses: Vec<Address>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Address {
        #[serde(rename = "ID")]
        pub id: String,
        pub email: String,
        /// Sort order — the primary address has the lowest value.
        pub order: u32,
        pub keys: Vec<AddressKey>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct AddressKey {
        #[serde(rename = "ID")]
        pub id: String,
        pub primary: u8,
        pub private_key: String,
        /// Armored PGP message: the address-key passphrase encrypted to one of
        /// the user's keys. Absent for some legacy key layouts.
        #[serde(default)]
        pub token: Option<String>,
    }
}

pub mod shares {
    use super::*;

    /// Response from `GET drive/v2/shares/my-files`.
    ///
    /// Mirrors `PrimaryRootShareResponseDto` in driveTypes.ts.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetMyFilesResponse {
        pub volume: MyFilesVolume,
        pub share: MyFilesShare,
        /// Root link wrapped as FolderDetailsDto — outer field is "Link".
        pub link: MyFilesRootLink,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct MyFilesVolume {
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct MyFilesShare {
        #[serde(rename = "ShareID")]
        pub share_id: String,
        pub creator_email: Option<String>,
        pub key: String,
        pub passphrase: String,
        pub passphrase_signature: String,
        #[serde(rename = "AddressID")]
        pub address_id: String,
    }

    /// Outer "FolderDetailsDto" wrapper — `Link` field holds the actual LinkDto.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct MyFilesRootLink {
        pub link: super::nodes::Link,
    }

    /// `GET drive/shares/{shareID}` returns the share fields **flat** at the
    /// envelope level (not wrapped in a `Share` object). `#[serde(flatten)]`
    /// reproduces the wire shape while keeping the `.share` accessor for callers.
    #[derive(Debug, Clone, Deserialize)]
    pub struct GetShareResponse {
        #[serde(flatten)]
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
        #[serde(rename = "AddressID")]
        pub address_id: String,
        /// Not present on all share responses (the flat `drive/shares/{id}`
        /// payload omits it); only meaningful for shares with direct access.
        #[serde(rename = "AddressKeyID", default)]
        pub address_key_id: Option<String>,
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
        /// Non-zero means more pages exist; fetch with next `Page` index.
        #[serde(default)]
        pub more: u8,
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
        /// Name hash. Nullable on the wire (e.g. some folder layouts).
        #[serde(default)]
        pub hash: Option<String>,
        #[serde(rename = "MIMEType")]
        pub mime_type: String,
        pub state: u8, // 1 = active, 2 = trashed, 3 = deleted
        pub size: u64,
        /// Proton's field is `CreateTime` (not `CreatedTime`); `CreationTime`
        /// is a deprecated alias. Required on link responses.
        #[serde(rename = "CreateTime")]
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
        /// Optional on the wire (`ContentKeyPacket?`).
        #[serde(default)]
        pub content_key_packet: Option<String>,
        pub content_key_packet_signature: Option<String>,
        pub active_revision: Option<Revision>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct FolderProperties {
        /// Optional on the wire (`NodeHashKey?`); needed to compute the HMAC
        /// name hash when this folder is an upload parent.
        #[serde(default)]
        pub node_hash_key: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Revision {
        #[serde(rename = "ID", default)]
        pub id: String,
        #[serde(default)]
        pub state: u8,
        /// Proton's field is `CreateTime`; optional within `ActiveRevision`.
        #[serde(rename = "CreateTime", default)]
        pub created_time: i64,
        #[serde(default)]
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
        #[serde(rename = "ParentLinkID")]
        pub parent_link_id: String,
        #[serde(rename = "MIMEType")]
        pub mime_type: String,
        #[serde(rename = "ClientUID")]
        pub client_uid: Option<String>,
        /// Coarse size hint for early quota validation; sent as `null` when
        /// unknown (the server re-validates during commit).
        pub intended_upload_size: Option<u64>,
        pub node_key: String,
        pub node_passphrase: String,
        pub node_passphrase_signature: String,
        pub content_key_packet: String,
        pub content_key_packet_signature: String,
        pub signature_address: String,
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
        #[serde(rename = "AddressID")]
        pub address_id: String,
        #[serde(rename = "VolumeID")]
        pub volume_id: String,
        #[serde(rename = "LinkID")]
        pub link_id: String,
        #[serde(rename = "RevisionID")]
        pub revision_id: String,
        pub block_list: Vec<BlockUploadEntry>,
        /// Always sent (empty for non-thumbnail uploads) to match the JS client.
        pub thumbnail_list: Vec<ThumbnailUploadEntry>,
    }

    /// `Index` + `EncSignature` + `Verifier` only — Proton ignores client-sent
    /// `Hash`/`Size` for content blocks (the JS client omits them), so they are
    /// not part of this struct.
    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockUploadEntry {
        pub index: u32,
        #[serde(rename = "EncSignature")]
        pub enc_signature: String,
        pub verifier: BlockVerifier,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ThumbnailUploadEntry {
        pub r#type: u8,
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
        #[serde(rename = "BareURL")]
        pub bare_url: String,
        pub token: String,
    }

    #[derive(Debug, Clone, Serialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct CommitRevisionRequest {
        pub manifest_signature: String,
        pub signature_address: String,
        /// Encrypted extended attributes — Proton's field is `XAttr`.
        #[serde(rename = "XAttr")]
        pub x_attr: String,
        /// Whether the client verified the content checksum during upload.
        pub checksum_verified: bool,
        /// Only used for photos in the Photo volume; always `null` here.
        pub photo: Option<serde_json::Value>,
    }
}

pub mod download {
    use super::*;

    /// Response from `GET drive/v2/volumes/{VolumeID}/files/{linkID}/revisions/{revisionID}`.
    ///
    /// Mirrors `GetRevisionResponse` in `js/sdk/src/internal/download/apiService.ts`.
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct GetRevisionResponse {
        #[serde(rename = "Revision")]
        pub revision: RevisionWithBlocks,
    }

    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct RevisionWithBlocks {
        #[serde(rename = "ID")]
        pub id: String,
        /// Revision state: 1 = active, 2 = draft, 3 = superseded.
        pub state: Option<u8>,
        pub blocks: Vec<BlockResponse>,
        pub manifest_signature: Option<String>,
        /// Armored PKESK packet: wraps the content session key for the node key.
        pub content_key_packet: Option<String>,
        pub content_key_packet_signature: Option<String>,
        /// Encrypted extended attributes (modification time, size, SHA1 digest).
        /// May be absent for legacy revisions.
        pub x_attr: Option<String>,
        /// Email of the address that signed this revision's content.
        pub signature_email: Option<String>,
    }

    /// A single block within a revision.
    ///
    /// `Hash` is the base64-encoded SHA-256 of the **ciphertext** (not plaintext).
    /// As noted in `domain-model-mvp.md`: "Hash is sha256 of ciphertext, not plaintext."
    #[derive(Debug, Clone, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct BlockResponse {
        /// 1-based block index within the revision.
        pub index: u32,
        /// Opaque CDN URL — treated as a blob, never parsed (domain-model anti-corruption rule).
        /// The API uses uppercase "URL" suffix, not "Url".
        #[serde(rename = "BareURL")]
        pub bare_url: String,
        /// Bearer token for the `Authorization` header when fetching `bare_url`.
        pub token: String,
        /// Base64-encoded SHA-256 of the ciphertext bytes.
        pub hash: String,
        /// Encrypted detached signature for this block — Proton's field is
        /// `EncSignature` (optional for legacy revisions).
        #[serde(rename = "EncSignature", default)]
        pub encrypted_signature: Option<String>,
        /// Ciphertext size in bytes.
        #[serde(default)]
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
                "CreateTime": 1, "ModifyTime": 2,
                "NodeKey": "armored", "NodePassphrase": "armored",
                "NodePassphraseSignature": "armored",
                "FolderProperties": { "NodeHashKey": "armored" }
            }],
            "More": 0
        }"#;
        let resp: nodes::GetChildrenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.links.len(), 1);
        assert_eq!(resp.links[0].r#type, 1);
        assert!(resp.links[0].folder_properties.is_some());
        assert_eq!(resp.more, 0);
    }

    #[test]
    fn deserialize_children_response_with_pagination() {
        // Realistic JSON matching the v1 children endpoint shape.
        // Includes a file node (Type=2) with FileProperties, an active revision,
        // and More=1 indicating a second page exists.
        let body = r#"{
            "Code": 1000,
            "Links": [
                {
                    "LinkID": "folder-link-1",
                    "ParentLinkID": "root-link",
                    "Type": 1,
                    "Name": "yyMwuB1jJ2jGlHbzT3bxpgKQaVWpzlEn4R6B5X0cOiU=",
                    "Hash": "abc123hash",
                    "MIMEType": "Folder",
                    "State": 1,
                    "Size": 0,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000100,
                    "NodeKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\\nabc\\n-----END PGP PUBLIC KEY BLOCK-----",
                    "NodePassphrase": "-----BEGIN PGP MESSAGE-----\\ndef\\n-----END PGP MESSAGE-----",
                    "NodePassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\nghi\\n-----END PGP SIGNATURE-----",
                    "FolderProperties": { "NodeHashKey": "-----BEGIN PGP MESSAGE-----\\njkl\\n-----END PGP MESSAGE-----" }
                },
                {
                    "LinkID": "file-link-1",
                    "ParentLinkID": "root-link",
                    "Type": 2,
                    "Name": "zzEncryptedFileName==",
                    "Hash": "def456hash",
                    "MIMEType": "text/plain",
                    "State": 1,
                    "Size": 1234,
                    "CreateTime": 1700001000,
                    "ModifyTime": 1700001100,
                    "NodeKey": "-----BEGIN PGP PUBLIC KEY BLOCK-----\\nxyz\\n-----END PGP PUBLIC KEY BLOCK-----",
                    "NodePassphrase": "-----BEGIN PGP MESSAGE-----\\nuvw\\n-----END PGP MESSAGE-----",
                    "NodePassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\nrst\\n-----END PGP SIGNATURE-----",
                    "FileProperties": {
                        "ContentKeyPacket": "-----BEGIN PGP MESSAGE-----\\ncontent\\n-----END PGP MESSAGE-----",
                        "ContentKeyPacketSignature": "-----BEGIN PGP SIGNATURE-----\\ncontentsig\\n-----END PGP SIGNATURE-----",
                        "ActiveRevision": {
                            "ID": "rev-1",
                            "State": 1,
                            "CreateTime": 1700001050,
                            "Size": 1234
                        }
                    }
                }
            ],
            "More": 1
        }"#;
        let resp: nodes::GetChildrenResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.links.len(), 2, "expected 2 links");
        assert_eq!(resp.more, 1, "More flag should indicate another page");

        let folder = &resp.links[0];
        assert_eq!(folder.link_id, "folder-link-1");
        assert_eq!(folder.r#type, 1);
        assert!(folder.folder_properties.is_some());
        assert!(folder.file_properties.is_none());

        let file = &resp.links[1];
        assert_eq!(file.link_id, "file-link-1");
        assert_eq!(file.r#type, 2);
        assert!(file.file_properties.is_some());
        let fp = file.file_properties.as_ref().unwrap();
        assert!(fp.active_revision.is_some());
        assert_eq!(fp.active_revision.as_ref().unwrap().id, "rev-1");
    }

    #[test]
    fn deserialize_my_files_response() {
        // Mirrors PrimaryRootShareResponseDto shape.
        let body = r#"{
            "Code": 1000,
            "Volume": { "VolumeID": "vol-abc123" },
            "Share": {
                "ShareID": "share-xyz789",
                "CreatorEmail": "alice@proton.me",
                "Key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nsharekey\\n-----END PGP PRIVATE KEY BLOCK-----",
                "Passphrase": "-----BEGIN PGP MESSAGE-----\\npassphrase\\n-----END PGP MESSAGE-----",
                "PassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\npasssig\\n-----END PGP SIGNATURE-----",
                "AddressID": "addr-001"
            },
            "Link": {
                "Link": {
                    "LinkID": "root-link-001",
                    "Type": 1,
                    "Name": "EncryptedRootName==",
                    "Hash": "roothash",
                    "MIMEType": "Folder",
                    "State": 1,
                    "Size": 0,
                    "CreateTime": 1700000000,
                    "ModifyTime": 1700000001,
                    "NodeKey": "rootnodekey",
                    "NodePassphrase": "rootpassphrase",
                    "NodePassphraseSignature": "rootpasssig"
                }
            }
        }"#;
        let resp: shares::GetMyFilesResponse = serde_json::from_str(body).expect("parse");
        assert_eq!(resp.volume.volume_id, "vol-abc123");
        assert_eq!(resp.share.share_id, "share-xyz789");
        assert_eq!(resp.share.address_id, "addr-001");
        assert_eq!(resp.link.link.link_id, "root-link-001");
        assert_eq!(resp.link.link.r#type, 1);
    }

    /// `GET drive/shares/{shareID}` returns share fields **flat** at the
    /// top level (no `Share` wrapper). `#[serde(flatten)]` must reproduce
    /// this while keeping the `.share` accessor, and `AddressKeyID` must
    /// tolerate absence (the flat payload omits it).
    #[test]
    fn deserialize_flat_get_share_response() {
        let body = r#"{
            "Code": 1000,
            "ShareID": "share-flat-1",
            "VolumeID": "vol-flat-1",
            "LinkID": "link-flat-1",
            "Type": 1,
            "Key": "-----BEGIN PGP PRIVATE KEY BLOCK-----\\nk\\n-----END PGP PRIVATE KEY BLOCK-----",
            "Passphrase": "-----BEGIN PGP MESSAGE-----\\np\\n-----END PGP MESSAGE-----",
            "PassphraseSignature": "-----BEGIN PGP SIGNATURE-----\\ns\\n-----END PGP SIGNATURE-----",
            "AddressID": "addr-flat-1"
        }"#;
        let env: common::ResponseEnvelope<shares::GetShareResponse> =
            serde_json::from_str(body).expect("parse flat share");
        assert_eq!(env.code, common::CODE_OK);
        let s = &env.inner.share;
        assert_eq!(s.share_id, "share-flat-1");
        assert_eq!(s.volume_id, "vol-flat-1");
        assert_eq!(s.link_id, "link-flat-1");
        assert_eq!(s.address_id, "addr-flat-1");
        assert!(
            s.address_key_id.is_none(),
            "flat payload omits AddressKeyID"
        );
    }

    /// `ActiveRevision` carries `CreateTime` (not `CreatedTime`); the rename
    /// must map it onto `created_time`. A fabricated `CreatedTime` fixture
    /// would silently default to 0 — guard against that regression.
    #[test]
    fn revision_uses_create_time_field() {
        let body = r#"{
            "ID": "rev-9",
            "State": 1,
            "CreateTime": 1700009999,
            "Size": 42
        }"#;
        let rev: nodes::Revision = serde_json::from_str(body).expect("parse revision");
        assert_eq!(
            rev.created_time, 1700009999,
            "CreateTime must map to created_time"
        );
        assert_eq!(rev.size, 42);
    }

    /// Upload create request must emit Proton's exact PascalCase keys, send
    /// `IntendedUploadSize: null` when unknown, and key the client identifier
    /// as `ClientUID` (uppercase UID).
    #[test]
    fn serialize_create_file_request_shape() {
        let req = upload::CreateFileRequest {
            name: "enc-name".into(),
            hash: "namehash".into(),
            parent_link_id: "parent-1".into(),
            mime_type: "text/plain".into(),
            client_uid: None,
            intended_upload_size: None,
            node_key: "nk".into(),
            node_passphrase: "np".into(),
            node_passphrase_signature: "nps".into(),
            content_key_packet: "ckp".into(),
            content_key_packet_signature: "ckps".into(),
            signature_address: "sig@addr".into(),
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(
            obj.contains_key("MIMEType"),
            "must use MIMEType, not MimeType"
        );
        assert!(
            obj.contains_key("ClientUID"),
            "must use ClientUID, not ClientUid"
        );
        assert!(obj.contains_key("ParentLinkID"));
        assert!(obj.contains_key("IntendedUploadSize"));
        assert!(
            obj["IntendedUploadSize"].is_null(),
            "unknown size sent as null"
        );
        assert!(obj["ClientUID"].is_null());
        assert_eq!(obj["Hash"], "namehash");
    }

    /// Content block entries carry only Index/EncSignature/Verifier — Proton
    /// ignores client-sent Hash/Size, and the JS client omits them, so they
    /// must NOT appear on the wire.
    #[test]
    fn serialize_block_upload_entry_omits_hash_and_size() {
        let entry = upload::BlockUploadEntry {
            index: 1,
            enc_signature: "encsig".into(),
            verifier: upload::BlockVerifier {
                token: "tok".into(),
            },
        };
        let v = serde_json::to_value(&entry).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("Index"));
        assert!(obj.contains_key("EncSignature"));
        assert!(obj.contains_key("Verifier"));
        assert!(
            !obj.contains_key("Hash"),
            "Hash must not be sent for content blocks"
        );
        assert!(
            !obj.contains_key("Size"),
            "Size must not be sent for content blocks"
        );
        assert_eq!(obj["Verifier"]["Token"], "tok");
    }

    /// Commit request uses `XAttr` (not `XAttribute`), `ChecksumVerified`,
    /// and a `Photo` field that serializes to null for non-photo uploads.
    #[test]
    fn serialize_commit_revision_request_shape() {
        let req = upload::CommitRevisionRequest {
            manifest_signature: "msig".into(),
            signature_address: "sig@addr".into(),
            x_attr: "encrypted-xattr".into(),
            checksum_verified: true,
            photo: None,
        };
        let v = serde_json::to_value(&req).expect("serialize");
        let obj = v.as_object().expect("object");
        assert!(obj.contains_key("XAttr"), "must use XAttr key");
        assert!(obj.contains_key("ChecksumVerified"));
        assert!(obj.contains_key("Photo"));
        assert!(obj["Photo"].is_null(), "non-photo upload sends Photo: null");
        assert_eq!(obj["ChecksumVerified"], true);
    }
}
