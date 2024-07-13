use core::convert::TryInto;

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use serde_jcs;
use thiserror::Error;

use crate::{common::runtime::multihash, keyring::jwk::Jwk};

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,

    #[serde(rename = "description")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DidPublicKey {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "controller")]
    pub controller: String,

    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: Jwk,
}

#[derive(Debug, Serialize, Deserialize)]
struct Authentication {
    #[serde(rename = "type")]
    r#type: String,

    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DIDDocument {
    // TODO: impl parser for mixed type
    // #[serde(rename = "@context")]
    // context: String,
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "publicKey")]
    pub public_key: Option<Vec<DidPublicKey>>,

    #[serde(rename = "service")]
    pub service: Option<Vec<ServiceEndpoint>>,

    // TODO: impl parser for mixed type
    #[serde(rename = "authentication")]
    pub authentication: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyPayload {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "jwk")]
    pub jwk: Jwk,

    #[serde(rename = "purpose")]
    pub purpose: Vec<String>,
}

pub trait ToPublicKey<T: TryInto<Jwk>> {
    fn to_public_key(
        self,
        key_type: String,
        key_id: String,
        purpose: Vec<String>,
    ) -> Result<PublicKeyPayload, T::Error>;
}

impl<T> ToPublicKey<T> for T
where
    T: TryInto<Jwk>,
{
    fn to_public_key(
        self,
        key_type: String,
        key_id: String,
        purpose: Vec<String>,
    ) -> Result<PublicKeyPayload, T::Error> {
        let jwk: Jwk = self.try_into()?;
        Ok(PublicKeyPayload { id: key_id.into(), r#type: key_type.into(), jwk, purpose })
    }
}

// ACTION: replace
#[derive(Debug, Serialize, Deserialize)]
pub struct DIDReplacePayload {
    #[serde(rename = "public_keys")]
    pub public_keys: Vec<PublicKeyPayload>,

    #[serde(rename = "service_endpoints")]
    pub service_endpoints: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DIDReplaceAction {
    action: String, // 'replace',
    document: DIDReplacePayload,
}

#[derive(Serialize, Deserialize, Debug)]
struct DIDReplaceDeltaObject {
    patches: Vec<DIDReplaceAction>,
    update_commitment: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DIDReplaceSuffixObject {
    delta_hash: String,
    recovery_commitment: String,
}

// ACTION: ietf-json-patch
#[allow(dead_code)]
struct DIDIetfJsonPatchAction {
    action: String, /* 'replace',
                     * patches: Vec<> */
}

#[allow(dead_code)]
struct DIDResolutionRequest {
    did: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MethodMetadata {
    #[serde(rename = "published")]
    pub published: bool,

    #[serde(rename = "recoveryCommitment")]
    pub recovery_commitment: Option<String>,

    #[serde(rename = "updateCommitment")]
    pub update_commitment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DIDResolutionResponse {
    #[serde(rename = "@context")]
    pub context: String,

    #[serde(rename = "didDocument")]
    pub did_document: DIDDocument,

    #[serde(rename = "methodMetadata")]
    pub method_metadata: MethodMetadata,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CommitmentKeys {
    #[serde(rename = "recovery")]
    pub recovery: Jwk,

    #[serde(rename = "update")]
    pub update: Jwk,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DIDCreateRequest {
    #[serde(rename = "publicKeys")]
    pub public_keys: Vec<PublicKeyPayload>,

    #[serde(rename = "commitmentKeys")]
    pub commitment_keys: CommitmentKeys,

    #[serde(rename = "serviceEndpoints")]
    pub service_endpoints: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DIDCreatePayload {
    r#type: String, // 'create',
    delta: String,
    suffix_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DIDCreateResponse {
    #[serde(rename = "@context")]
    pub context: String,

    #[serde(rename = "didDocument")]
    pub did_document: DIDDocument,

    #[serde(rename = "methodMetadata")]
    pub method_metadata: MethodMetadata,
}

#[derive(Debug, Error)]
pub enum DIDCreatePayloadError {
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),
}

#[inline]
fn canon<T>(value: &T) -> Result<Vec<u8>, serde_json::Error>
where
    T: ?Sized + Serialize,
{
    Ok(serde_jcs::to_string(value)?.into_bytes())
}

pub fn did_create_payload(
    replace_payload: DIDReplacePayload,
    update_key: &Jwk,
    recovery_key: &Jwk,
) -> Result<String, DIDCreatePayloadError> {
    let update = canon(update_key)?;
    let update_commitment = multihash::double_hash_encode(&update);
    let recovery = canon(recovery_key)?;
    let recovery_commitment = multihash::double_hash_encode(&recovery);
    let patch = DIDReplaceAction { action: "replace".to_string(), document: replace_payload };
    let delta = DIDReplaceDeltaObject { patches: vec![patch], update_commitment };
    let delta = canon(&delta)?;
    let delta_hash = multihash::hash_encode(&delta);

    let suffix = DIDReplaceSuffixObject { delta_hash, recovery_commitment };
    let suffix = canon(&suffix)?;
    let encoded_delta = BASE64URL_NOPAD.encode(&delta);
    let encoded_suffix = BASE64URL_NOPAD.encode(&suffix);

    let payload = DIDCreatePayload {
        r#type: "create".to_string(),
        delta: encoded_delta,
        suffix_data: encoded_suffix,
    };

    Ok(serde_jcs::to_string(&payload)?)
}

#[cfg(test)]
pub mod tests {
    use rand_core::OsRng;

    use super::*;
    use crate::{keyring, keyring::keypair::KeyPair};

    #[test]
    pub fn test_did_create_payload() {
        let keyring = keyring::keypair::KeyPairing::create_keyring(OsRng);
        let public = keyring
            .sign
            .get_public_key()
            .to_public_key("".to_string(), "key_id".to_string(), vec!["".to_string()])
            .unwrap();
        let update: Jwk = keyring.recovery.get_public_key().try_into().unwrap();
        let recovery: Jwk = keyring.update.get_public_key().try_into().unwrap();

        let document = DIDReplacePayload { public_keys: vec![public], service_endpoints: vec![] };

        let _result = did_create_payload(document, &update, &recovery).unwrap();
    }
}
