use std::convert::TryInto;

use http::StatusCode;

use super::sidetree::{
    client::SidetreeHttpClient,
    payload::{
        did_create_payload, DidDocument, DidReplacePayload, DidResolutionResponse, ToPublicKey,
    },
};
use crate::keyring::{
    jwk::Jwk,
    keypair::{KeyPair, KeyPairing},
};

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentifierError<StudioClientError: std::error::Error> {
    #[error("Failed to convert to JWK")]
    JwkError,
    #[error("Failed to build operation payload: {0}")]
    PayloadBuildFailed(#[from] crate::did::sidetree::payload::DidCreatePayloadError),
    #[error("Failed to parse body: {0}")]
    BodyParseError(#[from] serde_json::Error),
    #[error("Failed to create identifier. response: {0}")]
    SidetreeRequestFailed(String),
    #[error("Failed to send request: {0}")]
    SidetreeHttpClientError(StudioClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum FindIdentifierError<StudioClientError: std::error::Error> {
    #[error("Failed to send request to sidetree: {0}")]
    SidetreeRequestFailed(String),
    #[error("Failed to parse body: {0}")]
    BodyParseError(#[from] serde_json::Error),
    #[error("Failed to send request: {0}")]
    SidetreeHttpClientError(StudioClientError),
}

#[derive(Debug, thiserror::Error)]
pub enum GetPublicKeyError {
    #[error("Failed to get public key")]
    PublicKeyNotFound(String),
    #[error("Failed to convert from JWK: {0}")]
    JwkToK256Error(#[from] crate::keyring::jwk::JwkToK256Error),
    #[error("Failed to convert from JWK: {0}")]
    JwkToX25519Error(#[from] crate::keyring::jwk::JwkToX25519Error),
}

fn get_key(key_type: &str, did_document: &DidDocument) -> Result<Jwk, GetPublicKeyError> {
    let did = &did_document.id;
    let public_key = did_document
        .public_key
        .clone()
        .and_then(|pks| pks.into_iter().find(|pk| pk.id == key_type))
        .ok_or(GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
    Ok(public_key.public_key_jwk)
}

pub fn get_sign_key(did_document: &DidDocument) -> Result<k256::PublicKey, GetPublicKeyError> {
    let public_key = get_key("signingKey", &did_document)?;
    Ok(public_key.try_into()?)
}

pub fn get_encrypt_key(
    did_document: &DidDocument,
) -> Result<x25519_dalek::PublicKey, GetPublicKeyError> {
    let public_key = get_key("encryptionKey", &did_document)?;
    Ok(public_key.try_into()?)
}

#[async_trait::async_trait]
pub trait DidRepository: Sync {
    type CreateIdentifierError: std::error::Error + Send + Sync;
    type FindIdentifierError: std::error::Error + Send + Sync;
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DidResolutionResponse, Self::CreateIdentifierError>;
    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError>;
}

pub struct DidRepositoryImpl<C: SidetreeHttpClient + Send + Sync> {
    client: C,
}

impl<C> Clone for DidRepositoryImpl<C>
where
    C: SidetreeHttpClient + Send + Sync + Clone,
{
    fn clone(&self) -> Self {
        Self { client: self.client.clone() }
    }
}

impl<C: SidetreeHttpClient + Send + Sync> DidRepositoryImpl<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }
}

#[async_trait::async_trait]
impl<C: SidetreeHttpClient + Send + Sync> DidRepository for DidRepositoryImpl<C> {
    type CreateIdentifierError = CreateIdentifierError<C::Error>;
    type FindIdentifierError = FindIdentifierError<C::Error>;
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DidResolutionResponse, CreateIdentifierError<C::Error>> {
        // https://w3c.github.io/did-spec-registries/#assertionmethod
        let sign = keyring
            .sign
            .get_public_key()
            .to_public_key(
                "EcdsaSecp256k1VerificationKey2019".to_string(),
                "signingKey".to_string(),
                vec!["auth".to_string(), "general".to_string()]
                // TODO: This purpose property is strange...
                // https://identity.foundation/sidetree/spec/#add-public-keys
                // vec!["assertionMethod".to_string()],
            )
            .map_err(|_| CreateIdentifierError::JwkError)?;
        let enc = keyring
            .encrypt
            .get_public_key()
            .to_public_key(
                "X25519KeyAgreementKey2019".to_string(),
                "encryptionKey".to_string(),
                vec!["auth".to_string(), "general".to_string()]
                // TODO: This purpose property is strange...
                // https://identity.foundation/sidetree/spec/#add-public-keys
                // vec!["keyAgreement".to_string()]
            )
            .map_err(|_| CreateIdentifierError::JwkError)?;
        let update: Jwk = keyring
            .update
            .get_public_key()
            .try_into()
            .map_err(|_| CreateIdentifierError::JwkError)?;
        let recovery: Jwk = keyring
            .recovery
            .get_public_key()
            .try_into()
            .map_err(|_| CreateIdentifierError::JwkError)?;
        let document =
            DidReplacePayload { public_keys: vec![sign, enc], service_endpoints: vec![] };
        let payload = did_create_payload(document, &update, &recovery)?;

        let response = self
            .client
            .post_create_identifier(&payload)
            .await
            .map_err(CreateIdentifierError::SidetreeHttpClientError)?;
        if response.status_code.is_success() {
            let response = serde_json::from_str(&response.body)?;
            Ok(response)
        } else {
            Err(CreateIdentifierError::SidetreeRequestFailed(format!("{:?}", response)))
        }
    }

    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DidResolutionResponse>, FindIdentifierError<C::Error>> {
        let response = self
            .client
            .get_find_identifier(did)
            .await
            .map_err(FindIdentifierError::SidetreeHttpClientError)?;

        match response.status_code {
            StatusCode::OK => Ok(Some(serde_json::from_str(&response.body)?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(FindIdentifierError::SidetreeRequestFailed(format!("{:?}", response))),
        }
    }
}

#[cfg(test)]
pub mod mocks {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        did::sidetree::payload::{DidDocument, DidPublicKey, MethodMetadata},
        keyring::keypair::KeyPairing,
    };

    #[derive(Clone)]
    pub struct MockDidRepository {
        map: BTreeMap<String, Vec<KeyPairing>>,
    }

    impl MockDidRepository {
        pub fn from_single(map: BTreeMap<String, KeyPairing>) -> Self {
            Self { map: map.into_iter().map(|(k, v)| (k, vec![v])).collect() }
        }

        pub fn new(map: BTreeMap<String, Vec<KeyPairing>>) -> Self {
            Self { map }
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DummyError {}

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        type CreateIdentifierError = CreateIdentifierError<DummyError>;
        type FindIdentifierError = FindIdentifierError<DummyError>;
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DidResolutionResponse, Self::CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError> {
            if let Some(keyrings) = self.map.get(did) {
                let public_keys = keyrings
                    .iter()
                    .flat_map(|keyring| {
                        vec![
                            DidPublicKey {
                                id: "signingKey".to_string(),
                                controller: String::new(),
                                r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                                public_key_jwk: keyring.sign.get_public_key().try_into().unwrap(),
                            },
                            DidPublicKey {
                                id: "encryptionKey".to_string(),
                                controller: String::new(),
                                r#type: "X25519KeyAgreementKey2019".to_string(),
                                public_key_jwk: keyring
                                    .encrypt
                                    .get_public_key()
                                    .try_into()
                                    .unwrap(),
                            },
                        ]
                    })
                    .collect();

                let response = DidResolutionResponse {
                    context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                    did_document: DidDocument {
                        id: did.to_string(),
                        public_key: Some(public_keys),
                        service: None,
                        authentication: Some(vec!["signingKey".to_string()]),
                    },
                    method_metadata: MethodMetadata {
                        published: true,
                        recovery_commitment: None,
                        update_commitment: None,
                    },
                };
                Ok(Some(response))
            } else {
                Ok(None)
            }
        }
    }

    #[derive(Clone, Copy)]
    pub struct NoPublicKeyDidRepository;

    #[async_trait::async_trait]
    impl DidRepository for NoPublicKeyDidRepository {
        type CreateIdentifierError = CreateIdentifierError<DummyError>;
        type FindIdentifierError = FindIdentifierError<DummyError>;
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DidResolutionResponse, Self::CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError> {
            Ok(Some(DidResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DidDocument {
                    id: did.to_string(),
                    public_key: None,
                    service: None,
                    authentication: None,
                },
                method_metadata: MethodMetadata {
                    published: true,
                    recovery_commitment: None,
                    update_commitment: None,
                },
            }))
        }
    }

    #[derive(Clone, Copy)]
    pub struct IllegalPublicKeyLengthDidRepository;

    #[async_trait::async_trait]
    impl DidRepository for IllegalPublicKeyLengthDidRepository {
        type CreateIdentifierError = CreateIdentifierError<DummyError>;
        type FindIdentifierError = FindIdentifierError<DummyError>;
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DidResolutionResponse, Self::CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DidResolutionResponse>, Self::FindIdentifierError> {
            Ok(Some(DidResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DidDocument {
                    id: did.to_string(),
                    public_key: Some(vec![]),
                    service: None,
                    authentication: None,
                },
                method_metadata: MethodMetadata {
                    published: true,
                    recovery_commitment: None,
                    update_commitment: None,
                },
            }))
        }
    }
}
