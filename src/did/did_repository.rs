use std::convert::TryInto;

use http::StatusCode;

use super::sidetree::{
    client::{HttpError, SidetreeHttpClient},
    payload::{did_create_payload, DIDReplacePayload, ToPublicKey},
};
use crate::{
    did::sidetree::payload::DIDResolutionResponse,
    keyring::{
        jwk::Jwk,
        keypair::{KeyPair, KeyPairing},
    },
};

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentifierError {
    #[error("Failed to convert to JWK")]
    JwkError,
    #[error("Failed to build operation payload: {0}")]
    PayloadBuildFailed(#[from] crate::did::sidetree::payload::DIDCreatePayloadError),
    #[error("Failed to parse body: {0}")]
    BodyParseError(#[from] serde_json::Error),
    #[error("Failed to send request to sidetree: {0}")]
    SidetreeRequestFailed(anyhow::Error),
}

impl From<HttpError> for CreateIdentifierError {
    fn from(HttpError::Inner(e): HttpError) -> Self {
        Self::SidetreeRequestFailed(e)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FindIdentifierError {
    #[error("Failed to send request to sidetree: {0}")]
    SidetreeRequestFailed(anyhow::Error),
    #[error("Failed to parse body: {0}")]
    BodyParseError(#[from] serde_json::Error),
}

impl From<HttpError> for FindIdentifierError {
    fn from(HttpError::Inner(e): HttpError) -> Self {
        Self::SidetreeRequestFailed(e)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum GetPublicKeyError {
    #[error("Failed to find indentifier: {0}")]
    FindIdentifierError(#[from] FindIdentifierError),
    #[error("Failed to get did document: {0}")]
    DidDocNotFound(String),
    #[error("Failed to get public key")]
    PublicKeyNotFound(String),
    #[error("Failed to convert from JWK: {0}")]
    JwkToK256Error(#[from] crate::keyring::jwk::JwkToK256Error),
    #[error("Failed to convert from JWK: {0}")]
    JwkToX25519Error(#[from] crate::keyring::jwk::JwkToX25519Error),
}

#[async_trait::async_trait]
pub trait DidRepository: Sync {
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DIDResolutionResponse, CreateIdentifierError>;
    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError>;
    async fn get_sign_key(&self, did: &str) -> Result<k256::PublicKey, GetPublicKeyError> {
        let did_document = self.find_identifier(did).await?;
        let public_keys = did_document
            .ok_or(GetPublicKeyError::DidDocNotFound(did.to_string()))?
            .did_document
            .public_key
            .ok_or(GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
        let public_key = public_keys
            .iter()
            .find(|pk| pk.id == "signingKey")
            .ok_or(GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
        let public_key: k256::PublicKey = public_key.public_key_jwk.clone().try_into()?;
        Ok(public_key)
    }
    async fn get_encrypt_key(
        &self,
        did: &str,
    ) -> Result<x25519_dalek::PublicKey, GetPublicKeyError> {
        let did_document = self.find_identifier(did).await?;
        let public_keys = did_document
            .ok_or(GetPublicKeyError::DidDocNotFound(did.to_string()))?
            .did_document
            .public_key
            .ok_or(GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
        let public_key = public_keys
            .iter()
            .find(|pk| pk.id == "encryptionKey")
            .ok_or(GetPublicKeyError::PublicKeyNotFound(did.to_string()))?;
        let public_key: x25519_dalek::PublicKey = public_key.public_key_jwk.clone().try_into()?;
        Ok(public_key)
    }
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
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
        // https://w3c.github.io/did-spec-registries/#assertionmethod
        let sign = keyring
            .sign
            .get_public_key()
            .to_public_key(
                "EcdsaSecp256k1VerificationKey2019".to_string(),
                "signingKey".to_string(),
                vec!["assertionMethod".to_string()],
            )
            .map_err(|_| CreateIdentifierError::JwkError)?;
        let enc = keyring
            .encrypt
            .get_public_key()
            .to_public_key(
                "X25519KeyAgreementKey2019".to_string(),
                "encryptionKey".to_string(),
                vec!["keyAgreement".to_string()],
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
            DIDReplacePayload { public_keys: vec![sign, enc], service_endpoints: vec![] };
        let payload = did_create_payload(document, &update, &recovery)?;

        let response = self.client.post_create_identifier(&payload).await?;
        if response.status_code.is_success() {
            let response = serde_json::from_str(&response.body)?;
            Ok(response)
        } else {
            Err(CreateIdentifierError::SidetreeRequestFailed(anyhow::anyhow!(
                "Failed to create identifier. response: {:?}",
                response
            )))
        }
    }

    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
        let response = self.client.get_find_identifier(did).await?;

        match response.status_code {
            StatusCode::OK => Ok(Some(serde_json::from_str(&response.body)?)),
            StatusCode::NOT_FOUND => Ok(None),
            _ => Err(FindIdentifierError::SidetreeRequestFailed(anyhow::anyhow!(
                "Failed to find identifier. response: {:?}",
                response
            ))),
        }
    }
}

#[cfg(test)]
pub mod mocks {
    use std::collections::BTreeMap;

    use super::*;
    use crate::{
        did::sidetree::payload::{DIDDocument, DidPublicKey, MethodMetadata},
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

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
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

                let response = DIDResolutionResponse {
                    context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                    did_document: DIDDocument {
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
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
            Ok(Some(DIDResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DIDDocument {
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
        async fn create_identifier(
            &self,
            _keyring: KeyPairing,
        ) -> Result<DIDResolutionResponse, CreateIdentifierError> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError> {
            Ok(Some(DIDResolutionResponse {
                context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                did_document: DIDDocument {
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
