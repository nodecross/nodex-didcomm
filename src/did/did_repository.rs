use anyhow::Context;
use http::StatusCode;

use super::sidetree::{
    client::{HttpError, SidetreeHttpClient},
    payload::{CommitmentKeys, DIDCreateRequest, OperationPayloadBuilder},
};
use crate::{did::sidetree::payload::DIDResolutionResponse, keyring::keypair::KeyPairing};

#[derive(Debug, thiserror::Error)]
pub enum CreateIdentifierError {
    #[error("Failed to convert public key: {0}")]
    PublicKeyConvertFailed(crate::keyring::secp256k1::Secp256k1Error),
    #[error("Failed to convert to JWK: {0}")]
    JwkConvertFailed(#[from] crate::keyring::secp256k1::Secp256k1Error),
    #[error("Failed to build operation payload: {0}")]
    PayloadBuildFailed(#[from] crate::did::sidetree::payload::OperationPayloadBuilderError),
    #[error("Failed to send request to sidetree: {0}")]
    SidetreeRequestFailed(anyhow::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
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
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<HttpError> for FindIdentifierError {
    fn from(HttpError::Inner(e): HttpError) -> Self {
        Self::SidetreeRequestFailed(e)
    }
}

#[async_trait::async_trait]
pub trait DidRepository {
    async fn create_identifier(
        &self,
        keyring: KeyPairing,
    ) -> Result<DIDResolutionResponse, CreateIdentifierError>;
    async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<Option<DIDResolutionResponse>, FindIdentifierError>;
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
        let public = keyring
            .sign
            .to_public_key("signingKey", &["auth", "general"])
            .map_err(CreateIdentifierError::PublicKeyConvertFailed)?;

        let update = keyring.update.to_jwk(false)?;
        let recovery = keyring.recovery.to_jwk(false)?;
        let payload = OperationPayloadBuilder::did_create_payload(&DIDCreateRequest {
            public_keys: vec![public],
            commitment_keys: CommitmentKeys { recovery, update },
            service_endpoints: vec![],
        })?;

        let response = self.client.post_create_identifier(&payload).await?;
        if response.status_code.is_success() {
            let response = serde_json::from_str(&response.body).context("failed to parse body")?;
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
            StatusCode::OK => {
                Ok(Some(serde_json::from_str(&response.body).context("failed to parse body")?))
            }
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
                    .map(|keyring| DidPublicKey {
                        id: did.to_string() + "#signingKey",
                        controller: String::new(),
                        r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                        public_key_jwk: keyring.sign.to_jwk(false).unwrap(),
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
