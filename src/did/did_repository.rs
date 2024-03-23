use crate::did::sidetree::payload::DIDResolutionResponse;

#[async_trait::async_trait]
pub trait DidRepository {
    async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse>;
    async fn find_identifier(&self, did: &str) -> anyhow::Result<Option<DIDResolutionResponse>>;
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
        map: BTreeMap<String, KeyPairing>,
    }

    impl MockDidRepository {
        pub fn new(map: BTreeMap<String, KeyPairing>) -> Self {
            Self { map }
        }
    }

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<DIDResolutionResponse>> {
            if let Some(keyring) = self.map.get(did) {
                let jwk = keyring.sign.to_jwk(false)?;

                let response = DIDResolutionResponse {
                    context: "https://www.w3.org/ns/did-resolution/v1".to_string(),
                    did_document: DIDDocument {
                        id: did.to_string(),
                        public_key: Some(vec![DidPublicKey {
                            id: did.to_string() + "#signingKey",
                            controller: String::new(),
                            r#type: "EcdsaSecp256k1VerificationKey2019".to_string(),
                            public_key_jwk: jwk,
                        }]),
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
        async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<DIDResolutionResponse>> {
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
        async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
            unimplemented!()
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<DIDResolutionResponse>> {
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
