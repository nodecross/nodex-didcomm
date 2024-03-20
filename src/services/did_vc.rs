use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    nodex::{
        cipher::credential_signer::{
            CredentialSigner, CredentialSignerSignError, CredentialSignerSuite,
            CredentialSignerVerifyError,
        },
        keyring,
        schema::general::{CredentialSubject, GeneralVcDataModel, Issuer},
    },
    repository::did_repository::DidRepository,
};

pub struct DIDVCService {
    did_repository: Box<dyn DidRepository + Send + Sync + 'static>,
}

impl DIDVCService {
    pub fn new<R: DidRepository + Send + Sync + 'static>(did_repository: R) -> Self {
        Self { did_repository: Box::new(did_repository) }
    }
}

#[derive(Debug, Error)]
pub enum DIDVCServiceGenerateError {
    #[error("credential signer error")]
    SignFailed(#[from] CredentialSignerSignError),
}

#[derive(Debug, Error)]
pub enum DIDVCServiceVerifyError {
    #[error("did not found : {0}")]
    DIDNotFound(String),
    #[error("did public key not found. did: {0}")]
    PublicKeyNotFound(String),
    #[error("credential signer error")]
    VerifyFailed(#[from] CredentialSignerVerifyError),
    #[error("public_keys length must be 1")]
    PublicKeyLengthMismatch,
    #[error("signature is not verified")]
    SignatureNotVerified,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DIDVCService {
    pub fn generate(
        &self,
        from_did: &str,
        from_keyring: &keyring::keypair::KeyPairing,
        message: &Value,
        issuance_date: DateTime<Utc>,
    ) -> Result<GeneralVcDataModel, DIDVCServiceGenerateError> {
        let r#type = "VerifiableCredential".to_string();
        let context = "https://www.w3.org/2018/credentials/v1".to_string();
        let issuance_date = issuance_date.to_rfc3339();

        let model = GeneralVcDataModel {
            id: None,
            issuer: Issuer { id: from_did.to_string() },
            r#type: vec![r#type],
            context: vec![context],
            issuance_date,
            credential_subject: CredentialSubject { id: None, container: message.clone() },
            expiration_date: None,
            proof: None,
        };

        let signed: GeneralVcDataModel = CredentialSigner::sign(
            &model,
            CredentialSignerSuite {
                did: from_did,
                key_id: "signingKey",
                context: &from_keyring.sign,
            },
        )?;

        Ok(signed)
    }

    pub async fn verify(
        &self,
        model: GeneralVcDataModel,
    ) -> Result<GeneralVcDataModel, DIDVCServiceVerifyError> {
        let did_document = self
            .did_repository
            .find_identifier(&model.issuer.id)
            .await?
            .ok_or_else(|| DIDVCServiceVerifyError::DIDNotFound(model.issuer.id.clone()))?;
        let public_keys = did_document
            .did_document
            .public_key
            .ok_or_else(|| DIDVCServiceVerifyError::PublicKeyNotFound(model.issuer.id.clone()))?;

        // FIXME: workaround
        if public_keys.len() != 1 {
            return Err(DIDVCServiceVerifyError::PublicKeyLengthMismatch);
        }

        let public_key = public_keys[0].clone();

        let context = keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk)
            .context("failed to convert key")?;

        let (verified_model, verified) =
            CredentialSigner::verify(model, &context).context("failed to verify credential")?;

        if verified {
            Ok(verified_model)
        } else {
            Err(DIDVCServiceVerifyError::SignatureNotVerified)
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::distributions::{Alphanumeric, DistString as _};
    use serde_json::json;

    use super::*;
    use crate::{
        nodex::{
            extension::trng::OSRandomNumberGenerator,
            keyring::keypair::KeyPairing,
            sidetree::payload::{DIDDocument, DIDResolutionResponse, DidPublicKey, MethodMetadata},
        },
        repository::did_repository::DidRepository,
    };

    struct MockDidRepository {
        did: String,
        keyring: KeyPairing,
    }

    impl MockDidRepository {
        pub fn new(did: String, keyring: KeyPairing) -> Self {
            Self { did, keyring }
        }
    }

    #[async_trait::async_trait]
    impl DidRepository for MockDidRepository {
        async fn create_identifier(&self) -> anyhow::Result<DIDResolutionResponse> {
            let res = self.find_identifier(&self.did).await?;
            Ok(res.unwrap())
        }
        async fn find_identifier(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<DIDResolutionResponse>> {
            // extract from NodeX::create_identifier
            let jwk = self.keyring.sign.to_jwk(false)?;

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
        }
    }

    fn create_random_did() -> String {
        let random_string = Alphanumeric.sample_string(&mut rand::thread_rng(), 16);
        format!("did:nodex:test:{}", random_string)
    }

    #[actix_rt::test]
    async fn test_generate_and_verify() {
        let from_did = create_random_did();

        let trng = OSRandomNumberGenerator::default();
        let from_keyring = KeyPairing::create_keyring(&trng).unwrap();

        let mock_repository = MockDidRepository::new(from_did.to_string(), from_keyring.clone());

        let service = DIDVCService::new(mock_repository);

        let message = json!({"test": "0123456789abcdef"});
        let issuance_date = Utc::now();

        let res = service.generate(&from_did, &from_keyring, &message, issuance_date).unwrap();

        let verified = service.verify(res).await.unwrap();

        assert_eq!(verified.issuer.id, from_did);
        assert_eq!(verified.credential_subject.container, message);
    }
}
