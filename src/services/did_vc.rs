use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    nodex::{
        cipher::credential_signer::{
            CredentialSigner, CredentialSignerError, CredentialSignerSuite,
        },
        keyring::{self},
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
    CredentialSignerError(#[from] CredentialSignerError),
}

#[derive(Debug, Error)]
pub enum DIDVCServiceVerifyError {
    #[error("did not found : {0}")]
    DIDNotFound(String),
    #[error("did public key not found. did: {0}")]
    PublicKeyNotFound(String),
    #[error("credential signer error")]
    CredentialSignerError(#[from] CredentialSignerError),
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
