use anyhow::Context;
use arrayref::array_ref;
use chrono::{DateTime, Utc};
use cuid;
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    AttachmentBuilder, AttachmentDataBuilder, Message,
};
use serde_json::Value;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

use super::{
    did_vc::{DIDVCService, DIDVCServiceGenerateError, DIDVCServiceVerifyError},
    types::VerifiedContainer,
};
use crate::{
    didcomm::DIDCommMessage,
    nodex::{
        keyring::{self, keypair::KeyPairing},
        runtime::{
            self,
            base64_url::{self, PaddingType},
        },
        schema::general::GeneralVcDataModel,
    },
    repository::did_repository::DidRepository,
};

pub struct DIDCommEncryptedService {
    did_repository: Box<dyn DidRepository + Send + Sync + 'static>,
    vc_service: DIDVCService,
    attachment_link: String,
}

#[derive(Debug, Error)]
pub enum DIDCommEncryptedServiceGenerateError {
    #[error("Secp256k1 error")]
    KeyringSecp256k1Error(#[from] keyring::secp256k1::Secp256k1Error),
    #[error("Secp256k1 error")]
    RuntimeSecp256k1Error(#[from] runtime::secp256k1::Secp256k1Error),
    #[error("did not found : {0}")]
    DIDNotFound(String),
    #[error("did public key not found. did: {0}")]
    DidPublicKeyNotFound(String),
    #[error("something went wrong with vc service")]
    VCServiceError(#[from] DIDVCServiceGenerateError),
    #[error("failed to encrypt message")]
    EncryptFailed(#[from] didcomm_rs::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Debug, Error)]
pub enum DIDCommEncryptedServiceVerifyError {
    #[error("key pairing error")]
    KeyParingError(#[from] keyring::keypair::KeyPairingError),
    #[error("Secp256k1 error")]
    KeyringSecp256k1Error(#[from] keyring::secp256k1::Secp256k1Error),
    #[error("Secp256k1 error")]
    RuntimeSecp256k1Error(#[from] runtime::secp256k1::Secp256k1Error),
    #[error("did not found : {0}")]
    DIDNotFound(String),
    #[error("did public key not found")]
    DidPublicKeyNotFound,
    #[error("something went wrong with vc service")]
    VCServiceError(#[from] DIDVCServiceVerifyError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl DIDCommEncryptedService {
    pub fn new<R: DidRepository + Send + Sync + 'static>(
        did_repository: R,
        vc_service: DIDVCService,
        attachment_link: Option<String>,
    ) -> DIDCommEncryptedService {
        fn default_attachment_link() -> String {
            std::env::var("NODEX_DID_ATTACHMENT_LINK")
                .unwrap_or("https://did.getnodex.io".to_string())
        }

        DIDCommEncryptedService {
            did_repository: Box::new(did_repository),
            vc_service,
            attachment_link: attachment_link.unwrap_or(default_attachment_link()),
        }
    }

    pub async fn generate(
        &self,
        from_did: &str,
        to_did: &str,
        from_keyring: &KeyPairing,
        message: &Value,
        metadata: Option<&Value>,
        issuance_date: DateTime<Utc>,
    ) -> Result<DIDCommMessage, DIDCommEncryptedServiceGenerateError> {
        // NOTE: recipient to
        let did_document =
            self.did_repository.find_identifier(to_did).await?.ok_or_else(|| {
                DIDCommEncryptedServiceGenerateError::DIDNotFound(to_did.to_string())
            })?;

        let public_keys = did_document.did_document.public_key.ok_or_else(|| {
            DIDCommEncryptedServiceGenerateError::DidPublicKeyNotFound(to_did.to_string())
        })?;

        // FIXME: workaround
        if public_keys.len() != 1 {
            return Err(anyhow::anyhow!("public_keys length must be 1").into());
        }

        let public_key = public_keys[0].clone();

        let other_key = keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk)?;

        // NOTE: ecdh
        let shared_key = runtime::secp256k1::Secp256k1::ecdh(
            &from_keyring.sign.get_secret_key(),
            &other_key.get_public_key(),
        )?;

        let sk = StaticSecret::from(array_ref!(shared_key, 0, 32).to_owned());
        let pk = PublicKey::from(&sk);

        // NOTE: message
        let body = self.vc_service.generate(from_did, from_keyring, message, issuance_date)?;
        let body = serde_json::to_string(&body).context("failed to serialize")?;

        let mut message =
            Message::new().from(from_did).to(&[to_did]).body(&body).map_err(|e| {
                anyhow::anyhow!("Failed to initialize message with error = {:?}", e)
            })?;

        // NOTE: Has attachment
        if let Some(value) = metadata {
            let id = cuid::cuid2();

            // let media_type = "application/json";
            let data = AttachmentDataBuilder::new()
                .with_link(&self.attachment_link)
                .with_json(&value.to_string());

            message.append_attachment(
                AttachmentBuilder::new(true).with_id(&id).with_format("metadata").with_data(data),
            )
        }

        let seal_signed_message =
            message.as_jwe(&CryptoAlgorithm::XC20P, Some(pk.as_bytes().to_vec())).seal_signed(
                sk.to_bytes().as_ref(),
                Some(vec![Some(pk.as_bytes().to_vec())]),
                SignatureAlgorithm::Es256k,
                &from_keyring.sign.get_secret_key(),
            )?;

        Ok(serde_json::from_str::<DIDCommMessage>(&seal_signed_message)
            .context("failed to convert to json")?)
    }

    pub async fn verify(
        &self,
        my_keyring: &KeyPairing,
        message: &Value,
    ) -> Result<VerifiedContainer, DIDCommEncryptedServiceVerifyError> {
        let protected = message
            .get("protected")
            .context("protected not found")?
            .as_str()
            .context("failed to serialize protected")?;

        let decoded = base64_url::Base64Url::decode_as_string(protected, &PaddingType::NoPadding)
            .context("failed to base64 decode protected")?;
        let decoded =
            serde_json::from_str::<Value>(&decoded).context("failed to decode to json")?;

        let other_did = decoded
            .get("skid")
            .context("skid not found")?
            .as_str()
            .context("failed to serialize skid")?;

        let did_document = self
            .did_repository
            .find_identifier(other_did)
            .await?
            .ok_or(DIDCommEncryptedServiceVerifyError::DIDNotFound(other_did.to_string()))?;

        let public_keys = did_document.did_document.public_key.with_context(|| {
            format!("public_key is not found in did_document. did = {}", other_did)
        })?;

        // FIXME: workaround
        if public_keys.len() != 1 {
            return Err(anyhow::anyhow!("public_keys length must be 1").into());
        }

        let public_key = public_keys[0].clone();

        let other_key = keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk)?;

        // NOTE: ecdh
        let shared_key = runtime::secp256k1::Secp256k1::ecdh(
            &my_keyring.sign.get_secret_key(),
            &other_key.get_public_key(),
        )?;

        let sk = StaticSecret::from(array_ref!(shared_key, 0, 32).to_owned());
        let pk = PublicKey::from(&sk);

        let message = Message::receive(
            &message.to_string(),
            Some(sk.to_bytes().as_ref()),
            Some(pk.as_bytes().to_vec()),
            Some(&other_key.get_public_key()),
        )
        .map_err(|e| anyhow::anyhow!("failed to decrypt message : {:?}", e))?;

        let metadata = message.attachment_iter().find(|item| match item.format.clone() {
            Some(value) => value == "metadata",
            None => false,
        });

        let body = message
            .clone()
            .get_body()
            .map_err(|e| anyhow::anyhow!("failed to get body : {:?}", e))?;
        let body =
            serde_json::from_str::<GeneralVcDataModel>(&body).context("failed to parse body")?;

        match metadata {
            Some(metadata) => {
                let metadata =
                    metadata.data.json.as_ref().ok_or(anyhow::anyhow!("metadata not found"))?;
                let metadata = serde_json::from_str::<Value>(metadata)
                    .context("failed to parse metadata to json")?;
                Ok(VerifiedContainer { message: body, metadata: Some(metadata) })
            }
            None => Ok(VerifiedContainer { message: body, metadata: None }),
        }
    }
}
