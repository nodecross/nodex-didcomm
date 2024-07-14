use chrono::{DateTime, Utc};
use cuid;
use didcomm_rs::{crypto::CryptoAlgorithm, AttachmentBuilder, AttachmentDataBuilder, Message};
use serde_json::Value;
use thiserror::Error;

use crate::{
    did::{
        did_repository::{get_encrypt_key, get_sign_key, DidRepository, GetPublicKeyError},
        sidetree::payload::DidDocument,
    },
    didcomm::types::{DidCommMessage, FindSenderError},
    keyring::keypair::{KeyPair, KeyPairing},
    verifiable_credentials::{
        credential_signer::{CredentialSigner, CredentialSignerVerifyError},
        did_vc::DidVcService,
        types::{VerifiableCredentials, VerifiedContainer},
    },
};

#[async_trait::async_trait]
pub trait DidCommEncryptedService: Sync {
    type GenerateError: std::error::Error;
    type VerifyError: std::error::Error;
    async fn generate(
        &self,
        from_did: &str,
        to_did: &str,
        from_keyring: &KeyPairing,
        message: &Value,
        metadata: Option<&Value>,
        issuance_date: DateTime<Utc>,
        attachment_link: &str,
    ) -> Result<DidCommMessage, Self::GenerateError>;
    async fn verify(
        &self,
        my_keyring: &KeyPairing,
        message: &DidCommMessage,
    ) -> Result<VerifiedContainer, Self::VerifyError>;
}

fn generate<R: DidRepository, V: DidVcService>(
    from_did: &str,
    to_doc: &DidDocument,
    from_keyring: &KeyPairing,
    metadata: Option<&Value>,
    body: &VerifiableCredentials,
    attachment_link: &str,
) -> Result<
    DidCommMessage,
    DidCommEncryptedServiceGenerateError<R::FindIdentifierError, V::GenerateError>,
> {
    let to_did = &to_doc.id;
    // NOTE: message
    let body = serde_json::to_string(body)?;

    let mut message = Message::new().from(from_did).to(&[to_did]).body(&body)?;

    // NOTE: Has attachment
    if let Some(value) = metadata {
        let id = cuid::cuid2();

        // let media_type = "application/json";
        let data =
            AttachmentDataBuilder::new().with_link(attachment_link).with_json(&value.to_string());

        message.append_attachment(
            AttachmentBuilder::new(true).with_id(&id).with_format("metadata").with_data(data),
        )
    }

    // NOTE: recipient to
    let public_key = get_encrypt_key(to_doc)?.as_bytes().to_vec();
    let public_key = Some(public_key);

    let seal_message = message
        .as_jwe(&CryptoAlgorithm::XC20P, public_key.clone())
        .seal(&from_keyring.encrypt.get_secret_key().as_bytes().to_vec(), Some(vec![public_key]))?;

    Ok(serde_json::from_str::<DidCommMessage>(&seal_message)?)
}

fn verify<R: DidRepository>(
    from_doc: &DidDocument,
    my_keyring: &KeyPairing,
    message: &DidCommMessage,
) -> Result<VerifiedContainer, DidCommEncryptedServiceVerifyError<R::FindIdentifierError>> {
    let public_key = get_encrypt_key(from_doc)?.as_bytes().to_vec();

    let public_key = Some(public_key);

    let message = Message::receive(
        &serde_json::to_string(&message)?,
        Some(&my_keyring.encrypt.get_secret_key().as_bytes().to_vec()),
        public_key,
        None,
    )?;

    let metadata = message.attachment_iter().find(|item| match &item.format {
        Some(value) => value == "metadata",
        None => false,
    });

    let body = message
        .get_body()
        .map_err(|e| DidCommEncryptedServiceVerifyError::MetadataBodyNotFound(Some(e)))?;
    let body = serde_json::from_str::<VerifiableCredentials>(&body)?;
    // let body = did_vc::verify(from_doc, body)?;

    match metadata {
        Some(metadata) => {
            let metadata = metadata
                .data
                .json
                .as_ref()
                .ok_or(DidCommEncryptedServiceVerifyError::MetadataBodyNotFound(None))?;
            let metadata = serde_json::from_str::<Value>(metadata)?;
            Ok(VerifiedContainer { message: body, metadata: Some(metadata) })
        }
        None => Ok(VerifiedContainer { message: body, metadata: None }),
    }
}

#[derive(Debug, Error)]
pub enum DidCommEncryptedServiceGenerateError<
    FindIdentifierError: std::error::Error,
    DidVcServiceGenerateError: std::error::Error,
> {
    #[error("failed to get did document: {0}")]
    DidDocNotFound(String),
    #[error("did public key not found. did: {0}")]
    DidPublicKeyNotFound(#[from] GetPublicKeyError),
    #[error("something went wrong with vc service")]
    VCServiceError(DidVcServiceGenerateError),
    #[error("failed to create identifier")]
    SidetreeFindRequestFailed(FindIdentifierError),
    #[error("failed to encrypt message with error: {0}")]
    EncryptFailed(#[from] didcomm_rs::Error),
    #[error("failed serialize/deserialize : {0}")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum DidCommEncryptedServiceVerifyError<FindIdentifierError: std::error::Error> {
    #[error("failed to get did document: {0}")]
    DidDocNotFound(String),
    #[error("something went wrong with vc service")]
    VCServiceError(#[from] CredentialSignerVerifyError),
    #[error("failed to find identifier")]
    SidetreeFindRequestFailed(FindIdentifierError),
    #[error("did public key not found. did: {0}")]
    DidPublicKeyNotFound(#[from] GetPublicKeyError),
    #[error("failed to decrypt message : {0}")]
    DecryptFailed(#[from] didcomm_rs::Error),
    #[error("failed to get body : {0:?}")]
    MetadataBodyNotFound(Option<didcomm_rs::Error>),
    #[error("failed serialize/deserialize : {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("failed to find sender did : {0}")]
    FindSenderError(#[from] FindSenderError),
}

#[async_trait::async_trait]
impl<R> DidCommEncryptedService for R
where
    R: DidRepository + DidVcService,
{
    type GenerateError =
        DidCommEncryptedServiceGenerateError<R::FindIdentifierError, R::GenerateError>;
    type VerifyError = DidCommEncryptedServiceVerifyError<R::FindIdentifierError>;
    async fn generate(
        &self,
        from_did: &str,
        to_did: &str,
        from_keyring: &KeyPairing,
        message: &Value,
        metadata: Option<&Value>,
        issuance_date: DateTime<Utc>,
        attachment_link: &str,
    ) -> Result<DidCommMessage, Self::GenerateError> {
        // NOTE: message
        let body = DidVcService::generate(self, from_did, from_keyring, message, issuance_date)
            .map_err(Self::GenerateError::VCServiceError)?;
        let to_doc = self
            .find_identifier(to_did)
            .await
            .map_err(Self::GenerateError::SidetreeFindRequestFailed)?
            .ok_or(Self::GenerateError::DidDocNotFound(to_did.to_string()))?
            .did_document;

        Ok(generate::<R, R>(from_did, &to_doc, from_keyring, metadata, &body, attachment_link)?)
    }

    async fn verify(
        &self,
        my_keyring: &KeyPairing,
        message: &DidCommMessage,
    ) -> Result<VerifiedContainer, Self::VerifyError> {
        let other_did = message.find_sender()?;
        let other_doc = self
            .find_identifier(&other_did)
            .await
            .map_err(Self::VerifyError::SidetreeFindRequestFailed)?
            .ok_or(Self::VerifyError::DidDocNotFound(other_did))?
            .did_document;
        let mut container = verify::<R>(&other_doc, my_keyring, message)?;
        // For performance, call low level api
        let public_key = get_sign_key(&other_doc)?;
        let body = CredentialSigner::verify(container.message, &public_key)?;
        container.message = body;
        Ok(container)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, iter::FromIterator as _};

    use rand_core::OsRng;
    use serde_json::json;

    use super::*;
    use crate::{
        did::did_repository::mocks::MockDidRepository, didcomm::test_utils::create_random_did,
        keyring::keypair::KeyPairing,
    };

    #[actix_rt::test]
    async fn test_generate_and_verify() {
        let from_did = create_random_did();
        let to_did = create_random_did();

        let to_keyring = KeyPairing::create_keyring(&mut OsRng);
        let from_keyring = KeyPairing::create_keyring(&mut OsRng);

        let repo = MockDidRepository::from_single(BTreeMap::from_iter([
            (from_did.clone(), from_keyring.clone()),
            (to_did.clone(), to_keyring.clone()),
        ]));

        let message = json!({"test": "0123456789abcdef"});
        let issuance_date = Utc::now();

        let res = DidCommEncryptedService::generate(
            &repo,
            &from_did,
            &to_did,
            &from_keyring,
            &message,
            None,
            issuance_date,
            "",
        )
        .await
        .unwrap();

        let verified = DidCommEncryptedService::verify(&repo, &to_keyring, &res).await.unwrap();
        let verified = verified.message;

        assert_eq!(verified.issuer.id, from_did);
        assert_eq!(verified.credential_subject.container, message);
    }

    mod generate_failed {
        use super::*;
        use crate::did::did_repository::mocks::NoPublicKeyDidRepository;

        #[actix_rt::test]
        async fn test_did_not_found() {
            let from_did = create_random_did();
            let to_did = create_random_did();

            let from_keyring = KeyPairing::create_keyring(&mut OsRng);

            let repo = MockDidRepository::from_single(BTreeMap::from_iter([(
                from_did.clone(),
                from_keyring.clone(),
            )]));

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = DidCommEncryptedService::generate(
                &repo,
                &from_did,
                &to_did,
                &from_keyring,
                &message,
                None,
                issuance_date,
                "",
            )
            .await
            .unwrap_err();

            if let DidCommEncryptedServiceGenerateError::DidDocNotFound(did) = res {
                assert_eq!(did, to_did);
            } else {
                panic!("unexpected result: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_did_public_key_not_found() {
            let from_did = create_random_did();
            let to_did = create_random_did();

            let from_keyring = KeyPairing::create_keyring(&mut OsRng);

            let repo = NoPublicKeyDidRepository;

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = DidCommEncryptedService::generate(
                &repo,
                &from_did,
                &to_did,
                &from_keyring,
                &message,
                None,
                issuance_date,
                "",
            )
            .await
            .unwrap_err();

            if let DidCommEncryptedServiceGenerateError::DidPublicKeyNotFound(
                GetPublicKeyError::PublicKeyNotFound(did),
            ) = res
            {
                assert_eq!(did, to_did);
            } else {
                panic!("unexpected result: {:?}", res);
            }
        }
    }

    mod verify_failed {
        use super::*;
        use crate::did::did_repository::mocks::NoPublicKeyDidRepository;

        async fn create_didcomm(
            from_did: &str,
            to_did: &str,
            from_keyring: &KeyPairing,
            to_keyring: &KeyPairing,
            message: &Value,
            metadata: Option<&Value>,
            issuance_date: DateTime<Utc>,
        ) -> DidCommMessage {
            let repo = MockDidRepository::from_single(BTreeMap::from_iter([(
                to_did.to_string(),
                to_keyring.clone(),
            )]));

            DidCommEncryptedService::generate(
                &repo,
                &from_did,
                &to_did,
                &from_keyring,
                &message,
                metadata,
                issuance_date,
                "",
            )
            .await
            .unwrap()
        }

        #[actix_rt::test]
        async fn test_did_not_found() {
            let from_did = create_random_did();
            let to_did = create_random_did();

            let to_keyring = KeyPairing::create_keyring(&mut OsRng);
            let from_keyring = KeyPairing::create_keyring(&mut OsRng);

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = create_didcomm(
                &from_did,
                &to_did,
                &from_keyring,
                &to_keyring,
                &message,
                None,
                issuance_date,
            )
            .await;

            let repo = MockDidRepository::from_single(BTreeMap::from_iter([(
                to_did.clone(),
                to_keyring.clone(),
            )]));
            let res =
                DidCommEncryptedService::verify(&repo, &from_keyring, &res).await.unwrap_err();

            if let DidCommEncryptedServiceVerifyError::DidDocNotFound(did) = res {
                assert_eq!(did, from_did);
            } else {
                panic!("unexpected result: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_cannot_steal_message() {
            let from_did = create_random_did();
            let to_did = create_random_did();
            let other_did = create_random_did();

            let to_keyring = KeyPairing::create_keyring(&mut OsRng);
            let from_keyring = KeyPairing::create_keyring(&mut OsRng);
            let other_keyring = KeyPairing::create_keyring(&mut OsRng);

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = create_didcomm(
                &from_did,
                &to_did,
                &from_keyring,
                &to_keyring,
                &message,
                None,
                issuance_date,
            )
            .await;

            let repo = MockDidRepository::from_single(BTreeMap::from_iter([
                (from_did.clone(), from_keyring.clone()),
                (to_did.clone(), to_keyring.clone()),
                (other_did.clone(), other_keyring.clone()),
            ]));

            let res =
                DidCommEncryptedService::verify(&repo, &other_keyring, &res).await.unwrap_err();

            if let DidCommEncryptedServiceVerifyError::DecryptFailed(_) = res {
            } else {
                panic!("unexpected result: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_did_public_key_not_found() {
            let from_did = create_random_did();
            let to_did = create_random_did();

            let to_keyring = KeyPairing::create_keyring(&mut OsRng);
            let from_keyring = KeyPairing::create_keyring(&mut OsRng);

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = create_didcomm(
                &from_did,
                &to_did,
                &from_keyring,
                &to_keyring,
                &message,
                None,
                issuance_date,
            )
            .await;

            let repo = NoPublicKeyDidRepository;

            let res =
                DidCommEncryptedService::verify(&repo, &from_keyring, &res).await.unwrap_err();

            if let DidCommEncryptedServiceVerifyError::DidPublicKeyNotFound(
                GetPublicKeyError::PublicKeyNotFound(did),
            ) = res
            {
                assert_eq!(did, from_did);
            } else {
                panic!("unexpected result: {:?}", res);
            }
        }
    }
}
