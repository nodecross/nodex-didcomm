use chrono::{DateTime, Utc};
use cuid;
use didcomm_rs::{crypto::CryptoAlgorithm, AttachmentBuilder, AttachmentDataBuilder, Message};
use serde_json::Value;
use thiserror::Error;

use crate::{
    did::did_repository::{
        CreateIdentifierError, DidRepository, FindIdentifierError, GetPublicKeyError,
    },
    didcomm::types::{DidCommMessage, FindSenderError},
    keyring::keypair::{KeyPair, KeyPairing},
    verifiable_credentials::{
        did_vc::{
            DidVcService, DidVcServiceGenerateError, DidVcServiceImpl, DidVcServiceVerifyError,
        },
        types::{VerifiableCredentials, VerifiedContainer},
    },
};

#[async_trait::async_trait]
pub trait DidCommEncryptedService {
    async fn generate(
        &self,
        from_did: &str,
        to_did: &str,
        from_keyring: &KeyPairing,
        message: &Value,
        metadata: Option<&Value>,
        issuance_date: DateTime<Utc>,
    ) -> Result<DidCommMessage, DidCommEncryptedServiceGenerateError>;
    async fn verify(
        &self,
        my_keyring: &KeyPairing,
        message: &DidCommMessage,
    ) -> Result<VerifiedContainer, DidCommEncryptedServiceVerifyError>;
}

#[derive(Clone)]
pub struct DidCommEncryptedServiceImpl<R, V>
where
    R: DidRepository,
    V: DidVcService,
{
    did_repository: R,
    vc_service: V,
    attachment_link: String,
}

impl<R, V> DidCommEncryptedServiceImpl<R, V>
where
    R: DidRepository,
    V: DidVcService,
{
    pub fn new_with_vc(did_repository: R, vc_service: V, attachment_link: Option<String>) -> Self {
        fn default_attachment_link() -> String {
            std::env::var("NODEX_Did_ATTACHMENT_LINK")
                .unwrap_or("https://did.getnodex.io".to_string())
        }

        DidCommEncryptedServiceImpl {
            did_repository,
            vc_service,
            attachment_link: attachment_link.unwrap_or(default_attachment_link()),
        }
    }
}

impl<R> DidCommEncryptedServiceImpl<R, DidVcServiceImpl<R>>
where
    R: DidRepository + Clone,
{
    pub fn new(did_repository: R, attachment_link: Option<String>) -> Self {
        Self::new_with_vc(
            did_repository.clone(),
            DidVcServiceImpl::new(did_repository),
            attachment_link,
        )
    }
}

#[derive(Debug, Error)]
pub enum DidCommEncryptedServiceGenerateError {
    #[error("did public key not found. did: {0}")]
    DidPublicKeyNotFound(#[from] GetPublicKeyError),
    #[error("something went wrong with vc service")]
    VCServiceError(#[from] DidVcServiceGenerateError),
    #[error("failed to create identifier")]
    SidetreeCreateRequestFailed(#[from] CreateIdentifierError),
    #[error("failed to encrypt message with error: {0}")]
    EncryptFailed(#[from] didcomm_rs::Error),
    #[error("failed serialize/deserialize : {0}")]
    JsonError(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum DidCommEncryptedServiceVerifyError {
    #[error("something went wrong with vc service")]
    VCServiceError(#[from] DidVcServiceVerifyError),
    #[error("failed to find identifier")]
    SidetreeFindRequestFailed(#[from] FindIdentifierError),
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
impl<R, V> DidCommEncryptedService for DidCommEncryptedServiceImpl<R, V>
where
    R: DidRepository,
    V: DidVcService,
{
    async fn generate(
        &self,
        from_did: &str,
        to_did: &str,
        from_keyring: &KeyPairing,
        message: &Value,
        metadata: Option<&Value>,
        issuance_date: DateTime<Utc>,
    ) -> Result<DidCommMessage, DidCommEncryptedServiceGenerateError> {
        // NOTE: message
        let body = self.vc_service.generate(from_did, from_keyring, message, issuance_date)?;
        let body = serde_json::to_string(&body)?;

        let mut message = Message::new().from(from_did).to(&[to_did]).body(&body)?;

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

        // NOTE: recipient to
        let public_key = self.did_repository.get_encrypt_key(to_did).await?.as_bytes().to_vec();
        let public_key = Some(public_key);

        let seal_message = message.as_jwe(&CryptoAlgorithm::XC20P, public_key.clone()).seal(
            &from_keyring.encrypt.get_secret_key().as_bytes().to_vec(),
            Some(vec![public_key]),
        )?;

        Ok(serde_json::from_str::<DidCommMessage>(&seal_message)?)
    }

    async fn verify(
        &self,
        my_keyring: &KeyPairing,
        message: &DidCommMessage,
    ) -> Result<VerifiedContainer, DidCommEncryptedServiceVerifyError> {
        let other_did = message.find_sender()?;
        let public_key = self.did_repository.get_encrypt_key(&other_did).await?.as_bytes().to_vec();
        let public_key = Some(public_key);

        let message = Message::receive(
            &serde_json::to_string(&message)?,
            Some(&my_keyring.encrypt.get_secret_key().as_bytes().to_vec()),
            public_key,
            None,
        )?;

        let metadata = message.attachment_iter().find(|item| match item.format.clone() {
            Some(value) => value == "metadata",
            None => false,
        });

        let body = message
            .get_body()
            .map_err(|e| DidCommEncryptedServiceVerifyError::MetadataBodyNotFound(Some(e)))?;
        let body = serde_json::from_str::<VerifiableCredentials>(&body)?;
        let body = self.vc_service.verify(body).await?;

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

        let service = DidCommEncryptedServiceImpl::new(repo, None);

        let message = json!({"test": "0123456789abcdef"});
        let issuance_date = Utc::now();

        let res = service
            .generate(&from_did, &to_did, &from_keyring, &message, None, issuance_date)
            .await
            .unwrap();

        let verified = service.verify(&to_keyring, &res).await.unwrap();
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

            let service = DidCommEncryptedServiceImpl::new(repo, None);

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = service
                .generate(&from_did, &to_did, &from_keyring, &message, None, issuance_date)
                .await
                .unwrap_err();

            if let DidCommEncryptedServiceGenerateError::DidPublicKeyNotFound(
                GetPublicKeyError::DidDocNotFound(did),
            ) = res
            {
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

            let service = DidCommEncryptedServiceImpl::new(repo, None);

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res = service
                .generate(&from_did, &to_did, &from_keyring, &message, None, issuance_date)
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

            let service = DidCommEncryptedServiceImpl::new(repo, None);

            service
                .generate(from_did, to_did, from_keyring, message, metadata, issuance_date)
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

            let service = DidCommEncryptedServiceImpl::new(repo, None);

            let res = service.verify(&from_keyring, &res).await.unwrap_err();

            if let DidCommEncryptedServiceVerifyError::DidPublicKeyNotFound(
                GetPublicKeyError::DidDocNotFound(did),
            ) = res
            {
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

            let service = DidCommEncryptedServiceImpl::new(repo, None);

            let res = service.verify(&other_keyring, &res).await.unwrap_err();

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

            let service = DidCommEncryptedServiceImpl::new(repo, None);

            let res = service.verify(&from_keyring, &res).await.unwrap_err();

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
