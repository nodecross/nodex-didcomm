use anyhow::Context as _;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    did::did_repository::DidRepository,
    keyring::{self, keypair},
    verifiable_credentials::{
        credential_signer::{
            CredentialSigner, CredentialSignerSignError, CredentialSignerSuite,
            CredentialSignerVerifyError,
        },
        types::{CredentialSubject, GeneralVcDataModel, Issuer},
    },
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
        from_keyring: &keypair::KeyPairing,
        message: &Value,
        issuance_date: DateTime<Utc>,
    ) -> Result<GeneralVcDataModel, DIDVCServiceGenerateError> {
        let r#type = "VerifiableCredential".to_string();
        let context = "https://www.w3.org/2018/credentials/v1".to_string();

        let model = GeneralVcDataModel {
            id: None,
            issuer: Issuer { id: from_did.to_string() },
            r#type: vec![r#type],
            context: vec![context],
            issuance_date: issuance_date.to_rfc3339(),
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
            issuance_date,
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

        let (verified_model, verified) = CredentialSigner::verify(model, &context)?;

        if verified {
            Ok(verified_model)
        } else {
            Err(DIDVCServiceVerifyError::SignatureNotVerified)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, iter::FromIterator as _};

    use serde_json::json;

    use super::*;
    use crate::{
        common::extension::trng::OSRandomNumberGenerator,
        did::{did_repository::mocks::MockDidRepository, test_utils::create_random_did},
        keyring::keypair::KeyPairing,
    };

    #[actix_rt::test]
    async fn test_generate_and_verify() {
        let from_did = create_random_did();

        let trng = OSRandomNumberGenerator::default();
        let from_keyring = KeyPairing::create_keyring(&trng).unwrap();

        let mock_repository =
            MockDidRepository::new(BTreeMap::from_iter([(from_did.clone(), from_keyring.clone())]));

        let service = DIDVCService::new(mock_repository);

        let message = json!({"test": "0123456789abcdef"});
        let issuance_date = Utc::now();

        let res = service.generate(&from_did, &from_keyring, &message, issuance_date).unwrap();

        let verified = service.verify(res).await.unwrap();

        assert_eq!(verified.issuer.id, from_did);
        assert_eq!(verified.credential_subject.container, message);
    }

    mod generate_failed {
        use super::*;
        use crate::keyring::secp256k1::Secp256k1;

        #[actix_rt::test]
        async fn test_generate_sign_failed() {
            let from_did = create_random_did();

            let trng = OSRandomNumberGenerator::default();
            let mut illegal_keyring = KeyPairing::create_keyring(&trng).unwrap();
            illegal_keyring.sign = Secp256k1::new(
                illegal_keyring.sign.get_public_key(),
                vec![0; illegal_keyring.sign.get_secret_key().len()],
            )
            .unwrap();

            let mock_repository = MockDidRepository::new(BTreeMap::new());

            let service = DIDVCService::new(mock_repository);

            let message = json!({"test": "0123456789abcdef"});
            let issuance_date = Utc::now();

            let res =
                service.generate(&from_did, &illegal_keyring, &message, issuance_date).unwrap_err();

            assert!(matches!(res, DIDVCServiceGenerateError::SignFailed(_)));
        }
    }

    mod verify_failed {
        use super::*;
        use crate::did::did_repository::mocks::{
            IllegalPublicKeyLengthDidRepository, NoPublicKeyDidRepository,
        };

        fn create_did_vc(
            from_did: &str,
            from_keyring: &KeyPairing,
            message: &Value,
            issuance_date: DateTime<Utc>,
        ) -> GeneralVcDataModel {
            let service = DIDVCService::new(MockDidRepository::new(BTreeMap::new()));

            service.generate(from_did, from_keyring, message, issuance_date).unwrap()
        }

        #[actix_rt::test]
        async fn test_did_not_found() {
            let from_did = create_random_did();

            let mock_repository = MockDidRepository::new(BTreeMap::new());

            let service = DIDVCService::new(mock_repository);

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
                &json!({}),
                Utc::now(),
            );

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::DIDNotFound(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_public_key_not_found() {
            let from_did = create_random_did();

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = NoPublicKeyDidRepository;
            let service = DIDVCService::new(mock_repository);

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::PublicKeyNotFound(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_verify_failed() {
            let from_did = create_random_did();

            let mut model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
                &json!({}),
                Utc::now(),
            );
            // for failing credential signer
            model.proof = None;

            let mock_repository = MockDidRepository::new(BTreeMap::from_iter([(
                from_did.clone(),
                KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
            )]));
            let service = DIDVCService::new(mock_repository);

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::VerifyFailed(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_public_key_length_mismatch() {
            let from_did = create_random_did();

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = IllegalPublicKeyLengthDidRepository;
            let service = DIDVCService::new(mock_repository);

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::PublicKeyLengthMismatch = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_signature_not_verified() {
            let from_did = create_random_did();

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = MockDidRepository::new(BTreeMap::from_iter([(
                from_did.clone(),
                KeyPairing::create_keyring(&OSRandomNumberGenerator::default()).unwrap(),
            )]));
            let service = DIDVCService::new(mock_repository);

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::SignatureNotVerified = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }
    }
}
