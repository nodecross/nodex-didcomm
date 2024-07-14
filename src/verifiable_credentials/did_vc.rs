use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    did::did_repository::{get_sign_key, DidRepository, GetPublicKeyError},
    keyring::keypair,
    verifiable_credentials::{
        credential_signer::{
            CredentialSigner, CredentialSignerSignError, CredentialSignerSuite,
            CredentialSignerVerifyError,
        },
        types::{CredentialSubject, Issuer, VerifiableCredentials},
    },
};

#[async_trait::async_trait]
pub trait DidVcService: Sync {
    type GenerateError: std::error::Error;
    type VerifyError: std::error::Error;
    fn generate(
        &self,
        from_did: &str,
        from_keyring: &keypair::KeyPairing,
        message: &Value,
        issuance_date: DateTime<Utc>,
    ) -> Result<VerifiableCredentials, Self::GenerateError>;
    async fn verify(
        &self,
        model: VerifiableCredentials,
    ) -> Result<VerifiableCredentials, Self::VerifyError>;
}

#[derive(Debug, Error)]
pub enum DidVcServiceGenerateError {
    #[error("credential signer error")]
    SignFailed(#[from] CredentialSignerSignError),
}

#[derive(Debug, Error)]
pub enum DidVcServiceVerifyError<FindIdentifierError: std::error::Error> {
    #[error("did public key not found. did: {0}")]
    PublicKeyNotFound(#[from] GetPublicKeyError),
    #[error("failed to get did document: {0}")]
    DidDocNotFound(String),
    #[error("failed to find indentifier: {0}")]
    FindIdentifierError(FindIdentifierError),
    #[error("credential signer error")]
    VerifyFailed(#[from] CredentialSignerVerifyError),
}

#[async_trait::async_trait]
impl<R: DidRepository> DidVcService for R {
    type GenerateError = DidVcServiceGenerateError;
    type VerifyError = DidVcServiceVerifyError<R::FindIdentifierError>;
    fn generate(
        &self,
        from_did: &str,
        from_keyring: &keypair::KeyPairing,
        message: &Value,
        issuance_date: DateTime<Utc>,
    ) -> Result<VerifiableCredentials, Self::GenerateError> {
        let r#type = "VerifiableCredential".to_string();
        let context = "https://www.w3.org/2018/credentials/v1".to_string();

        let model = VerifiableCredentials {
            id: None,
            issuer: Issuer { id: from_did.to_string() },
            r#type: vec![r#type],
            context: vec![context],
            issuance_date: issuance_date.to_rfc3339(),
            credential_subject: CredentialSubject { id: None, container: message.clone() },
            expiration_date: None,
            proof: None,
        };

        let signed: VerifiableCredentials = CredentialSigner::sign(
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

    async fn verify(
        &self,
        model: VerifiableCredentials,
    ) -> Result<VerifiableCredentials, Self::VerifyError> {
        let did_document = self
            .find_identifier(&model.issuer.id)
            .await
            .map_err(Self::VerifyError::FindIdentifierError)?;
        let did_document = did_document
            .ok_or(DidVcServiceVerifyError::DidDocNotFound(model.issuer.id.clone()))?
            .did_document;
        let public_key = get_sign_key(&did_document)?;
        Ok(CredentialSigner::verify(model, &public_key)?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, iter::FromIterator as _};

    use rand_core::OsRng;
    use serde_json::json;

    use super::*;
    use crate::{
        did::{did_repository::mocks::MockDidRepository, test_utils::create_random_did},
        keyring::keypair::KeyPairing,
    };

    #[actix_rt::test]
    async fn test_generate_and_verify() {
        let from_did = create_random_did();

        let from_keyring = KeyPairing::create_keyring(OsRng);

        let mock_repository = MockDidRepository::from_single(BTreeMap::from_iter([(
            from_did.clone(),
            from_keyring.clone(),
        )]));

        let service = mock_repository;

        let message = json!({"test": "0123456789abcdef"});
        let issuance_date = Utc::now();

        let res = service.generate(&from_did, &from_keyring, &message, issuance_date).unwrap();

        let verified = service.verify(res).await.unwrap();

        assert_eq!(verified.issuer.id, from_did);
        assert_eq!(verified.credential_subject.container, message);
    }

    mod generate_failed {}

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
        ) -> VerifiableCredentials {
            let service = MockDidRepository::from_single(BTreeMap::new());

            service.generate(from_did, from_keyring, message, issuance_date).unwrap()
        }

        #[actix_rt::test]
        async fn test_did_not_found() {
            let from_did = create_random_did();

            let mock_repository = MockDidRepository::from_single(BTreeMap::new());

            let service = mock_repository;

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );

            let res = service.verify(model).await.unwrap_err();

            if let DidVcServiceVerifyError::DidDocNotFound(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_public_key_not_found() {
            let from_did = create_random_did();

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = NoPublicKeyDidRepository;
            let service = mock_repository;

            let res = service.verify(model).await.unwrap_err();

            if let DidVcServiceVerifyError::PublicKeyNotFound(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_verify_failed() {
            let from_did = create_random_did();

            let mut model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );
            // for failing credential signer
            model.proof = None;

            let mock_repository = MockDidRepository::from_single(BTreeMap::from_iter([(
                from_did.clone(),
                KeyPairing::create_keyring(OsRng),
            )]));
            let service = mock_repository;

            let res = service.verify(model).await.unwrap_err();

            if let DidVcServiceVerifyError::VerifyFailed(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_public_key_length_mismatch() {
            let from_did = create_random_did();

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = IllegalPublicKeyLengthDidRepository;
            let service = mock_repository;

            let res = service.verify(model).await.unwrap_err();

            if let DidVcServiceVerifyError::PublicKeyNotFound(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }

        #[actix_rt::test]
        async fn test_signature_not_verified() {
            let from_did = create_random_did();

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = MockDidRepository::from_single(BTreeMap::from_iter([(
                from_did.clone(),
                KeyPairing::create_keyring(OsRng),
            )]));
            let service = mock_repository;

            let res = service.verify(model).await.unwrap_err();

            if let DidVcServiceVerifyError::VerifyFailed(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }
    }
}
