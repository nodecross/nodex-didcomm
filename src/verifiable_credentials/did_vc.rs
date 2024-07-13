use std::marker::Sync;

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

use crate::{
    did::did_repository::{DidRepository, GetPublicKeyError},
    keyring::keypair,
    verifiable_credentials::{
        credential_signer::{
            CredentialSigner, CredentialSignerSignError, CredentialSignerSuite,
            CredentialSignerVerifyError,
        },
        types::{CredentialSubject, Issuer, VerifiableCredentials},
    },
};

#[derive(Clone)]
pub struct DIDVCService<R: DidRepository + Sync> {
    pub(crate) did_repository: R,
}

#[derive(Debug, Error)]
pub enum DIDVCServiceGenerateError {
    #[error("credential signer error")]
    SignFailed(#[from] CredentialSignerSignError),
}

#[derive(Debug, Error)]
pub enum DIDVCServiceVerifyError {
    #[error("did public key not found. did: {0}")]
    PublicKeyNotFound(#[from] GetPublicKeyError),
    #[error("credential signer error")]
    VerifyFailed(#[from] CredentialSignerVerifyError),
}

impl<R: DidRepository + Sync> DIDVCService<R> {
    pub fn new(did_repository: R) -> Self {
        Self { did_repository }
    }
    pub fn generate(
        &self,
        from_did: &str,
        from_keyring: &keypair::KeyPairing,
        message: &Value,
        issuance_date: DateTime<Utc>,
    ) -> Result<VerifiableCredentials, DIDVCServiceGenerateError> {
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

    pub async fn verify(
        &self,
        model: VerifiableCredentials,
    ) -> Result<VerifiableCredentials, DIDVCServiceVerifyError> {
        let public_key = self.did_repository.get_sign_key(&model.issuer.id).await?;
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

        let service = DIDVCService::new(mock_repository);

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
            let service = DIDVCService::new(MockDidRepository::from_single(BTreeMap::new()));

            service.generate(from_did, from_keyring, message, issuance_date).unwrap()
        }

        #[actix_rt::test]
        async fn test_did_not_found() {
            let from_did = create_random_did();

            let mock_repository = MockDidRepository::from_single(BTreeMap::new());

            let service = DIDVCService::new(mock_repository);

            let model = create_did_vc(
                &from_did,
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::PublicKeyNotFound(GetPublicKeyError::DidDocNotFound(
                _,
            )) = res
            {
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
                &KeyPairing::create_keyring(OsRng),
                &json!({}),
                Utc::now(),
            );

            let mock_repository = IllegalPublicKeyLengthDidRepository;
            let service = DIDVCService::new(mock_repository);

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::PublicKeyNotFound(_) = res {
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
            let service = DIDVCService::new(mock_repository);

            let res = service.verify(model).await.unwrap_err();

            if let DIDVCServiceVerifyError::VerifyFailed(_) = res {
            } else {
                panic!("unexpected error: {:?}", res);
            }
        }
    }
}
