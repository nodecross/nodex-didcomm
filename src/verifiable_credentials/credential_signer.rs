use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use super::types::Proof;
use crate::{
    common::{cipher::jws::Jws, utils},
    keyring::secp256k1::Secp256k1,
    verifiable_credentials::types::VerifiableCredentials,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct ProofContext {
    #[serde(rename = "proof")]
    pub proof: Option<Proof>,
}

pub struct CredentialSignerSuite<'a> {
    pub did: &'a str,
    pub key_id: &'a str,
    pub context: &'a Secp256k1,
}

#[derive(Debug, Error)]
pub enum CredentialSignerSignError {
    #[error("jws error: {0:?}")]
    JwsError(#[from] crate::common::cipher::jws::JwsEncodeError),
    #[error("json parse error: {0:?}")]
    JsonParseError(#[from] serde_json::Error),
}

#[derive(Debug, Error)]
pub enum CredentialSignerVerifyError {
    #[error("jws error: {0:?}")]
    JwsError(#[from] crate::common::cipher::jws::JwsDecodeError),
    #[error("json parse error: {0:?}")]
    JsonParseError(#[from] serde_json::Error),
    #[error("proof not found")]
    ProofNotFound,
}

pub struct CredentialSigner {}

impl CredentialSigner {
    pub fn sign(
        object: &VerifiableCredentials,
        suite: CredentialSignerSuite,
        created: DateTime<Utc>,
    ) -> Result<VerifiableCredentials, CredentialSignerSignError> {
        let jws = Jws::encode(&json!(object), suite.context)?;

        let did = suite.did;
        let key_id = suite.key_id;

        let proof: ProofContext = ProofContext {
            proof: Some(Proof {
                r#type: "EcdsaSecp256k1Signature2019".to_string(),
                proof_purpose: "authentication".to_string(),
                created: created.to_rfc3339(),
                verification_method: format!("{}#{}", did, key_id),
                jws,
                domain: None,
                controller: None,
                challenge: None,
            }),
        };

        // NOTE: sign
        let mut signed_object = json!(object);

        utils::json::merge(&mut signed_object, json!(proof));

        Ok(serde_json::from_value::<VerifiableCredentials>(signed_object)?)
    }

    pub fn verify(
        mut object: VerifiableCredentials,
        context: &Secp256k1,
    ) -> Result<(VerifiableCredentials, bool), CredentialSignerVerifyError> {
        let proof = object.proof.take().ok_or(CredentialSignerVerifyError::ProofNotFound)?;

        let jws = proof.jws;
        let payload = serde_json::to_value(&object)?;

        let verified = Jws::verify(&payload, &jws, context)?;

        Ok((object, verified))
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::{
        keyring::{self},
        verifiable_credentials::types::{CredentialSubject, Issuer},
    };

    const PRIVATE_KEY: [u8; 32] = [
        0xc7, 0x39, 0x80, 0x5a, 0xb0, 0x3d, 0xa6, 0x2d, 0xdb, 0xe0, 0x33, 0x90, 0xac, 0xdf, 0x76,
        0x15, 0x64, 0x0a, 0xa6, 0xed, 0x31, 0xb8, 0xf1, 0x82, 0x43, 0xf0, 0x4a, 0x57, 0x2c, 0x52,
        0x8e, 0xdb,
    ];

    const PUBLIC_KEY: [u8; 33] = [
        0x02, 0x70, 0x96, 0x45, 0x32, 0xf0, 0x83, 0xf4, 0x5f, 0xe8, 0xe8, 0xcc, 0xea, 0x96, 0xa2,
        0x2f, 0x60, 0x18, 0xd4, 0x6a, 0x40, 0x6f, 0x58, 0x3a, 0xb2, 0x26, 0xb1, 0x92, 0x83, 0xaa,
        0x60, 0x5c, 0x44,
    ];

    #[test]
    pub fn test_sign() {
        let context =
            keyring::secp256k1::Secp256k1::new(PUBLIC_KEY.to_vec(), PRIVATE_KEY.to_vec()).unwrap();

        let model = VerifiableCredentials {
            id: None,
            r#type: vec!["type".to_string()],
            issuer: Issuer { id: "issuer".to_string() },
            context: vec!["context".to_string()],
            issuance_date: "issuance_date".to_string(),
            credential_subject: CredentialSubject {
                id: None,
                container: json!(r#"{"k":"0123456789abcdef"}"#),
            },
            expiration_date: None,
            proof: None,
        };

        let result = CredentialSigner::sign(
            &model,
            CredentialSignerSuite {
                did: "did:nodex:test:000000000000000000000000000000",
                key_id: "signingKey",
                context: &context,
            },
            Utc::now(),
        )
        .unwrap();

        match result.proof {
            Some(proof) => {
                assert_eq!(
                    proof.jws,
                    "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..Qc-NyzQu2v735_qPR72j1oqUDK1Ne4XQ7Lc66_x9tlMSeI9xmrgguEA8UmQyTM0cd13xkvpK4g-NEWJBp8_d_w"
                );
                assert_eq!(proof.proof_purpose, "authentication");
                assert_eq!(proof.r#type, "EcdsaSecp256k1Signature2019");
                assert_eq!(
                    proof.verification_method,
                    "did:nodex:test:000000000000000000000000000000#signingKey"
                );
            }
            None => panic!(),
        }
    }

    #[test]
    pub fn test_verify() {
        let context =
            keyring::secp256k1::Secp256k1::new(PUBLIC_KEY.to_vec(), PRIVATE_KEY.to_vec()).unwrap();

        let model = VerifiableCredentials {
            id: None,
            r#type: vec!["type".to_string()],
            issuer: Issuer { id: "issuer".to_string() },
            context: vec!["context".to_string()],
            issuance_date: "issuance_date".to_string(),
            credential_subject: CredentialSubject {
                id: None,
                container: json!(r#"{"k":"0123456789abcdef"}"#),
            },
            expiration_date: None,
            proof: None,
        };

        let vc = CredentialSigner::sign(
            &model,
            CredentialSignerSuite {
                did: "did:nodex:test:000000000000000000000000000000",
                key_id: "signingKey",
                context: &context,
            },
            Utc::now(),
        )
        .unwrap();

        let (verified_model, verified) = CredentialSigner::verify(vc, &context).unwrap();

        assert!(verified);
        assert_eq!(model, verified_model);
    }
}
