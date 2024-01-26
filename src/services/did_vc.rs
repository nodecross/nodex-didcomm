use crate::{
    cipher::credential_signer::{CredentialSigner, CredentialSignerSuite},
    client::nodex::NodeX,
    errors::NodeXDidCommError,
    keyring::{self},
    schema::general::{CredentialSubject, GeneralVcDataModel, Issuer},
};
use chrono::Utc;
use serde_json::{json, Value};

pub struct DIDVCService {}

impl DIDVCService {
    pub fn generate(message: &Value) -> Result<Value, NodeXDidCommError> {
        let keyring = match keyring::keypair::KeyPairing::load_keyring() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };
        let did = match keyring.get_identifier() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let r#type = "VerifiableCredential".to_string();
        let context = "https://www.w3.org/2018/credentials/v1".to_string();
        let issuance_date = Utc::now().to_rfc3339();

        let model = GeneralVcDataModel {
            id: None,
            issuer: Issuer { id: did.clone() },
            r#type: vec![r#type],
            context: vec![context],
            issuance_date,
            credential_subject: CredentialSubject {
                id: None,
                container: message.clone(),
            },
            expiration_date: None,
            proof: None,
        };

        let signed = match CredentialSigner::sign(
            &model,
            &CredentialSignerSuite {
                did: Some(did),
                key_id: Some("signingKey".to_string()),
                context: keyring.get_sign_key_pair(),
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        Ok(json!(signed))
    }

    pub async fn verify(message: &Value) -> Result<Value, NodeXDidCommError> {
        let nodex_client = NodeX::new();

        let model = match serde_json::from_value::<GeneralVcDataModel>(message.clone()) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let did_document = match nodex_client.find_identifier(&model.issuer.id).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };
        let public_keys = match did_document.did_document.public_key {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };

        // FIXME: workaround
        if public_keys.len() != 1 {
            return Err(NodeXDidCommError {});
        }

        let public_key = public_keys[0].clone();

        let context = match keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let (verified_model, verified) = match CredentialSigner::verify(
            &model,
            &CredentialSignerSuite {
                did: None,
                key_id: None,
                context,
            },
        ) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        if !verified {
            return Err(NodeXDidCommError {});
        }

        Ok(verified_model)
    }
}
