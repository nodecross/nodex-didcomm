use super::{attachment_link, did_vc::DIDVCService, types::VerifiedContainer};
use crate::{
    client::nodex::NodeX,
    errors::NodeXDidCommError,
    keyring::{self},
    runtime::{
        self,
        base64_url::{self, PaddingType},
    },
    schema::general::GeneralVcDataModel,
};
use arrayref::array_ref;
use cuid;
use didcomm_rs::{
    crypto::{CryptoAlgorithm, SignatureAlgorithm},
    AttachmentBuilder, AttachmentDataBuilder, Message,
};
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct DIDCommEncryptedService {}

impl DIDCommEncryptedService {
    pub async fn generate(
        to_did: &str,
        message: &Value,
        metadata: Option<&Value>,
    ) -> Result<Value, NodeXDidCommError> {
        let nodex_client = NodeX::new();

        // NOTE: recipient from
        let my_keyring = match keyring::keypair::KeyPairing::load_keyring() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };
        let my_did: String = match my_keyring.get_identifier() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: recipient to
        let did_document = match nodex_client.find_identifier(to_did).await {
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

        let other_key = match keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: ecdh
        let shared_key = match runtime::secp256k1::Secp256k1::ecdh(
            &my_keyring.get_sign_key_pair().get_secret_key(),
            &other_key.get_public_key(),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let sk = StaticSecret::from(array_ref!(shared_key, 0, 32).to_owned());
        let pk = PublicKey::from(&sk);

        // NOTE: message
        let body = match DIDVCService::generate(message) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let mut message = match Message::new()
            .from(&my_did)
            .to(&[to_did])
            .body(&body.to_string())
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("Failed to initialize message with error = {:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: Has attachment
        if let Some(value) = metadata {
            let id = cuid::cuid2();

            // let media_type = "application/json";
            let data = AttachmentDataBuilder::new()
                .with_link(&attachment_link())
                .with_json(&value.to_string());

            message.append_attachment(
                AttachmentBuilder::new(true)
                    .with_id(&id)
                    .with_format("metadata")
                    .with_data(data),
            )
        }

        match message
            .clone()
            .as_jwe(&CryptoAlgorithm::XC20P, Some(pk.as_bytes().to_vec()))
            .seal_signed(
                sk.to_bytes().as_ref(),
                Some(vec![Some(pk.as_bytes().to_vec())]),
                SignatureAlgorithm::Es256k,
                &my_keyring.get_sign_key_pair().get_secret_key(),
            ) {
            Ok(v) => match serde_json::from_str::<Value>(&v) {
                Ok(v) => Ok(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    Err(NodeXDidCommError {})
                }
            },
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXDidCommError {})
            }
        }
    }

    pub async fn verify(message: &Value) -> Result<VerifiedContainer, NodeXDidCommError> {
        let nodex_client = NodeX::new();

        // NOTE: recipient to
        let my_keyring = match keyring::keypair::KeyPairing::load_keyring() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: recipient from
        let protected = match message.get("protected") {
            Some(v) => match v.as_str() {
                Some(v) => v.to_string(),
                None => return Err(NodeXDidCommError {}),
            },
            None => return Err(NodeXDidCommError {}),
        };

        let decoded =
            match base64_url::Base64Url::decode_as_string(&protected, &PaddingType::NoPadding) {
                Ok(v) => match serde_json::from_str::<Value>(&v) {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("{:?}", e);
                        return Err(NodeXDidCommError {});
                    }
                },
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

        let other_did = match decoded.get("skid") {
            Some(v) => match v.as_str() {
                Some(v) => v.to_string(),
                None => return Err(NodeXDidCommError {}),
            },
            None => return Err(NodeXDidCommError {}),
        };

        let did_document = match nodex_client.find_identifier(&other_did).await {
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

        let other_key = match keyring::secp256k1::Secp256k1::from_jwk(&public_key.public_key_jwk) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: ecdh
        let shared_key = match runtime::secp256k1::Secp256k1::ecdh(
            &my_keyring.get_sign_key_pair().get_secret_key(),
            &other_key.get_public_key(),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let sk = StaticSecret::from(array_ref!(shared_key, 0, 32).to_owned());
        let pk = PublicKey::from(&sk);

        let message = match Message::receive(
            &message.to_string(),
            Some(sk.to_bytes().as_ref()),
            Some(pk.as_bytes().to_vec()),
            Some(&other_key.get_public_key()),
        ) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let metadata = message
            .attachment_iter()
            .find(|item| match item.format.clone() {
                Some(value) => value == "metadata",
                None => false,
            });

        let body = match message.clone().get_body() {
            Ok(v) => match serde_json::from_str::<GeneralVcDataModel>(&v) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            },
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        match metadata {
            Some(metadata) => match metadata.data.json.clone() {
                Some(json) => match serde_json::from_str::<Value>(&json) {
                    Ok(metadata) => Ok(VerifiedContainer {
                        message: body,
                        metadata: Some(metadata),
                    }),
                    _ => Err(NodeXDidCommError {}),
                },
                _ => Err(NodeXDidCommError {}),
            },
            None => Ok(VerifiedContainer {
                message: body,
                metadata: None,
            }),
        }
    }
}
