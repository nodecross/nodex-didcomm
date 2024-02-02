use super::{attachment_link, did_vc::DIDVCService, types::VerifiedContainer};
use crate::{
    errors::NodeXDidCommError,
    keyring::{self},
    schema::general::GeneralVcDataModel,
};
use cuid;
use didcomm_rs::{AttachmentBuilder, AttachmentDataBuilder, Message};
use serde_json::Value;

pub struct DIDCommPlaintextService {}

impl DIDCommPlaintextService {
    pub fn generate(
        to_did: &str,
        message: &Value,
        metadata: Option<&Value>,
    ) -> Result<Value, NodeXDidCommError> {
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

        let body = match DIDVCService::generate(message) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let mut message = match Message::new()
            .from(&did)
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

        match message.clone().as_raw_json() {
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

    pub fn verify(message: &Value) -> Result<VerifiedContainer, NodeXDidCommError> {
        let message = match Message::receive(&message.to_string(), None, None, None) {
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
