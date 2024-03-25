use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::common::runtime::base64_url::{self, PaddingType};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DIDCommMessage {
    pub ciphertext: String,
    pub iv: String,
    pub protected: String,
    pub recipients: Vec<Recipient>,
    pub tag: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Recipient {
    pub encrypted_key: String,
    pub header: Header,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Header {
    pub alg: String,
    pub epk: Epk,
    pub iv: String,
    pub key_ops: Vec<String>,
    pub kid: String,
    pub tag: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Epk {
    pub crv: String,
    pub kty: String,
    pub x: String,
}

impl DIDCommMessage {
    pub fn find_receivers(&self) -> anyhow::Result<Vec<String>> {
        let to_dids = self.recipients.iter().map(|v| v.header.kid.clone()).collect();

        Ok(to_dids)
    }

    pub fn find_sender(&self) -> anyhow::Result<String> {
        let protected = &self.protected;

        let decoded = base64_url::Base64Url::decode_as_string(protected, &PaddingType::NoPadding)
            .context("failed to base64 decode protected")?;
        let decoded = serde_json::from_str::<serde_json::Value>(&decoded)
            .context("failed to decode to json")?;

        let from_did = decoded
            .get("skid")
            .context("skid not found")?
            .as_str()
            .context("failed to serialize skid")?
            .to_string();

        Ok(from_did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE: &str = include_str!("../../test_resources/collect_didcomm_message.json");

    const FROM_DID: &str = "did:unid:test:EiBprXreMiba4loyl3psXm0RsECdtlCiQIjM8G9BtdQplA";
    const TO_DID: &str = "did:nodex:test:EiBprXreMiba4loyl3psXm0RsECdtlCiQIjM8G9BtdQplA";

    #[test]
    fn extract_from_did() {
        let message: DIDCommMessage = serde_json::from_str(MESSAGE).unwrap();
        let result = message.find_sender().unwrap();
        assert_eq!(&result, FROM_DID);
    }

    #[test]
    fn extract_from_did_when_invalid_base64() {
        let message = include_str!("../../test_resources/invalid_didcomm_message.json");
        let message: DIDCommMessage = serde_json::from_str(message).unwrap();
        let result = message.find_sender();
        assert!(result.is_err());
    }

    #[test]
    fn extract_to_did() {
        let message: DIDCommMessage = serde_json::from_str(MESSAGE).unwrap();
        let result = message.find_receivers().unwrap();
        let expected_did = vec![TO_DID.to_string()];
        assert_eq!(result, expected_did);
    }
}
