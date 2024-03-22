use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use super::signer::{Signer, SignerError};
use crate::nodex::{
    keyring::secp256k1::Secp256k1,
    runtime::{self, base64_url::PaddingType},
};

#[derive(Debug, Serialize, Deserialize)]
struct JWSHeader {
    alg: String,
    b64: bool,
    crit: Vec<String>,
}

pub struct Jws {}

#[derive(Debug, Error)]
pub enum JwsEncodeError {
    #[error(transparent)]
    SignerError(#[from] SignerError),
}

#[derive(Debug, Error)]
pub enum JwsDecodeError {
    #[error(transparent)]
    SignerError(#[from] SignerError),
    #[error("InvalidJws : {0}")]
    InvalidJws(String),
    #[error(transparent)]
    Base64UrlError(#[from] runtime::base64_url::Base64UrlError),
    #[error(transparent)]
    JsonParseError(#[from] serde_json::Error),
    #[error("InvalidAlgorithm: {0}")]
    InvalidAlgorithm(String),
    #[error("b64 option is not supported")]
    B64NotSupported,
    #[error("b64 option is not supported, but contained")]
    B64NotSupportedButContained,
    #[error("EmptyPayload")]
    EmptyPayload,
}

impl Jws {
    pub fn encode(object: &Value, context: &Secp256k1) -> Result<String, JwsEncodeError> {
        // NOTE: header
        let header =
            JWSHeader { alg: "ES256K".to_string(), b64: false, crit: vec!["b64".to_string()] };
        let header = runtime::base64_url::Base64Url::encode(
            json!(&header).to_string().as_bytes(),
            &PaddingType::NoPadding,
        );

        // NOTE: payload
        let payload = runtime::base64_url::Base64Url::encode(
            object.to_string().as_bytes(),
            &PaddingType::NoPadding,
        );

        // NOTE: message
        let message = [header.clone(), payload].join(".");

        // NOTE: signature
        let signature = Signer::sign(&message, context)?;
        let signature = runtime::base64_url::Base64Url::encode(&signature, &PaddingType::NoPadding);

        Ok([header, "".to_string(), signature].join("."))
    }

    pub fn verify(object: &Value, jws: &str, context: &Secp256k1) -> Result<bool, JwsDecodeError> {
        let split: Vec<String> = jws.split('.').map(|v| v.to_string()).collect();

        if split.len() != 3 {
            return Err(JwsDecodeError::InvalidJws(jws.to_string()));
        }

        let _header = split[0].clone();
        let __payload = split[1].clone();
        let _signature = split[2].clone();

        // NOTE: header
        let decoded =
            runtime::base64_url::Base64Url::decode_as_string(&_header, &PaddingType::NoPadding)?;
        let header = serde_json::from_str::<JWSHeader>(&decoded)?;

        if header.alg != *"ES256K" {
            return Err(JwsDecodeError::InvalidAlgorithm(header.alg));
        }
        if header.b64 {
            return Err(JwsDecodeError::B64NotSupported);
        }
        if header.crit.iter().all(|v| v != "b64") {
            return Err(JwsDecodeError::B64NotSupportedButContained);
        };

        // NOTE: payload
        if __payload != *"".to_string() {
            return Err(JwsDecodeError::EmptyPayload);
        }
        let _payload = runtime::base64_url::Base64Url::encode(
            object.to_string().as_bytes(),
            &PaddingType::NoPadding,
        );

        // NOTE: message
        let message = [_header, _payload].join(".");

        // NOTE: signature
        let signature =
            runtime::base64_url::Base64Url::decode_as_bytes(&_signature, &PaddingType::NoPadding)?;

        // NOTE: verify
        Ok(Signer::verify(&message, &signature, context)?)
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use crate::nodex::keyring::{self};

    const SECRET_KEY: [u8; 32] = [
        0xc7, 0x39, 0x80, 0x5a, 0xb0, 0x3d, 0xa6, 0x2d, 0xdb, 0xe0, 0x33, 0x90, 0xac, 0xdf, 0x76,
        0x15, 0x64, 0x0a, 0xa6, 0xed, 0x31, 0xb8, 0xf1, 0x82, 0x43, 0xf0, 0x4a, 0x57, 0x2c, 0x52,
        0x8e, 0xdb,
    ];

    const PUBLIC_KEY: [u8; 33] = [
        0x02, 0x70, 0x96, 0x45, 0x32, 0xf0, 0x83, 0xf4, 0x5f, 0xe8, 0xe8, 0xcc, 0xea, 0x96, 0xa2,
        0x2f, 0x60, 0x18, 0xd4, 0x6a, 0x40, 0x6f, 0x58, 0x3a, 0xb2, 0x26, 0xb1, 0x92, 0x83, 0xaa,
        0x60, 0x5c, 0x44,
    ];

    fn message() -> String {
        String::from(r#"{"k":"0123456789abcdef"}"#)
    }

    fn signature() -> String {
        String::from(
            "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ..vuhCrs1zs9Mlhof0TXgN9XQEY9ZJ2g2kZsH4Ef99wn5MR0pQOhkAHvgYZfHBvXOR795WnWKF_rUiE85abp5CAA",
        )
    }

    #[test]
    pub fn test_encode() {
        let context =
            keyring::secp256k1::Secp256k1::new(PUBLIC_KEY.to_vec(), SECRET_KEY.to_vec()).unwrap();

        let json: Value = serde_json::from_str(&message()).unwrap();

        let result = Jws::encode(&json, &context).unwrap();

        assert_eq!(result, signature())
    }

    #[test]
    pub fn test_verify() {
        let context =
            keyring::secp256k1::Secp256k1::new(PUBLIC_KEY.to_vec(), SECRET_KEY.to_vec()).unwrap();

        let json: Value = serde_json::from_str(&message()).unwrap();

        let result = Jws::verify(&json, &signature(), &context).unwrap();

        assert!(result)
    }
}
