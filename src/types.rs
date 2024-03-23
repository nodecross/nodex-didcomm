use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::nodex::keyring::{
    keypair::KeyPairing,
    secp256k1::{Secp256k1, Secp256k1Error, Secp256k1HexKeyPair},
};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Extension {
    pub filename: String,
    pub symbol: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TRNGExtensionConfig {
    pub read: Extension,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecureKeystoreExtensionConfig {
    pub write: Extension,
    pub read: Extension,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CipherExtensionConfig {
    pub encrypt: Extension,
    pub decrypt: Extension,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExtensionsConfig {
    pub trng: Option<TRNGExtensionConfig>,
    pub secure_keystore: Option<SecureKeystoreExtensionConfig>,
    pub cipher: Option<CipherExtensionConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyPairConfigs {
    pub sign: Secp256k1HexKeyPair,
    pub update: Secp256k1HexKeyPair,
    pub recover: Secp256k1HexKeyPair,
    pub encrypt: Secp256k1HexKeyPair,
}

impl TryFrom<&KeyPairConfigs> for KeyPairing {
    type Error = Secp256k1Error;

    fn try_from(value: &KeyPairConfigs) -> Result<Self, Self::Error> {
        Ok(KeyPairing {
            sign: Secp256k1::try_from(&value.sign)?,
            update: Secp256k1::try_from(&value.update)?,
            recovery: Secp256k1::try_from(&value.recover)?,
            encrypt: Secp256k1::try_from(&value.encrypt)?,
        })
    }
}

impl From<&KeyPairing> for KeyPairConfigs {
    fn from(value: &KeyPairing) -> Self {
        KeyPairConfigs {
            sign: (&value.sign).into(),
            update: (&value.update).into(),
            recover: (&value.recovery).into(),
            encrypt: (&value.encrypt).into(),
        }
    }
}
