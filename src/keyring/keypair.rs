use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::secp256k1::{Secp256k1, Secp256k1Error, Secp256k1HexKeyPair};
use crate::common::{extension::trng::Trng, runtime};

#[derive(Debug, Clone)]
pub struct KeyPairing {
    pub sign: Secp256k1,
    pub update: Secp256k1,
    pub recovery: Secp256k1,
    pub encrypt: Secp256k1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct KeyPairingHex {
    pub sign: Secp256k1HexKeyPair,
    pub update: Secp256k1HexKeyPair,
    pub recovery: Secp256k1HexKeyPair,
    pub encrypt: Secp256k1HexKeyPair,
}

#[derive(Error, Debug)]
pub enum KeyPairingError {
    #[error("secp256k1 error")]
    KeyInitializationFailed(#[from] Secp256k1Error),
    #[error("Trng error")]
    TrngGenerationFailed(#[from] crate::common::extension::trng::TrngError),
    #[error("BIP32 error")]
    BIP32Error(#[from] runtime::bip32::BIP32Error),
}

impl KeyPairing {
    const SIGN_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/10";
    const UPDATE_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/20";
    const RECOVERY_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/30";
    const ENCRYPT_DERIVATION_PATH: &'static str = "m/44'/0'/0'/0/40";

    pub fn create_keyring<T: Trng>(trng: &T) -> Result<Self, KeyPairingError> {
        let seed = trng.generate(&(256 / 8))?;

        let sign = Self::generate_secp256k1(&seed, Self::SIGN_DERIVATION_PATH)?;
        let update = Self::generate_secp256k1(&seed, Self::UPDATE_DERIVATION_PATH)?;
        let recovery = Self::generate_secp256k1(&seed, Self::RECOVERY_DERIVATION_PATH)?;
        let encrypt = Self::generate_secp256k1(&seed, Self::ENCRYPT_DERIVATION_PATH)?;

        Ok(KeyPairing { sign, update, recovery, encrypt })
    }

    fn generate_secp256k1(
        seed: &[u8],
        derivation_path: &str,
    ) -> Result<Secp256k1, KeyPairingError> {
        let node = runtime::bip32::BIP32::get_node(seed, derivation_path)?;

        Ok(Secp256k1::from_bip32(node)?)
    }
}

impl From<&KeyPairing> for KeyPairingHex {
    fn from(keypair: &KeyPairing) -> Self {
        KeyPairingHex {
            sign: keypair.sign.to_hex_key_pair(),
            update: keypair.update.to_hex_key_pair(),
            recovery: keypair.recovery.to_hex_key_pair(),
            encrypt: keypair.encrypt.to_hex_key_pair(),
        }
    }
}

impl TryFrom<&KeyPairingHex> for KeyPairing {
    type Error = KeyPairingError;

    fn try_from(hex: &KeyPairingHex) -> Result<Self, Self::Error> {
        let sign = Secp256k1::from_hex_key_pair(&hex.sign)?;
        let update = Secp256k1::from_hex_key_pair(&hex.update)?;
        let recovery = Secp256k1::from_hex_key_pair(&hex.recovery)?;
        let encrypt = Secp256k1::from_hex_key_pair(&hex.encrypt)?;

        Ok(KeyPairing { sign, update, recovery, encrypt })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::common::extension::trng::OSRandomNumberGenerator;

    #[test]
    pub fn test_create_keyring() {
        let trng = OSRandomNumberGenerator::default();
        let keyring = KeyPairing::create_keyring(&trng).unwrap();

        assert_eq!(keyring.sign.get_secret_key().len(), 32);
        assert_eq!(keyring.update.get_secret_key().len(), 32);
        assert_eq!(keyring.recovery.get_secret_key().len(), 32);
        assert_eq!(keyring.encrypt.get_secret_key().len(), 32);
    }
}
