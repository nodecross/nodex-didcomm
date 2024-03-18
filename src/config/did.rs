use home_config::HomeConfig;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use thiserror::Error;

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

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl KeyPair {
    fn to_keypair_config(&self) -> KeyPairConfig {
        KeyPairConfig {
            public_key: hex::encode(&self.public_key),
            secret_key: hex::encode(&self.secret_key),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KeyPairConfig {
    public_key: String,
    secret_key: String,
}

impl KeyPairConfig {
    fn to_keypair(&self) -> Result<KeyPair, Box<dyn Error>> {
        let pk = hex::decode(&self.public_key)?;
        let sk = hex::decode(&self.secret_key)?;

        Ok(KeyPair {
            public_key: pk,
            secret_key: sk,
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyPairsConfig {
    sign: Option<KeyPairConfig>,
    update: Option<KeyPairConfig>,
    recover: Option<KeyPairConfig>,
    encrypt: Option<KeyPairConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigRoot {
    did: Option<String>,
    key_pairs: KeyPairsConfig,
    extensions: ExtensionsConfig,
    is_initialized: bool,
    schema_version: u8,
}

impl Default for ConfigRoot {
    fn default() -> Self {
        ConfigRoot {
            did: None,
            key_pairs: KeyPairsConfig {
                sign: None,
                update: None,
                recover: None,
                encrypt: None,
            },
            extensions: ExtensionsConfig {
                trng: None,
                secure_keystore: None,
                cipher: None,
            },
            is_initialized: false,
            schema_version: 1,
        }
    }
}

#[derive(Debug)]
pub struct DidConfig {
    config: HomeConfig,
    root: ConfigRoot,
}

#[derive(Error, Debug)]
pub enum DidConfigError {
    #[error("key decode failed")]
    DecodeFailed(Box<dyn std::error::Error>),
    #[error("failed to write config file")]
    WriteError(home_config::JsonError),
}

impl DidConfig {
    fn touch(path: &Path) -> io::Result<()> {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        file.write_all(b"{}")?;
        Ok(())
    }

    const APP_NAME: &'static str = "nodex";
    const CONFIG_FILE: &'static str = "config.json";

    pub fn new() -> Self {
        let config = HomeConfig::with_config_dir(DidConfig::APP_NAME, DidConfig::CONFIG_FILE);
        let config_dir = config.path().parent().expect("unreachable");

        if !Path::exists(config.path()) {
            match fs::create_dir_all(config_dir) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                    panic!()
                }
            };

            match Self::touch(config.path()) {
                Ok(_) => {}
                Err(e) => {
                    log::error!("{:?}", e);
                    panic!()
                }
            };
        }

        let root = match config.json::<ConfigRoot>() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        DidConfig { root, config }
    }

    pub fn write(&self) -> Result<(), DidConfigError> {
        self.config
            .save_json(&self.root)
            .map_err(DidConfigError::WriteError)
    }

    fn decode(&self, value: &Option<String>) -> Option<Vec<u8>> {
        match value {
            Some(v) => match hex::decode(v) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    None
                }
            },
            None => None,
        }
    }

    // NOTE: trng - read
    pub fn load_trng_read_sig(&self) -> Option<Extension> {
        match self.root.extensions.trng.clone() {
            Some(v) => Some(v.read),
            None => None,
        }
    }

    // NOTE: secure_keystore - write
    pub fn load_secure_keystore_write_sig(&self) -> Option<Extension> {
        match self.root.extensions.secure_keystore.clone() {
            Some(v) => Some(v.write),
            None => None,
        }
    }

    // NOTE: secure_keystore - read
    pub fn load_secure_keystore_read_sig(&self) -> Option<Extension> {
        match self.root.extensions.secure_keystore.clone() {
            Some(v) => Some(v.read),
            None => None,
        }
    }

    // NOTE: cipher - encrypt
    #[allow(dead_code)]
    pub fn load_cipher_encrypt_sig(&self) -> Option<Extension> {
        match self.root.extensions.cipher.clone() {
            Some(v) => Some(v.encrypt),
            None => None,
        }
    }

    // NOTE: cipher - decrypt
    #[allow(dead_code)]
    pub fn load_cipher_decrypt_sig(&self) -> Option<Extension> {
        match self.root.extensions.cipher.clone() {
            Some(v) => Some(v.decrypt),
            None => None,
        }
    }

    // NOTE: SIGN
    pub fn load_sign_key_pair(&self) -> Option<KeyPair> {
        if let Some(ref key) = self.root.key_pairs.sign {
            match Self::convert_to_key(key) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    fn convert_to_key(config: &KeyPairConfig) -> Result<KeyPair, DidConfigError> {
        config.to_keypair().map_err(DidConfigError::DecodeFailed)
    }

    pub fn save_sign_key_pair(&mut self, value: &KeyPair) -> Result<(), DidConfigError> {
        self.root.key_pairs.sign = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: UPDATE
    pub fn load_update_key_pair(&self) -> Option<KeyPair> {
        if let Some(ref key) = self.root.key_pairs.update {
            match Self::convert_to_key(key) {
                Ok(v) => Some(v),
                Err(e) => {
                    log::error!("{:?}", e);
                    None
                }
            }
        } else {
            None
        }
    }

    pub fn save_update_key_pair(&mut self, value: &KeyPair) -> Result<(), DidConfigError> {
        self.root.key_pairs.update = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: RECOVER
    pub fn load_recovery_key_pair(&self) -> Option<KeyPair> {
        match self.root.key_pairs.recover.clone() {
            Some(v) => {
                let pk = match self.decode(&Some(v.public_key)) {
                    Some(v) => v,
                    None => return None,
                };
                let sk = match self.decode(&Some(v.secret_key)) {
                    Some(v) => v,
                    None => return None,
                };

                Some(KeyPair {
                    public_key: pk,
                    secret_key: sk,
                })
            }
            None => None,
        }
    }

    pub fn save_recover_key_pair(&mut self, value: &KeyPair) -> Result<(), DidConfigError> {
        self.root.key_pairs.recover = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: ENCRYPT
    pub fn load_encrypt_key_pair(&self) -> Option<KeyPair> {
        match self.root.key_pairs.encrypt.clone() {
            Some(v) => {
                let pk = match self.decode(&Some(v.public_key)) {
                    Some(v) => v,
                    None => return None,
                };
                let sk = match self.decode(&Some(v.secret_key)) {
                    Some(v) => v,
                    None => return None,
                };

                Some(KeyPair {
                    public_key: pk,
                    secret_key: sk,
                })
            }
            None => None,
        }
    }

    pub fn save_encrypt_key_pair(&mut self, value: &KeyPair) -> Result<(), DidConfigError> {
        self.root.key_pairs.encrypt = Some(value.to_keypair_config());
        self.write()
    }

    // NOTE: DID
    pub fn get_did(&self) -> Option<String> {
        self.root.did.clone()
    }

    pub fn save_did(&mut self, value: &str) {
        self.root.did = Some(value.to_string());

        match self.write() {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    // NOTE: Is Initialized
    #[allow(dead_code)]
    pub fn get_is_initialized(&self) -> bool {
        self.root.is_initialized
    }

    pub fn save_is_initialized(&mut self, value: bool) {
        self.root.is_initialized = value;
        match self.write() {
            Ok(_) => {}
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }
}
