use home_config::HomeConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;

use crate::errors::NodeXDidCommError;

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

#[derive(Debug, Clone, Deserialize, Serialize)]
struct KeyPairConfig {
    public_key: String,
    secret_key: String,
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

impl DidConfig {
    fn touch(path: &Path) -> io::Result<()> {
        match OpenOptions::new().create(true).write(true).open(path) {
            Ok(mut file) => match file.write_all(b"{}") {
                Ok(_) => Ok(()),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        }
    }

    pub fn new() -> Self {
        let config = HomeConfig::with_config_dir("nodex", "config.json");
        let config_dir = config.path().parent();

        if !Path::exists(config.path()) {
            match config_dir {
                Some(v) => {
                    match fs::create_dir_all(v) {
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("{:?}", e);
                            panic!()
                        }
                    };
                }
                None => panic!(),
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

    pub fn write(&self) -> Result<(), NodeXDidCommError> {
        match self.config.save_json(&self.root) {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    pub fn encode(&self, value: &Option<Vec<u8>>) -> Option<String> {
        value.as_ref().map(hex::encode)
    }

    pub fn decode(&self, value: &Option<String>) -> Option<Vec<u8>> {
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
        match self.root.key_pairs.sign.clone() {
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

    pub fn save_sign_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXDidCommError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };
        let sk = match self.encode(&Some(value.secret_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };

        self.root.key_pairs.sign = Some(KeyPairConfig {
            public_key: pk,
            secret_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
    }

    // NOTE: UPDATE
    pub fn load_update_key_pair(&self) -> Option<KeyPair> {
        match self.root.key_pairs.update.clone() {
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

    pub fn save_update_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXDidCommError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };
        let sk = match self.encode(&Some(value.secret_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };

        self.root.key_pairs.update = Some(KeyPairConfig {
            public_key: pk,
            secret_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
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

    pub fn save_recover_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXDidCommError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };
        let sk = match self.encode(&Some(value.secret_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };

        self.root.key_pairs.recover = Some(KeyPairConfig {
            public_key: pk,
            secret_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
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

    pub fn save_encrypt_key_pair(&mut self, value: &KeyPair) -> Result<(), NodeXDidCommError> {
        let pk = match self.encode(&Some(value.public_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };
        let sk = match self.encode(&Some(value.secret_key.clone())) {
            Some(v) => v,
            None => return Err(NodeXDidCommError {}),
        };

        self.root.key_pairs.encrypt = Some(KeyPairConfig {
            public_key: pk,
            secret_key: sk,
        });

        match self.write() {
            Ok(_) => Ok(()),
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        }
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
