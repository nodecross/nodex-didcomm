use std::ffi::CStr;

use crate::{
    config::did::{Extension, KeyPair},
    config::did_config,
    errors::NodeXDidCommError,
};

#[repr(C)]
enum SecureKeystoreType {
    Sign,
    Update,
    Recover,
    Encrypt,
}

#[derive(Debug)]
pub enum SecureKeyStoreType {
    Sign,
    Update,
    Recover,
    Encrypt,
}

pub struct SecureKeyStore {}

impl SecureKeyStore {
    const MAX_BUFFER_LENGTH: usize = 1024;

    pub fn new() -> SecureKeyStore {
        SecureKeyStore {}
    }

    fn write_external(
        &self,
        extension: &Extension,
        key_type: &SecureKeyStoreType,
        key_pair: &KeyPair,
    ) -> Result<(), NodeXDidCommError> {
        log::info!("Called: write_external (type: {:?})", key_type);

        unsafe {
            let encoded_secret_key = hex::encode(&key_pair.secret_key);
            let encoded_public_key = hex::encode(&key_pair.public_key);
            let secret_key = [encoded_secret_key.as_bytes(), b"\0"].concat();
            let public_key = [encoded_public_key.as_bytes(), b"\0"].concat();

            let secret_key_ptr: *const i8 = secret_key.as_ptr().cast();
            let public_key_ptr: *const i8 = public_key.as_ptr().cast();

            let lib = match libloading::Library::new(&extension.filename) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

            let func: libloading::Symbol<
                unsafe extern "C" fn(
                    key_type: SecureKeystoreType,
                    secret_key_buffer: *const i8,
                    public_key_buffer: *const i8,
                    secret_key_buffer_len: usize,
                    public_key_buffer_len: usize,
                ) -> u32,
            > = match lib.get(extension.symbol.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

            let result = match key_type {
                SecureKeyStoreType::Sign => func(
                    SecureKeystoreType::Sign,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
                SecureKeyStoreType::Update => func(
                    SecureKeystoreType::Update,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
                SecureKeyStoreType::Recover => func(
                    SecureKeystoreType::Recover,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
                SecureKeyStoreType::Encrypt => func(
                    SecureKeystoreType::Encrypt,
                    secret_key_ptr,
                    public_key_ptr,
                    encoded_secret_key.len(),
                    encoded_public_key.len(),
                ),
            };

            if result != 0 {
                Err(NodeXDidCommError {})
            } else {
                Ok(())
            }
        }
    }

    fn write_internal(
        &self,
        key_type: &SecureKeyStoreType,
        key_pair: &KeyPair,
    ) -> Result<(), NodeXDidCommError> {
        log::info!("Called: write_internal (type: {:?})", key_type);

        let config = did_config();

        match key_type {
            SecureKeyStoreType::Sign => match config.inner.lock() {
                Ok(mut config) => config.save_sign_key_pair(key_pair),
                _ => Err(NodeXDidCommError {}),
            },
            SecureKeyStoreType::Update => match config.inner.lock() {
                Ok(mut config) => config.save_update_key_pair(key_pair),
                _ => Err(NodeXDidCommError {}),
            },
            SecureKeyStoreType::Recover => match config.inner.lock() {
                Ok(mut config) => config.save_recover_key_pair(key_pair),
                _ => Err(NodeXDidCommError {}),
            },
            SecureKeyStoreType::Encrypt => match config.inner.lock() {
                Ok(mut config) => config.save_encrypt_key_pair(key_pair),
                _ => Err(NodeXDidCommError {}),
            },
        }
    }

    fn read_external(
        &self,
        extension: &Extension,
        key_type: &SecureKeyStoreType,
    ) -> Result<Option<KeyPair>, NodeXDidCommError> {
        log::info!("Called: read_external (type: {:?})", key_type);

        unsafe {
            let secret_key_buffer = [0u8; SecureKeyStore::MAX_BUFFER_LENGTH + 1];
            let public_key_buffer = [0u8; SecureKeyStore::MAX_BUFFER_LENGTH + 1];

            let secret_key_buffer_ptr: *const i8 = secret_key_buffer.as_ptr().cast();
            let public_key_buffer_ptr: *const i8 = public_key_buffer.as_ptr().cast();

            let secret_key_len = 0;
            let public_key_len = 0;

            let lib = match libloading::Library::new(&extension.filename) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

            let func: libloading::Symbol<
                unsafe extern "C" fn(
                    key_type: SecureKeystoreType,
                    secret_key_buffer: *const i8,
                    public_key_buffer: *const i8,
                    secret_key_buffer_len: usize,
                    public_key_buffer_len: usize,
                    secret_key_len: *const usize,
                    public_key_len: *const usize,
                ) -> u32,
            > = match lib.get(extension.symbol.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

            let result = match key_type {
                SecureKeyStoreType::Sign => func(
                    SecureKeystoreType::Sign,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
                SecureKeyStoreType::Update => func(
                    SecureKeystoreType::Update,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
                SecureKeyStoreType::Recover => func(
                    SecureKeystoreType::Recover,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
                SecureKeyStoreType::Encrypt => func(
                    SecureKeystoreType::Encrypt,
                    secret_key_buffer_ptr,
                    public_key_buffer_ptr,
                    secret_key_buffer.len(),
                    public_key_buffer.len(),
                    &secret_key_len,
                    &public_key_len,
                ),
            };

            let secret_key =
                match CStr::from_ptr(secret_key_buffer_ptr as *const core::ffi::c_char).to_str() {
                    Ok(v) => match hex::decode(v) {
                        Ok(v) => v,
                        _ => return Err(NodeXDidCommError {}),
                    },
                    _ => return Err(NodeXDidCommError {}),
                };
            let public_key =
                match CStr::from_ptr(public_key_buffer_ptr as *const core::ffi::c_char).to_str() {
                    Ok(v) => match hex::decode(v) {
                        Ok(v) => v,
                        _ => return Err(NodeXDidCommError {}),
                    },
                    _ => return Err(NodeXDidCommError {}),
                };

            if result == 0 {
                Ok(Some(KeyPair {
                    public_key,
                    secret_key,
                }))
            } else {
                Err(NodeXDidCommError {})
            }
        }
    }

    fn read_internal(
        &self,
        key_type: &SecureKeyStoreType,
    ) -> Result<Option<KeyPair>, NodeXDidCommError> {
        log::debug!("Called: read_internal (type: {:?})", key_type);

        let config = did_config();

        match key_type {
            SecureKeyStoreType::Sign => match config.inner.lock() {
                Ok(config) => Ok(config.load_sign_key_pair()),
                _ => Err(NodeXDidCommError {}),
            },
            SecureKeyStoreType::Update => match config.inner.lock() {
                Ok(config) => Ok(config.load_update_key_pair()),
                _ => Err(NodeXDidCommError {}),
            },
            SecureKeyStoreType::Recover => match config.inner.lock() {
                Ok(config) => Ok(config.load_recovery_key_pair()),
                _ => Err(NodeXDidCommError {}),
            },
            SecureKeyStoreType::Encrypt => match config.inner.lock() {
                Ok(config) => Ok(config.load_encrypt_key_pair()),
                _ => Err(NodeXDidCommError {}),
            },
        }
    }

    pub fn write(
        &self,
        key_type: &SecureKeyStoreType,
        key_pair: &KeyPair,
    ) -> Result<(), NodeXDidCommError> {
        let config = did_config();
        let extension = match config.inner.lock() {
            Ok(config) => config.load_secure_keystore_write_sig(),
            _ => return Err(NodeXDidCommError {}),
        };

        match extension {
            Some(v) => self.write_external(&v, key_type, key_pair),
            _ => self.write_internal(key_type, key_pair),
        }
    }

    pub fn read(
        &self,
        key_type: &SecureKeyStoreType,
    ) -> Result<Option<KeyPair>, NodeXDidCommError> {
        let config = did_config();
        let extension = match config.inner.lock() {
            Ok(config) => config.load_secure_keystore_read_sig(),
            _ => return Err(NodeXDidCommError {}),
        };

        match extension {
            Some(v) => self.read_external(&v, key_type),
            _ => self.read_internal(key_type),
        }
    }
}
