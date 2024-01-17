use crate::{
    config::did::Extension, config::did_config, errors::NodeXDidCommError, runtime::random::Random,
};
use std::ffi::CStr;

pub struct Trng {}

impl Trng {
    const MAX_BUFFER_LENGTH: usize = 1024;

    pub fn new() -> Trng {
        Trng {}
    }

    fn read_external(
        &self,
        extension: &Extension,
        size: &usize,
    ) -> Result<Vec<u8>, NodeXDidCommError> {
        log::info!("Called: read_external");

        if Trng::MAX_BUFFER_LENGTH < *size {
            return Err(NodeXDidCommError {});
        }

        unsafe {
            let buffer = [0u8; Trng::MAX_BUFFER_LENGTH + 1];
            let buffer_ptr: *const i8 = buffer.as_ptr().cast();

            let lib = match libloading::Library::new(&extension.filename) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

            let func: libloading::Symbol<
                unsafe extern "C" fn(buf: *const i8, bufsize: usize, size: usize) -> u32,
            > = match lib.get(extension.symbol.as_bytes()) {
                Ok(v) => v,
                Err(e) => {
                    log::error!("{:?}", e);
                    return Err(NodeXDidCommError {});
                }
            };

            let result = func(buffer_ptr, buffer.len(), *size);

            if result != 0 {
                return Err(NodeXDidCommError {});
            }

            Ok(CStr::from_ptr(buffer_ptr as *const core::ffi::c_char)
                .to_bytes()
                .to_vec())
        }
    }

    fn read_internal(&self, size: &usize) -> Result<Vec<u8>, NodeXDidCommError> {
        log::info!("Called: read_internal");

        Random::bytes(size)
    }

    pub fn read(&self, size: &usize) -> Result<Vec<u8>, NodeXDidCommError> {
        let config = did_config();
        let extension = match config.inner.lock() {
            Ok(config) => config.load_trng_read_sig(),
            _ => return Err(NodeXDidCommError {}),
        };

        match extension {
            Some(v) => self.read_external(&v, size),
            _ => self.read_internal(size),
        }
    }
}
