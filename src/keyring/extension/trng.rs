use std::{ffi::CStr, num::NonZeroU32};

use thiserror::Error;

use super::Extension;
use crate::common::runtime::random::{Random, RandomError};

#[derive(Error, Debug)]
pub enum TrngError {
    #[error("Buffer length over")]
    BufferLengthOver,
    #[error("Library loading error")]
    LibraryLoadingError(#[from] libloading::Error),
    #[error("External function failed")]
    ExternalFunctionFailed(NonZeroU32),
    #[error("Random generation failed")]
    RandomGenerationFailed(#[from] RandomError),
}

pub trait Trng {
    const MAX_BUFFER_LENGTH: usize = 1024;
    fn generate(&self, size: &usize) -> Result<Vec<u8>, TrngError>;
}

#[derive(Default)]
pub struct OSRandomNumberGenerator {}

impl Trng for OSRandomNumberGenerator {
    fn generate(&self, size: &usize) -> Result<Vec<u8>, TrngError> {
        Random::bytes(size).map_err(TrngError::RandomGenerationFailed)
    }
}

pub struct ExternalTrng {
    extension: Extension,
}

impl Trng for ExternalTrng {
    fn generate(&self, size: &usize) -> Result<Vec<u8>, TrngError> {
        if Self::MAX_BUFFER_LENGTH < *size {
            return Err(TrngError::BufferLengthOver);
        }

        unsafe {
            let buffer = [0u8; Self::MAX_BUFFER_LENGTH + 1];
            let buffer_ptr: *const i8 = buffer.as_ptr().cast();

            let lib = libloading::Library::new(&self.extension.filename)?;

            let func: libloading::Symbol<
                unsafe extern "C" fn(buf: *const i8, bufsize: usize, size: usize) -> u32,
            > = lib.get(self.extension.symbol.as_bytes())?;

            let result = func(buffer_ptr, buffer.len(), *size);

            if let Some(exit_status) = NonZeroU32::new(result) {
                return Err(TrngError::ExternalFunctionFailed(exit_status));
            }

            Ok(CStr::from_ptr(buffer_ptr as *const core::ffi::c_char).to_bytes().to_vec())
        }
    }
}
