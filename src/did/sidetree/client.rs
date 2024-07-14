use http::StatusCode;

// This type isn't implement std::error::Error because of conflicting
// implementations
#[derive(Debug)]
pub enum HttpError {
    Inner(anyhow::Error),
}

impl<E> From<E> for HttpError
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn from(e: E) -> Self {
        Self::Inner(anyhow::Error::new(e))
    }
}

#[derive(Clone, Debug)]
pub struct SidetreeHttpClientResponse {
    pub(crate) status_code: StatusCode,
    pub(crate) body: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SidetreeResponseInitializationError {
    #[error("Invalid status code: {0}")]
    InvalidStatusCode(u16),
}

impl SidetreeHttpClientResponse {
    pub fn new(
        status_code: u16,
        body: String,
    ) -> Result<Self, SidetreeResponseInitializationError> {
        let status_code = StatusCode::from_u16(status_code)
            .map_err(|_| SidetreeResponseInitializationError::InvalidStatusCode(status_code))?;
        Ok(Self { status_code, body })
    }
}

#[async_trait::async_trait]
pub trait SidetreeHttpClient {
    type Error: std::error::Error;
    async fn post_create_identifier(
        &self,
        body: &str,
    ) -> Result<SidetreeHttpClientResponse, Self::Error>;
    async fn get_find_identifier(
        &self,
        did: &str,
    ) -> Result<SidetreeHttpClientResponse, Self::Error>;
}
