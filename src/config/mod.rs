pub mod did;
pub mod server;

use self::did::DidConfig;
use self::server::ServerConfig;
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex, Once};

#[derive(Clone)]
pub struct SingletonDidConfig {
    pub inner: Arc<Mutex<DidConfig>>,
}

impl SingletonDidConfig {
    pub fn lock(&self) -> MutexGuard<'_, DidConfig> {
        self.inner.lock().unwrap()
    }
}

pub fn server_config() -> ServerConfig {
    ServerConfig::new()
}

pub fn did_config() -> Box<SingletonDidConfig> {
    static mut SINGLETON: Option<Box<SingletonDidConfig>> = None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonDidConfig { inner: Arc::new(Mutex::new(DidConfig::new())) };

            SINGLETON = Some(Box::new(singleton))
        });

        SINGLETON.clone().unwrap()
    }
}
