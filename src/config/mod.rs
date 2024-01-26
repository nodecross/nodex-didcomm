pub mod did;
pub mod server;

use std::sync::{Arc, Mutex, Once};

use self::did::DidConfig;
use self::server::ServerConfig;

#[derive(Clone)]
pub struct SingletonDidConfig {
    pub inner: Arc<Mutex<DidConfig>>,
}

pub fn server_config() -> ServerConfig {
    ServerConfig::new()
}

pub fn did_config() -> Box<SingletonDidConfig> {
    static mut SINGLETON: Option<Box<SingletonDidConfig>> = None;
    static ONCE: Once = Once::new();

    unsafe {
        ONCE.call_once(|| {
            let singleton = SingletonDidConfig {
                inner: Arc::new(Mutex::new(DidConfig::new())),
            };

            SINGLETON = Some(Box::new(singleton))
        });

        SINGLETON.clone().unwrap()
    }
}
