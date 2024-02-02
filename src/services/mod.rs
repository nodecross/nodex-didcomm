pub mod did_vc;
pub mod encrypted;
pub mod plaintext;
pub mod types;

use crate::config::server_config;

fn attachment_link() -> String {
    let server_config = server_config();
    server_config.did_attachment_link()
}
