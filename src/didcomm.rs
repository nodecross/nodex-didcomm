use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct DIDCommMessage {
    pub ciphertext: String,
    pub iv: String,
    pub protected: String,
    pub recipients: Vec<Recipient>,
    pub tag: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Recipient {
    pub encrypted_key: String,
    pub header: Header,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Header {
    pub alg: String,
    pub epk: Epk,
    pub iv: String,
    pub key_ops: Vec<String>,
    pub kid: String,
    pub tag: String,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Epk {
    pub crv: String,
    pub kty: String,
    pub x: String,
}
