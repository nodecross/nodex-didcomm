use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::nodex::{
    cipher::credential_signer::Proof,
    schema::general::{GeneralVcDataModel, Issuer},
};

#[derive(Serialize, Deserialize)]
pub struct VerifiedContainer {
    pub message: GeneralVcDataModel,
    pub metadata: Option<Value>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "issuer")]
    pub issuer: Issuer,
    #[serde(rename = "proof")]
    pub proof: Proof,
    #[serde(rename = "type")]
    pub r#type: Vec<String>,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CredentialSubject {
    #[serde(rename = "container")]
    pub container: Value,
}
