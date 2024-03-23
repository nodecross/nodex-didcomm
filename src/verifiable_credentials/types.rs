use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedContainer {
    pub message: GeneralVcDataModel,
    pub metadata: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct Issuer {
    #[serde(rename = "id")]
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct CredentialSubject {
    // NOTE: 'id' property is optional.
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "container")]
    pub container: Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct Proof {
    #[serde(rename = "type")]
    pub r#type: String,

    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,

    #[serde(rename = "created")]
    pub created: String,

    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    #[serde(rename = "jws")]
    pub jws: String,

    #[serde(rename = "controller")]
    pub controller: Option<String>,

    #[serde(rename = "challenge")]
    pub challenge: Option<String>,

    #[serde(rename = "domain")]
    pub domain: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq, Clone)]
pub struct GeneralVcDataModel {
    // NOTE: 'id' property is optional.
    #[serde(rename = "id", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "issuer")]
    pub issuer: Issuer,

    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,

    #[serde(rename = "expirationDate", skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<String>,

    #[serde(rename = "@context")]
    pub context: Vec<String>,

    #[serde(rename = "type")]
    pub r#type: Vec<String>,

    #[serde(rename = "credentialSubject")]
    pub credential_subject: CredentialSubject,

    #[serde(rename = "proof", skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
}
