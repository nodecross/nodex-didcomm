use crate::{
    errors::NodeXDidCommError,
    keyring,
    sidetree::payload::{
        CommitmentKeys, DIDCreateRequest, DIDResolutionResponse, OperationPayload,
    },
    utils::http_client::{HttpClient, HttpClientConfig},
};

// use super::encrypted::DIDCommEncryptedService;
use crate::config::server_config;

pub struct NodeX {
    http_client: HttpClient,
}

impl NodeX {
    pub fn new() -> Self {
        let server_config = server_config();
        let client_config: HttpClientConfig = HttpClientConfig {
            base_url: server_config.did_http_endpoint(),
        };

        let client = match HttpClient::new(&client_config) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                panic!()
            }
        };

        NodeX {
            http_client: client,
        }
    }

    // NOTE: DONE
    pub async fn create_identifier(&self) -> Result<DIDResolutionResponse, NodeXDidCommError> {
        // NOTE: find did
        if let Ok(v) = keyring::keypair::KeyPairing::load_keyring() {
            if let Ok(did) = v.get_identifier() {
                if let Ok(json) = self.find_identifier(&did.as_str()).await {
                    return Ok(json);
                }
            }
        }

        // NOTE: does not exists did key ring
        let mut keyring = match keyring::keypair::KeyPairing::create_keyring() {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: create payload
        let public = match keyring
            .get_sign_key_pair()
            .to_public_key("signingKey", &["auth", "general"])
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };
        let update = match keyring.get_recovery_key_pair().to_jwk(false) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };
        let recovery = match keyring.get_update_key_pair().to_jwk(false) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let payload = match OperationPayload::did_create_payload(&DIDCreateRequest {
            public_keys: vec![public],
            commitment_keys: CommitmentKeys { recovery, update },
            service_endpoints: vec![],
        }) {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let res = match self.http_client.post("/api/v1/operations", &payload).await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        let json = match res.json::<DIDResolutionResponse>().await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        // NOTE: save context
        keyring.save(&json.did_document.id);

        Ok(json)
    }

    // NOTE: DONE
    pub async fn find_identifier(
        &self,
        did: &str,
    ) -> Result<DIDResolutionResponse, NodeXDidCommError> {
        let res = match self
            .http_client
            .get(&(format!("/api/v1/identifiers/{}", &did)))
            .await
        {
            Ok(v) => v,
            Err(e) => {
                log::error!("{:?}", e);
                return Err(NodeXDidCommError {});
            }
        };

        match res.json::<DIDResolutionResponse>().await {
            Ok(v) => Ok(v),
            Err(e) => {
                log::error!("{:?}", e);
                Err(NodeXDidCommError {})
            }
        }
    }

    // #[allow(dead_code)]
    // pub async fn transfer(
    //     &self,
    //     to_did: &str,
    //     messages: &Vec<Value>,
    //     metadata: &Value,
    // ) -> Result<Value, NodeXDidCommError> {
    //     // NOTE: didcomm (enc)
    //     let container =
    //         match DIDCommEncryptedService::generate(to_did, &json!(messages), Some(metadata)).await
    //         {
    //             Ok(v) => v,
    //             Err(e) => {
    //                 log::error!("{:?}", e);
    //                 return Err(NodeXDidCommError {});
    //             }
    //         };

    //     Ok(container)
    // }
}
