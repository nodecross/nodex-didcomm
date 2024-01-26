use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::schema::general::GeneralVcDataModel;

#[derive(Serialize, Deserialize)]
pub struct VerifiedContainer {
    pub message: GeneralVcDataModel,
    pub metadata: Option<Value>,
}
