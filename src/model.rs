use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub alg: String,
    pub typ: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Claims {
    pub iat: i64,
    pub exp: Option<i64>,

    #[serde(flatten)]
    pub payload: HashMap<String, serde_json::Value>,
}
