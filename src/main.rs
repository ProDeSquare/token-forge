use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct TokenRequest {
    pub payload: HashMap<String, serde_json::Value>,
}

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Could not decode token")]
    DecodeFailed,
    #[error("Invalid JSON file")]
    InvalidJsonFile,
    #[error("File Error")]
    FileError,
    #[error("Environment variable SECRET not found")]
    EnvError,
}

fn main() {
    println!("Hello from Token Forge!");
}
