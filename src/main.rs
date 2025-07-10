use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use thiserror::Error;

type HmacSha256 = Hmac<Sha256>;

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

pub struct TokenForge {
    secret: Vec<u8>,
}

impl TokenForge {
    pub fn with_secret(secret: &str) -> Self {
        TokenForge {
            secret: secret.as_bytes().to_vec(),
        }
    }

    pub fn sign(&self, data: &str) -> Result<Vec<u8>, TokenError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| TokenError::DecodeFailed)?;
        mac.update(data.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn base64url_encode(&self, input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    pub fn base64url_decode(&self, input: &str) -> Result<Vec<u8>, TokenError> {
        URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| TokenError::DecodeFailed)
    }
}

fn main() {
    println!("Hello from Token Forge!");
}
