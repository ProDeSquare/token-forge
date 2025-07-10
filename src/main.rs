use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
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
    pub fn new() -> Result<Self, TokenError> {
        dotenv::dotenv().ok();

        let secret = env::var("SECRET").map_err(|_| TokenError::EnvError)?;

        Ok(TokenForge {
            secret: secret.into_bytes(),
        })
    }

    pub fn generate_from_file(
        &self,
        file_path: &PathBuf,
        expires_in_seconds: Option<i64>,
    ) -> Result<String, TokenError> {
        let file_content = fs::read_to_string(file_path).map_err(|_| TokenError::FileError)?;

        let token_request: TokenRequest =
            serde_json::from_str(&file_content).map_err(|_| TokenError::InvalidJsonFile)?;

        if token_request.payload.is_empty() {
            return Err(TokenError::InvalidJsonFile);
        }

        self.generate_token(token_request.payload, expires_in_seconds)
    }

    pub fn generate_token(
        &self,
        payload: HashMap<String, serde_json::Value>,
        expires_in_seconds: Option<i64>,
    ) -> Result<String, TokenError> {
        let now = Utc::now().timestamp();

        let claims = Claims {
            iat: now,
            exp: expires_in_seconds.map(|seconds| now + seconds),
            payload,
        };

        self.create_token(claims)
    }

    pub fn create_token(&self, claims: Claims) -> Result<String, TokenError> {
        let header = Header {
            alg: "HS256".to_string(),
            typ: "TOK".to_string(),
        };

        let header_json = serde_json::to_string(&header).map_err(|_| TokenError::DecodeFailed)?;
        let header_b64 = self.base64url_encode(header_json.as_bytes());

        let claims_json = serde_json::to_string(&claims).map_err(|_| TokenError::DecodeFailed)?;
        let claims_b64 = self.base64url_encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = self.sign(&signing_input)?;
        let signature_b64 = self.base64url_encode(&signature);

        Ok(format!("{}.{}.{}", header_b64, claims_b64, signature_b64))
    }

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
