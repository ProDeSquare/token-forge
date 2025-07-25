use crate::error::TokenError;
use crate::model::{Claims, Header};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;

type HmacSha256 = Hmac<Sha256>;

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

    pub fn with_secret(secret: &str) -> Self {
        TokenForge {
            secret: secret.as_bytes().to_vec(),
        }
    }

    pub fn generate_from_file(
        &self,
        file_path: &PathBuf,
        expires_in_seconds: Option<i64>,
    ) -> Result<String, TokenError> {
        let file_content = fs::read_to_string(file_path).map_err(|_| TokenError::FileError)?;

        let payload: HashMap<String, serde_json::Value> =
            serde_json::from_str(&file_content).map_err(|_| TokenError::InvalidJsonFile)?;

        if payload.is_empty() {
            return Err(TokenError::InvalidJsonFile);
        }

        self.generate_token(payload, expires_in_seconds)
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

        let header_json = serde_json::to_string(&header).map_err(|_| TokenError::InvalidHeader)?;
        let header_b64 = self.base64url_encode(header_json.as_bytes());

        let claims_json = serde_json::to_string(&claims).map_err(|_| TokenError::InvalidClaims)?;
        let claims_b64 = self.base64url_encode(claims_json.as_bytes());

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let signature = self.sign(&signing_input)?;
        let signature_b64 = self.base64url_encode(&signature);

        Ok(format!("{}.{}.{}", header_b64, claims_b64, signature_b64))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, TokenError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::MalformedToken);
        }

        let header_b64 = parts[0];
        let claims_b64 = parts[1];
        let signature_b64 = parts[2];

        let signing_input = format!("{}.{}", header_b64, claims_b64);
        let expected_signature = self.sign(&signing_input)?;
        let provided_signature = self.base64url_decode(signature_b64)?;

        if expected_signature != provided_signature {
            return Err(TokenError::DecodeFailed);
        }

        let claims_json = self.base64url_decode(claims_b64)?;
        let claims_str = String::from_utf8(claims_json).map_err(|_| TokenError::InvalidClaims)?;
        let claims: Claims =
            serde_json::from_str(&claims_str).map_err(|_| TokenError::InvalidClaims)?;

        let header_json = self.base64url_decode(header_b64)?;
        let header_str = String::from_utf8(header_json).map_err(|_| TokenError::InvalidHeader)?;
        let header: Header =
            serde_json::from_str(&header_str).map_err(|_| TokenError::InvalidHeader)?;

        if header.alg != "HS256" || header.typ != "TOK" {
            return Err(TokenError::InvalidHeader);
        }

        if let Some(exp) = claims.exp {
            let now = Utc::now().timestamp();
            if now > exp {
                return Err(TokenError::TokenExpired);
            }
        }

        Ok(claims)
    }

    fn sign(&self, data: &str) -> Result<Vec<u8>, TokenError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).map_err(|_| TokenError::DecodeFailed)?;
        mac.update(data.as_bytes());
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn base64url_encode(&self, input: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(input)
    }

    fn base64url_decode(&self, input: &str) -> Result<Vec<u8>, TokenError> {
        URL_SAFE_NO_PAD
            .decode(input)
            .map_err(|_| TokenError::DecodeFailed)
    }
}
