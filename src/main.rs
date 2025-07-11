use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use clap::{CommandFactory, Parser, Subcommand};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::{path::PathBuf, process};
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

#[derive(Parser)]
#[command(name = "tokenforge")]
#[command(about = "TokenForge - Token service")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        #[arg(short, long, help = "JSON file containing the payload")]
        file: PathBuf,

        #[arg(
            short,
            long,
            help = "Expiry time in seconds (optional, token never expires if not set)"
        )]
        expiry: Option<i64>,

        #[arg(
            short,
            long,
            help = "Show detailed information including issued at and expires at"
        )]
        verbose: bool,
    },

    Decode {
        #[arg(short, long, help = "Token to decode")]
        token: String,

        #[arg(
            short,
            long,
            help = "Show detailed information including issued at and expires at"
        )]
        verbose: bool,
    },

    Demo,
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

    pub fn verify_token(&self, token: &str) -> Result<Claims, TokenError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::DecodeFailed);
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
        let claims_str = String::from_utf8(claims_json).map_err(|_| TokenError::DecodeFailed)?;
        let claims: Claims =
            serde_json::from_str(&claims_str).map_err(|_| TokenError::DecodeFailed)?;

        if let Some(exp) = claims.exp {
            let now = Utc::now().timestamp();
            if now > exp {
                return Err(TokenError::DecodeFailed);
            }
        }

        Ok(claims)
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

fn format_timestamp(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Invalid timestamp".to_string())
}

fn main() {
    let cli = Cli::parse();

    if cli.command.is_none() {
        let mut cmd = Cli::command();
        cmd.print_help().unwrap();
        return;
    }

    let token_forge = match TokenForge::new() {
        Ok(tf) => tf,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    match cli.command.unwrap() {
        Commands::Generate {
            file,
            expiry,
            verbose,
        } => {
            if !file.exists() {
                eprintln!("Error: File '{}' does not exist", file.display());
                process::exit(1);
            }

            match token_forge.generate_from_file(&file, expiry) {
                Ok(token) => {
                    println!("{}", token);

                    if verbose {
                        match token_forge.verify_token(&token) {
                            Ok(claims) => {
                                println!("Issued at: {}", format_timestamp(claims.iat));

                                if let Some(exp) = claims.exp {
                                    println!("Expires at: {}", format_timestamp(exp));
                                }
                            }
                            Err(e) => {
                                eprintln!("Error parsing the token for verbose output: {}", e);
                                process::exit(1);
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
            }
        }

        Commands::Decode { token, verbose } => match token_forge.verify_token(&token) {
            Ok(claims) => match serde_json::to_string(&claims.payload) {
                Ok(json) => {
                    println!("{}", json);

                    if verbose {
                        println!("Issued at: {}", format_timestamp(claims.iat));

                        if let Some(exp) = claims.exp {
                            println!("Expires at: {}", format_timestamp(exp));
                        }
                    }
                }
                Err(_) => {
                    eprintln!("Error: Could not decode token");
                    process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Error: {}", e);
                process::exit(1);
            }
        },

        Commands::Demo => {
            run_demo(&token_forge);
        }
    }
}

fn run_demo(token_forge: &TokenForge) {
    println!("TokenForge Demo");
    println!("================");

    let mut payload = HashMap::new();
    payload.insert(
        "name".to_string(),
        serde_json::Value::String("Hamza Mughal".to_string()),
    );
    payload.insert(
        "email".to_string(),
        serde_json::Value::String("hamza@prodesquare.com".to_string()),
    );

    println!("Generating token with 1-hour expiry...");
    match token_forge.generate_token(payload.clone(), Some(3600)) {
        Ok(token) => {
            println!("Token: {}", token);

            println!("\nVerifying token...");
            match token_forge.verify_token(&token) {
                Ok(claims) => match serde_json::to_string_pretty(&claims.payload) {
                    Ok(json) => {
                        println!("Payload: {}", json);
                        println!("Issued at: {}", format_timestamp(claims.iat));
                        if let Some(exp) = claims.exp {
                            println!("Expires at: {}", format_timestamp(exp));
                        }
                    }
                    Err(_) => println!("Error: Could not decode token"),
                },
                Err(e) => println!("Error: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    };

    println!("\nGenerating token with no expiration...");
    match token_forge.generate_token(payload, None) {
        Ok(token) => {
            println!("Token: {}", token);

            println!("\nVerifying token...");
            match token_forge.verify_token(&token) {
                Ok(claims) => match serde_json::to_string_pretty(&claims.payload) {
                    Ok(json) => {
                        println!("Payload: {}", json);
                        println!("Issued at: {}", format_timestamp(claims.iat));
                    }
                    Err(_) => println!("Error: Could not decode token"),
                },
                Err(e) => println!("Error: {}", e),
            }
        }
        Err(e) => println!("Error: {}", e),
    }

    println!("\nTesting expired token...");
    let expired_payload = HashMap::new();
    match token_forge.generate_token(expired_payload, Some(-1)) {
        Ok(expired_token) => match token_forge.verify_token(&expired_token) {
            Ok(_) => println!("This shouldn't happen!"),
            Err(e) => println!("Error: {}", e),
        },
        Err(e) => println!("Error: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_token_generation_and_verification() {
        let token_forge = TokenForge::with_secret("test_secret");

        let mut payload = HashMap::new();
        payload.insert(
            "user_id".to_string(),
            serde_json::Value::String("17081999".to_string()),
        );

        let token = token_forge
            .generate_token(payload.clone(), Some(3600))
            .unwrap();
        let claims = token_forge.verify_token(&token).unwrap();

        assert_eq!(claims.payload.get("user_id"), payload.get("user_id"));
        assert!(claims.exp.is_some());
    }

    #[test]
    fn test_token_from_file() {
        let token_forge = TokenForge::with_secret("test_secret");

        let mut temp_file = NamedTempFile::new().unwrap();
        let json_content = r#"
        {
            "payload": {
                "user_id": "27081999",
                "name": "Hamza Mughal",
                "email": "hamza@prodesquare.com",
                "role": "admin"
            }
        }
        "#;

        temp_file.write_all(json_content.as_bytes()).unwrap();

        let token = token_forge
            .generate_from_file(&temp_file.path().to_path_buf(), Some(3600))
            .unwrap();
        let claims = token_forge.verify_token(&token).unwrap();

        assert_eq!(claims.payload.get("user_id").unwrap(), "27081999");
        assert_eq!(
            claims.payload.get("email").unwrap(),
            "hamza@prodesquare.com"
        );
        assert_eq!(claims.payload.get("role").unwrap(), "admin");
        assert!(claims.exp.is_some());
    }

    #[test]
    fn test_token_without_expiration() {
        let token_forge = TokenForge::with_secret("test_secret");

        let payload = HashMap::new();
        let token = token_forge.generate_token(payload, None).unwrap();
        let claims = token_forge.verify_token(&token).unwrap();

        assert!(claims.exp.is_none());
    }

    #[test]
    fn test_expired_token() {
        let token_forge = TokenForge::with_secret("test_secret");

        let payload = HashMap::new();
        let token = token_forge.generate_token(payload, Some(-1)).unwrap();

        match token_forge.verify_token(&token) {
            Err(TokenError::DecodeFailed) => (),
            _ => panic!("Expected DecodeFailed error"),
        }
    }

    #[test]
    fn test_invalid_token() {
        let token_forge = TokenForge::with_secret("test_secret");

        let invalid_token = "invalid.token.here";
        match token_forge.verify_token(invalid_token) {
            Err(TokenError::DecodeFailed) => (),
            _ => panic!("Expected DecodeFailed error"),
        }
    }
}
