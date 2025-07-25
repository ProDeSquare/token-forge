use thiserror::Error;

#[derive(Error, Debug)]
pub enum TokenError {
    #[error("Token format is invalid")]
    MalformedToken,

    #[error("Token signature is invalid")]
    InvalidSignature,

    #[error("Token header is invalid")]
    InvalidHeader,

    #[error("Token claims are invalid")]
    InvalidClaims,

    #[error("Token is expired")]
    TokenExpired,

    #[error("Invalid JSON file")]
    InvalidJsonFile,

    #[error("File Error")]
    FileError,

    #[error("Environment variable SECRET not found")]
    EnvError,

    #[error("Base64 decoding failed")]
    InvalidBase64,
}
