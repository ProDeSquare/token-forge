use thiserror::Error;

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
