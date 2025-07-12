use std::collections::HashMap;
use std::io::Write;
use tempfile::NamedTempFile;
use token_forge::{TokenError, TokenForge};

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
