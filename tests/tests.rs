use base64::Engine as _;
use hmac::Mac;
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
            "user_id": "27081999",
            "name": "Hamza Mughal",
            "email": "hamza@prodesquare.com",
            "role": "admin"
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
        Err(TokenError::TokenExpired) => (),
        _ => panic!("Expected Token Expired error"),
    }
}

#[test]
fn test_invalid_token() {
    let token_forge = TokenForge::with_secret("test_secret");

    let invalid_token = "invalid.token.here";
    match token_forge.verify_token(invalid_token) {
        Err(TokenError::DecodeFailed) => (),
        _ => panic!("Expected Invalid Signature error"),
    }
}

#[test]
fn test_malformed_token_wrong_number_of_parts() {
    let token_forge = TokenForge::with_secret("test_secret");

    let malformed_token = "hamza.mughal";
    match token_forge.verify_token(malformed_token) {
        Err(TokenError::MalformedToken) => (),
        _ => panic!("Expected Malformed Token error for token with wrong number of parts"),
    }

    let malformed_token = "hamza.the.prodesquare.mughal";
    match token_forge.verify_token(malformed_token) {
        Err(TokenError::MalformedToken) => (),
        _ => panic!("Expected Malformed Token error for token with wrong number of parts"),
    }
}

#[test]
fn test_invalid_base64_signature() {
    let token_forge = TokenForge::with_secret("test_secret");

    let payload = HashMap::new();
    let valid_token = token_forge.generate_token(payload, None).unwrap();
    let parts: Vec<&str> = valid_token.split('.').collect();

    let invalid_token = format!("{}.{}.invalid_base64!!!", parts[0], parts[1]);

    match token_forge.verify_token(&invalid_token) {
        Err(TokenError::DecodeFailed) => (),
        _ => panic!("Expected Decode Failed error for invalid base64 signature"),
    }
}

#[test]
fn test_invalid_base64_payload() {
    let token_forge = TokenForge::with_secret("test_secret");

    let invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IlRPSyJ9.invalid_base64!!!.signature";

    match token_forge.verify_token(invalid_token) {
        Err(TokenError::DecodeFailed) => (),
        _ => panic!("Expected Decode Failed error for invalid base64 payload"),
    }
}

#[test]
fn test_wrong_secret_signature_verification() {
    let token_forge1 = TokenForge::with_secret("secret1");
    let token_forge2 = TokenForge::with_secret("secret2");

    let payload = HashMap::new();
    let token = token_forge1.generate_token(payload, None).unwrap();

    match token_forge2.verify_token(&token) {
        Err(TokenError::DecodeFailed) => (),
        _ => panic!("Expected Decode Failed error when verifying with wrong secret"),
    }
}

#[test]
fn test_invalid_json_in_header() {
    let token_forge = TokenForge::with_secret("test_secret");

    let invalid_header = "{alg:HS256,typ:TOK}";
    let invalid_header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invalid_header.as_bytes());

    let valid_payload = r#"{"iat":1676964000}"#;
    let valid_payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(valid_payload.as_bytes());

    let signing_input = format!("{}.{}", invalid_header_b64, valid_payload_b64);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test_secret").unwrap();
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    let invalid_token = format!(
        "{}.{}.{}",
        invalid_header_b64, valid_payload_b64, signature_b64
    );

    match token_forge.verify_token(&invalid_token) {
        Err(TokenError::InvalidHeader) => (),
        _ => panic!("Expected Invalid Header error for malformed JSON in header"),
    }
}

#[test]
fn test_invalid_json_in_payload() {
    let token_forge = TokenForge::with_secret("test_secret");

    let valid_header = r#"{"alg":"HS256","typ":"TOK"}"#;
    let valid_header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(valid_header.as_bytes());

    let invalid_payload = "{iat:1676964000}";
    let invalid_payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(invalid_payload.as_bytes());

    let signing_input = format!("{}.{}", valid_header_b64, invalid_payload_b64);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test_secret").unwrap();
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    let invalid_token = format!(
        "{}.{}.{}",
        valid_header_b64, invalid_payload_b64, signature_b64
    );

    match token_forge.verify_token(&invalid_token) {
        Err(TokenError::InvalidClaims) => (),
        _ => panic!("Expected Invalid Claims error for malformed JSON in payload"),
    }
}

#[test]
fn test_wrong_algorithm_in_header() {
    let token_forge = TokenForge::with_secret("test_secret");

    let wrong_alg_header = r#"{"alg":"RS256","typ":"TOK"}"#;
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong_alg_header.as_bytes());

    let valid_payload = r#"{"iat":1676964000}"#;
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(valid_payload.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test_secret").unwrap();
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    let invalid_token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    match token_forge.verify_token(&invalid_token) {
        Err(TokenError::InvalidHeader) => (),
        _ => panic!("Expected Invalid Header error for wrong algorithm"),
    }
}

#[test]
fn test_wrong_type_in_header() {
    let token_forge = TokenForge::with_secret("test_secret");

    let wrong_type_header = r#"{"alg":"HS256","typ":"JWT"}"#;
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wrong_type_header.as_bytes());

    let valid_payload = r#"{"iat":1676964000}"#;
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(valid_payload.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(b"test_secret").unwrap();
    mac.update(signing_input.as_bytes());
    let signature = mac.finalize().into_bytes();
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

    let invalid_token = format!("{}.{}.{}", header_b64, payload_b64, signature_b64);

    match token_forge.verify_token(&invalid_token) {
        Err(TokenError::InvalidHeader) => (),
        _ => panic!("Expected Invalid Header error for wrong token type"),
    }
}

#[test]
fn test_empty_json_file() {
    let token_forge = TokenForge::with_secret("test_secret");

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(b"{}").unwrap();

    match token_forge.generate_from_file(&temp_file.path().to_path_buf(), None) {
        Err(TokenError::InvalidJsonFile) => (),
        _ => panic!("Expected InvalidJsonFile error for empty JSON object"),
    }
}

#[test]
fn test_invalid_json_file_syntax() {
    let token_forge = TokenForge::with_secret("test_secret");

    let mut temp_file = NamedTempFile::new().unwrap();
    let invalid_json = r#"{"name": "Hamza", "invalid": }"#;
    temp_file.write_all(invalid_json.as_bytes()).unwrap();

    match token_forge.generate_from_file(&temp_file.path().to_path_buf(), None) {
        Err(TokenError::InvalidJsonFile) => (),
        _ => panic!("Expected InvalidJsonFile error for invalid JSON syntax"),
    }
}

#[test]
fn test_nonexistent_file() {
    let token_forge = TokenForge::with_secret("test_secret");

    let nonexistent_path = std::path::PathBuf::from("/nonexistent/path/prodesquare.json");

    match token_forge.generate_from_file(&nonexistent_path, None) {
        Err(TokenError::FileError) => (),
        _ => panic!("Expected File Error for nonexistent file"),
    }
}

#[test]
fn test_complex_payload_types() {
    let token_forge = TokenForge::with_secret("test_secret");

    let mut payload = HashMap::new();

    payload.insert(
        "string".to_string(),
        serde_json::Value::String("hamza".to_string()),
    );
    payload.insert(
        "number".to_string(),
        serde_json::Value::Number(serde_json::Number::from(42)),
    );
    payload.insert("boolean".to_string(), serde_json::Value::Bool(true));
    payload.insert("null".to_string(), serde_json::Value::Null);

    let array = serde_json::Value::Array(vec![
        serde_json::Value::String("item1".to_string()),
        serde_json::Value::String("item2".to_string()),
    ]);
    payload.insert("array".to_string(), array);

    let mut nested_obj = serde_json::Map::new();
    nested_obj.insert(
        "nested_key".to_string(),
        serde_json::Value::String("nested_value".to_string()),
    );
    payload.insert("object".to_string(), serde_json::Value::Object(nested_obj));

    let token = token_forge
        .generate_token(payload.clone(), Some(3600))
        .unwrap();
    let claims = token_forge.verify_token(&token).unwrap();

    assert_eq!(claims.payload.get("string").unwrap(), "hamza");
    assert_eq!(claims.payload.get("number").unwrap(), &42);
    assert_eq!(claims.payload.get("boolean").unwrap(), &true);
    assert_eq!(
        claims.payload.get("null").unwrap(),
        &serde_json::Value::Null
    );
    assert!(claims.payload.get("array").unwrap().is_array());
    assert!(claims.payload.get("object").unwrap().is_object());
}

#[test]
fn test_negative_expiry_time() {
    let token_forge = TokenForge::with_secret("test_secret");

    let payload = HashMap::new();

    let token = token_forge.generate_token(payload, Some(-1)).unwrap();

    match token_forge.verify_token(&token) {
        Err(TokenError::TokenExpired) => (),
        _ => panic!("Expected Token Expired error for negative expiry time"),
    }
}

#[test]
fn test_very_large_expiry_time() {
    let token_forge = TokenForge::with_secret("test_secret");

    let payload = HashMap::new();
    let token = token_forge
        .generate_token(payload, Some(100 * 365 * 24 * 60 * 60))
        .unwrap();
    let claims = token_forge.verify_token(&token).unwrap();

    assert!(claims.exp.is_some());
    assert!(claims.exp.unwrap() > chrono::Utc::now().timestamp());
}

#[test]
fn test_empty_secret() {
    let token_forge = TokenForge::with_secret("");

    let payload = HashMap::new();
    let token = token_forge.generate_token(payload, None).unwrap();

    let claims = token_forge.verify_token(&token).unwrap();
    assert!(claims.payload.is_empty());
}

#[test]
fn test_unicode_in_payload() {
    let token_forge = TokenForge::with_secret("test_secret");

    let mut payload = HashMap::new();
    payload.insert("unicode_text".to_string(),
        serde_json::Value::String("🚀 Unicode: café, naïve, 北京".to_string()));
    payload.insert("emoji".to_string(),
        serde_json::Value::String("😀🎉🔥".to_string()));

    let token = token_forge.generate_token(payload.clone(), None).unwrap();
    let claims = token_forge.verify_token(&token).unwrap();

    assert_eq!(claims.payload.get("unicode_text"), payload.get("unicode_text"));
    assert_eq!(claims.payload.get("emoji"), payload.get("emoji"));
}
