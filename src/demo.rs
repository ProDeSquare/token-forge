use crate::token::TokenForge;
use crate::utils::format_timestamp;
use std::collections::HashMap;

pub fn run_demo(token_forge: &TokenForge) {
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
