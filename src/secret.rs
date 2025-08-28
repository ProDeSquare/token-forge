use crate::error::TokenError;

pub struct SecretValidator;

impl SecretValidator {
    pub fn validate_secret(secret: &str) -> Result<(), TokenError> {
        if secret.len() < 32 {
            return Err(TokenError::WeakSecret);
        }

        let unique_chars = secret.chars().collect::<std::collections::HashSet<_>>();
        if unique_chars.len() < 8 {
            return Err(TokenError::WeakSecret);
        }

        Ok(())
    }
}
