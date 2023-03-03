use base64ct::{Base64UrlUnpadded, Encoding};
use ring::hmac::{self, HMAC_SHA256};
use serde::{de::DeserializeOwned, ser::Serialize};

// Re-export for JSON error type
pub use serde_json::Error as JsonError;

#[derive(Debug)]
pub enum DecodeError {
    InvalidToken,
    InvalidSignature,
    Json(JsonError),
}

impl From<JsonError> for DecodeError {
    fn from(value: JsonError) -> Self {
        Self::Json(value)
    }
}

impl From<base64ct::Error> for DecodeError {
    fn from(_: base64ct::Error) -> Self {
        Self::InvalidToken
    }
}

/// Tokens interface for creating and validating tokens
pub struct Tokens {
    key: hmac::Key,
}

impl Tokens {
    /// Creates a new tokens interface from the provided
    /// secret key
    ///
    /// `secret` The secret key
    pub fn new(secret: &[u8]) -> Self {
        // Create a new HMAC key using the provided secret
        let key = hmac::Key::new(HMAC_SHA256, secret);
        Self { key }
    }

    /// Encodes the provided claims into a token returning the
    /// encoded token
    ///
    /// `claims` The claims to encode
    pub fn encode<T: Serialize>(&self, claims: &T) -> Result<String, JsonError> {
        // Encode the message
        let msg_bytes = serde_json::to_vec(claims)?;
        let msg = Base64UrlUnpadded::encode_string(&msg_bytes);

        // Create a signature from the raw message bytes
        let sig = hmac::sign(&self.key, &msg_bytes);
        let sig = Base64UrlUnpadded::encode_string(sig.as_ref());

        // Join the message and signature to create the token
        Ok([msg, sig].join("."))
    }

    /// Decodes a token claims from the provided token string
    ///
    /// `token` The token to decode
    pub fn decode<T: DeserializeOwned>(&self, token: &str) -> Result<T, DecodeError> {
        // Split the token parts
        let (msg, sig) = match token.split_once('.') {
            Some(value) => value,
            None => return Err(DecodeError::InvalidToken),
        };

        // Decode the message signature
        let msg: Vec<u8> = Base64UrlUnpadded::decode_vec(msg)?;
        let sig: Vec<u8> = Base64UrlUnpadded::decode_vec(sig)?;

        // Verify the signature
        if hmac::verify(&self.key, &msg, &sig).is_err() {
            return Err(DecodeError::InvalidSignature);
        }

        // Decode the verified token claims
        let claims: T = serde_json::from_slice(&msg)?;
        Ok(claims)
    }
}
