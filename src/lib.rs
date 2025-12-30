pub mod types;

use crate::types::SurrealJWTClaims;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde::{Deserializer, Serialize, de::Error};

/// Decodes a JWT payload without any signature or timestamp validation.
///
/// # Errors
/// This function will return an error if:
/// - The token does not have three parts separated by dots.
/// - The payload is not valid Base64Url.
/// - The decoded payload is not valid JSON or doesn't match the Claims struct.
pub fn decode_payload_insecurely<T>(
    token: &str,
) -> Result<SurrealJWTClaims<T>, Box<dyn std::error::Error>>
where
    T: DeserializeOwned + Serialize,
{
    let mut parts = token.split('.');

    let payload_b64 = parts.nth(1).ok_or("Invalid JWT format: missing payload")?;

    let decoded_payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64)?;

    let claims: SurrealJWTClaims<T> = serde_json::from_slice(&decoded_payload_bytes)?;

    Ok(claims)
}

pub mod record_id_full {
    use super::*;
    use std::str::FromStr;

    /// Serialize a `surrealdb::RecordId` as its full string representation.
    ///
    /// This helper is intended for use with `#[serde(with = "...")]` on fields of type
    /// `surrealdb::RecordId`. It serializes the ID to a JSON string using the format produced
    /// by `RecordId::to_string()`, which includes the table and key (for example: `"user:abc123"`).
    pub fn serialize<S>(id: &surrealdb::RecordId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&id.to_string())
    }

    /// Deserialize a JSON string into a `surrealdb::RecordId`.
    ///
    /// This is the counterpart to `serialize` and expects the JSON value to be a string
    /// containing the full record id (table:key). If the input string cannot be parsed by
    /// `surrealdb::RecordId::from_str`, this function converts the parsing error into a
    /// `serde` deserialization error.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the provided JSON value is not a string or
    /// if the string is not a valid SurrealDB record id.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<surrealdb::RecordId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        surrealdb::RecordId::from_str(&s).map_err(D::Error::custom)
    }
}

pub mod record_id_naked {

    /// Serialize the key portion of a `surrealdb::RecordId` (the \"naked\" id).
    ///
    /// This helper is intended for use with `#[serde(with = "...")]` on fields of type
    /// `surrealdb::RecordId`. It serializes only the key portion (the part after the table
    /// separator) as a JSON string — akin to tradtional SQL IDs where only the numeric or
    /// key portion is stored or referenced.
    pub fn serialize<S>(id: &surrealdb::RecordId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let naked_id = id.key().to_string();
        serializer.serialize_str(&naked_id)
    }
}
