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

    /// Serialize an `Option<surrealdb::RecordId>` in the full (table:key) form.
    ///
    /// This helper is intended for use with `#[serde(with = "...")]` on fields of type
    /// `Option<surrealdb::RecordId>`. When the option is `Some`, the contained `RecordId`
    /// is serialized as the full textual representation produced by `RecordId::to_string()`
    /// (for example: `"user:abc123"`). When the option is `None`, a JSON `null` is emitted.
    pub fn serialize_opt<S>(
        id: &Option<surrealdb::RecordId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match id {
            Some(record_id) => serializer.serialize_str(&record_id.to_string()),
            None => serializer.serialize_none(),
        }
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

    /// Deserialize an `Option<surrealdb::RecordId>` from the full (table:key) form.
    ///
    /// This is the counterpart to `serialize_opt` and expects either a JSON string
    /// containing the full record id (for example `"user:abc123"`) or `null`.
    /// If a string is provided, it attempts to parse it with `surrealdb::RecordId::from_str`.
    /// If parsing fails, the error is converted into a serde deserialization error.
    ///
    /// # Errors
    ///
    /// Returns a deserialization error if the JSON value is not a string or `null`, or if
    /// the string is not a valid SurrealDB `RecordId`.
    pub fn deserialize_opt<'de, D>(deserializer: D) -> Result<Option<surrealdb::RecordId>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt = Option::<String>::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let record_id = surrealdb::RecordId::from_str(&s).map_err(D::Error::custom)?;
                Ok(Some(record_id))
            }
            None => Ok(None),
        }
    }
}

pub mod record_id_naked {

    /// Serialize the key portion of a `surrealdb::RecordId` (the "naked" id).
    ///
    /// This helper is intended for use with `#[serde(with = "...")]` on fields of type
    /// `surrealdb::RecordId`. It serializes only the key portion (the part after the table
    /// separator) as a JSON string — akin to traditional SQL IDs where only the numeric or
    /// key portion is stored or referenced.
    pub fn serialize<S>(id: &surrealdb::RecordId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let naked_id = id.key().to_string();
        serializer.serialize_str(&naked_id)
    }

    /// Serialize an `Option<surrealdb::RecordId>` as the naked key (key only).
    ///
    /// Intended for use with `#[serde(with = "...")]` on fields of type
    /// `Option<surrealdb::RecordId>`. When the option is `Some`, only the key portion
    /// (the part after the table separator) is serialized as a JSON string (for example:
    /// `"abc123"`). When the option is `None`, a JSON `null` is emitted.
    ///
    /// This shape is useful when you want IDs to resemble single-column identifiers,
    /// akin to traditional SQL IDs.
    pub fn serialize_opt<S>(
        id: &Option<surrealdb::RecordId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match id {
            Some(record_id) => {
                let naked_id = record_id.key().to_string();
                serializer.serialize_str(&naked_id)
            }
            None => serializer.serialize_none(),
        }
    }
}
