pub mod types;

use crate::types::SurrealJWTClaims;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde::{Deserializer, Serialize, de::Error};
use surrealdb::RecordId;

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

/// Deserializes a SurrealDB `RecordId` from a deserializer, returning its key as a `String` akin to traditional SQL.
///
/// # Arguments
///
/// * `deserializer` - The deserializer to extract the `RecordId` from.
///
/// # Returns
///
/// * `Ok(String)` containing the record key if deserialization is successful.
/// * `Err(D::Error)` if the value is `None` or deserialization fails.
///
/// # Errors
///
/// Returns an error if the deserialized value is `None`.
pub fn deserialize_record_id_naked<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Option<RecordId> = Option::deserialize(deserializer)?;
    match value {
        Some(id) => Ok(id.key().to_string()),
        None => Err(D::Error::custom("RecordId cannot be None")),
    }
}

/// Deserializes an optional SurrealDB `RecordId` from a deserializer, returning an
/// `Option<String>` akin to traditional SQL with the record key when present.
///
/// This is intended for optional fields where `null` or missing values should map to
/// `None` in Rust. When a `RecordId` is present it is converted to its string key.
///
/// # Arguments
///
/// * `deserializer` - The deserializer to extract the optional `RecordId` from.
///
/// # Returns
///
/// * `Ok(Some(String))` containing the record key when a `RecordId` is present.
/// * `Ok(None)` if the input is `null` or missing.
/// * `Err(D::Error)` if deserialization fails for other reasons.
pub fn deserialize_record_id_naked_option<'de, D>(
    deserializer: D,
) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value: Option<RecordId> = Option::deserialize(deserializer)?;

    match value {
        Some(id) => Ok(Some(id.key().to_string())),
        None => Ok(None),
    }
}

/// Serializes a SurrealDB `RecordId` as a JSON string as tb:id.
///
/// Use this with Serde `#[serde(serialize_with = "serialize_record_id")]` on
/// fields of type `RecordId` when you want the serialized representation to be
/// the record's key string rather than the full `RecordId` structure.
///
/// # Arguments
///
/// * `id` - The `RecordId` reference to serialize.
/// * `serializer` - The Serde serializer to write into.
///
/// # Returns
///
/// Returns the serializer's `Ok` result on success or `S::Error` on failure.
pub fn serialize_record_id<S>(id: &RecordId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&id.to_string())
}

/// Serializes an optional `RecordId` as a JSON string as tb:id when present, or `null` when `None`.
///
/// Use this with Serde `#[serde(serialize_with = "serialize_record_id_option")]` on
/// fields of type `Option<RecordId>` when you want `Some(id)` to be represented by the
/// record key string and `None` to be represented by JSON `null`.
///
/// # Arguments
///
/// * `id` - The optional `RecordId` reference to serialize.
/// * `serializer` - The Serde serializer to write into.
///
/// # Returns
///
/// Returns the serializer's `Ok` result on success or `S::Error` on failure.
pub fn serialize_record_id_option<S>(
    id: &Option<RecordId>,
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

/// Serializes a SurrealDB `RecordId` as a JSON string akin to traditional SQL containing its key.
///
/// Use this with Serde `#[serde(serialize_with = "serialize_record_id")]` on
/// fields of type `RecordId` when you want the serialized representation to be
/// the record's key string rather than the full `RecordId` structure.
///
/// # Arguments
///
/// * `id` - The `RecordId` reference to serialize.
/// * `serializer` - The Serde serializer to write into.
///
/// # Returns
///
/// Returns the serializer's `Ok` result on success or `S::Error` on failure.
pub fn serialize_record_id_naked<S>(id: &RecordId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&id.key().to_string())
}

/// Serializes an optional `RecordId` as a JSON string akin to traditional SQL when present, or `null` when `None`.
///
/// Use this with Serde `#[serde(serialize_with = "serialize_record_id_option")]` on
/// fields of type `Option<RecordId>` when you want `Some(id)` to be represented by the
/// record key string and `None` to be represented by JSON `null`.
///
/// # Arguments
///
/// * `id` - The optional `RecordId` reference to serialize.
/// * `serializer` - The Serde serializer to write into.
///
/// # Returns
///
/// Returns the serializer's `Ok` result on success or `S::Error` on failure.
pub fn serialize_record_id_naked_option<S>(
    id: &Option<RecordId>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match id {
        Some(record_id) => serializer.serialize_str(&record_id.key().to_string()),
        None => serializer.serialize_none(),
    }
}
