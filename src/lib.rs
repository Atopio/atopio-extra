pub mod types;

use crate::types::SurrealJWTClaims;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use serde::de::DeserializeOwned;
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

/// Serde serializer helper that serializes a `surrealdb::RecordId` as its key string.
///
/// This function is intended to be used with `#[serde(serialize_with = "...")]`
/// to serialize a `RecordId` into a JSON (or other format) string containing the
/// record's key (the part after the `:` in `<table>:<id>`).
///
/// # Example
///
/// ```rust,no_run
/// #[derive(serde::Serialize)]
/// struct Wrapper {
///     #[serde(serialize_with = "atopio-extra::serialize_record_id")]
///     id: surrealdb::RecordId,
/// }
///
/// // When serialized, `id` will be represented by its key string, e.g. "alice".
/// ```
pub fn serialize_record_id<S>(id: &RecordId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&id.key().to_string())
}

/// Serde serializer helper that serializes an `Option<surrealdb::RecordId>` as its key string or `null`.
///
/// This function is intended to be used with `#[serde(serialize_with = "...")]`
/// to serialize an `Option<RecordId>` into a string containing the record's
/// key (the part after the `:` in `<table>:<id>`), or `null` when `None`.
///
/// # Example
///
/// ```rust,no_run
/// #[derive(serde::Serialize)]
/// struct Wrapper {
///     #[serde(serialize_with = "atopio::serialize_record_id_option")]
///     id: Option<surrealdb::RecordId>,
/// }
///
/// // `Some(<table>:alice)` -> "alice"; `None` -> null.
/// ```
pub fn serialize_record_id_option<S>(
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
