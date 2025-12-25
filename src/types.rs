use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>", serialize = "T: Serialize"))]
/// Represents a set of JWT-like claims used by SurrealDB for authentication and authorization.
///
/// - `iat`: Issued At — Unix timestamp (seconds) when the token was created.
/// - `nbf`: Not Before — Unix timestamp before which the token MUST NOT be accepted.
/// - `exp`: Expiration Time — Unix timestamp after which the token is no longer valid.
/// - `iss`: Issuer — Identifier of the entity that issued the token (e.g., service or authority).
/// - `jti`: JWT ID — Unique identifier for the token to support revocation or deduplication.
/// - `ns` (serialized as "NS"): Namespace — SurrealDB namespace the token grants access to.
/// - `db` (serialized as "DB"): Database — SurrealDB database the token grants access to.
/// - `ac` (serialized as "AC"): Access Claims — Generic payload containing permissions/roles; type `T` allows flexibility
///   (for example, a list of permissions, a map of scopes, or a custom claims struct).
/// - `id` (serialized as "ID"): Subject Identifier — Identifier of the subject (user or service) the token represents.
///
/// All timestamps are expected to be seconds since the Unix epoch. The `NS`, `DB`, `AC`, and `ID` serde renames
/// ensure compatibility with SurrealDB's expected JSON field names.
pub struct SurrealJWTClaims<T> {
    pub iat: u64,
    pub nbf: u64,
    pub exp: u64,
    pub iss: String,
    pub jti: String,
    #[serde(rename = "NS")]
    pub ns: String,
    #[serde(rename = "DB")]
    pub db: String,
    #[serde(rename = "AC")]
    pub ac: T,
    #[serde(rename = "ID")]
    pub id: String,
}
