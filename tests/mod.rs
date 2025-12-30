use std::str::FromStr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::json;

use atopio_extra::{decode_payload_insecurely, types};

#[derive(Serialize, Deserialize)]
struct ContainerFull {
    #[serde(with = "atopio_extra::record_id_full")]
    id: surrealdb::RecordId,
}

#[derive(Serialize)]
struct ContainerNaked {
    #[serde(with = "atopio_extra::record_id_naked")]
    id: surrealdb::RecordId,
}

#[test]
fn test_record_id_full_serialize_deserialize() -> Result<(), Box<dyn std::error::Error>> {
    let id = surrealdb::RecordId::from_str("user:abc123")?;
    let container = ContainerFull { id: id.clone() };

    let s = serde_json::to_string(&container)?;
    assert_eq!(s, format!("{{\"id\":\"{id}\"}}"));

    let parsed: ContainerFull = serde_json::from_str(&s)?;
    assert_eq!(parsed.id.to_string(), id.to_string());

    Ok(())
}

#[test]
fn test_record_id_naked_serialize() -> Result<(), Box<dyn std::error::Error>> {
    let id = surrealdb::RecordId::from_str("user:xyz789")?;
    let container = ContainerNaked { id: id.clone() };

    let s = serde_json::to_string(&container)?;

    let expected_key = id.key().to_string();
    assert_eq!(s, format!("{{\"id\":\"{}\"}}", expected_key));

    Ok(())
}

#[test]
fn test_decode_payload_insecurely_success() -> Result<(), Box<dyn std::error::Error>> {
    let claims = types::SurrealJWTClaims {
        iat: 1,
        nbf: 2,
        exp: 3,
        iss: "issuer".into(),
        jti: "jti".into(),
        ns: "ns".into(),
        db: "db".into(),
        ac: json!({ "role": "admin" }),
        id: "subject".into(),
    };

    let payload_bytes = serde_json::to_vec(&claims)?;
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
    let token = format!("header.{}.sig", payload_b64);

    let decoded = decode_payload_insecurely::<serde_json::Value>(&token)?;

    // Verify some fields round-trip
    assert_eq!(decoded.iat, claims.iat);
    assert_eq!(decoded.iss, claims.iss);
    assert_eq!(decoded.db, claims.db);
    assert_eq!(decoded.ac["role"], "admin");

    Ok(())
}

#[test]
fn test_decode_payload_insecurely_errors() {
    // Missing payload
    let res = decode_payload_insecurely::<serde_json::Value>("no-dots");
    assert!(res.is_err());

    // Invalid base64 in payload
    let res = decode_payload_insecurely::<serde_json::Value>("a.invalid!!.c");
    assert!(res.is_err());
}
