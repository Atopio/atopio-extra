use atopio_extra::{
    deserialize_record_id, deserialize_record_id_option, serialize_record_id,
    serialize_record_id_option,
};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Serialize)]
struct SerRecord {
    #[serde(serialize_with = "serialize_record_id")]
    id: RecordId,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct DeRecord {
    #[serde(deserialize_with = "deserialize_record_id")]
    id: String,
}

#[derive(Serialize)]
struct SerOpt {
    #[serde(serialize_with = "serialize_record_id_option")]
    id: Option<RecordId>,
}

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct DeOpt {
    #[serde(deserialize_with = "deserialize_record_id_option")]
    id: Option<String>,
}

#[test]
fn test_serialize_record_id() {
    let rid = RecordId::from(("person", "john"));
    let s = SerRecord { id: rid };
    let json = serde_json::to_string(&s).expect("serialize should succeed");
    assert_eq!(json, r#"{"id":"john"}"#);
}

#[test]
fn test_deserialize_record_id() {
    let rid = RecordId::from(("person", "john"));
    let rid_json = serde_json::to_string(&rid).expect("serialize rid");
    let json_input = format!(r#"{{"id":{}}}"#, rid_json);
    let de: DeRecord = serde_json::from_str(&json_input).expect("deserialize should succeed");
    assert_eq!(de.id, "john");
}

#[test]
fn test_serialize_optional_record_id_some_and_none() {
    let some = SerOpt {
        id: Some(RecordId::from(("person", "mary"))),
    };
    let json_some = serde_json::to_string(&some).expect("serialize should succeed");
    assert_eq!(json_some, r#"{"id":"mary"}"#);

    let none = SerOpt { id: None };
    let json_none = serde_json::to_string(&none).expect("serialize should succeed");
    assert_eq!(json_none, r#"{"id":null}"#);
}

#[test]
fn test_deserialize_optional_record_id_some_and_none() {
    let rid = RecordId::from(("person", "mary"));
    let rid_json = serde_json::to_string(&rid).expect("serialize rid");
    let json_some = format!(r#"{{"id":{}}}"#, rid_json);
    let de_some: DeOpt = serde_json::from_str(&json_some).expect("deserialize should succeed");
    assert_eq!(de_some.id, Some("mary".to_string()));

    let json_none = r#"{"id":null}"#;
    let de_none: DeOpt = serde_json::from_str(&json_none).expect("deserialize should succeed");
    assert_eq!(de_none.id, None);
}

#[test]
fn test_deserialize_record_id_error_on_null() {
    let json_input = r#"{"id":null}"#;
    let res: Result<DeRecord, _> = serde_json::from_str(json_input);
    assert!(
        res.is_err(),
        "deserializing non-optional id from null should error"
    );
}
