//! The descriptor-driven validator and the plugin's generated validators
//! report the same violations, on the same messages, valid and not; and
//! validating an encoding agrees with decoding it and validating the decoded
//! message, however the encoding is written.

use std::sync::Arc;

use buffa::Message;
use buffa_descriptor::reflect::{DynamicMessage, ReflectMessage};
use protovalidate_buffa::{Validate, ValidationError};
use protovalidate_buffa_reflect::Validator;
use protovalidate_buffa_reflect_conformance::cases::buf::validate::conformance::cases::{
    self as c, custom_rules as cr,
};

fn summary(result: Result<(), ValidationError>) -> Vec<String> {
    let Err(e) = result else { return Vec::new() };
    let mut out: Vec<String> = e
        .violations
        .iter()
        .map(|v| {
            format!(
                "{} | {} | {} | for_key={}",
                v.field, v.rule, v.rule_id, v.for_key
            )
        })
        .collect();
    // The diagnostics' wording is each validator's own.
    out.extend(e.compile_error.map(|_| "compile error".to_owned()));
    out.extend(e.runtime_error.map(|_| "runtime error".to_owned()));
    out.sort();
    out
}

fn agree<M>(json: &str)
where
    M: Message + ReflectMessage + Validate + Default,
{
    let pool = c::__buffa::reflect::descriptor_pool();
    let idx = pool
        .message_index(M::default().message_descriptor().full_name())
        .expect("a case type");
    let dynamic = DynamicMessage::from_json(Arc::clone(pool), idx, json).expect("valid JSON");
    let typed = M::decode_from_slice(&dynamic.encode_to_vec()).expect("decodes");
    let validator = Validator::new();
    let generated = summary(typed.validate());
    let typed = summary(validator.validate(&typed));
    let encoded = summary(validator.validate_encoded(pool, idx, &dynamic.encode_to_vec()));
    assert_eq!(typed, generated, "{json}");
    assert_eq!(encoded, generated, "{json}");
}

/// Validating `bytes` agrees with decoding them and validating the decoded
/// message.
fn agree_encoded<M>(bytes: &[u8])
where
    M: Message + ReflectMessage + Validate + Default,
{
    let pool = c::__buffa::reflect::descriptor_pool();
    let idx = pool
        .message_index(M::default().message_descriptor().full_name())
        .expect("a case type");
    let decoded = M::decode_from_slice(bytes).expect("decodes");
    let generated = summary(decoded.validate());
    let encoded = summary(Validator::new().validate_encoded(pool, idx, bytes));
    assert_eq!(encoded, generated, "{bytes:02x?}");
}

const COMPLEX: &[(&str, &str)] = &[
    ("const", r#""abcd""#),
    ("intConst", "5"),
    ("boolConst", "false"),
    ("floatVal", "1.5"),
    ("durVal", r#""3s""#),
    ("tsVal", r#""1970-01-01T00:00:08Z""#),
    ("floatConst", "7"),
    ("doubleIn", "123"),
    ("enumConst", "2"),
    ("bytesVal", r#""AJk=""#),
    ("x", r#""x""#),
    (
        "anyVal",
        r#"{"@type": "type.googleapis.com/google.protobuf.Duration", "value": "1s"}"#,
    ),
    ("repTsVal", r#"["1970-01-01T00:00:01Z"]"#),
    ("mapVal", r#"{"-1": "a"}"#),
];

/// A valid `ComplexTestMsg`, with some fields replaced.
fn complex(changes: &[(&str, &str)]) -> String {
    let mut fields: Vec<(&str, &str)> = COMPLEX.to_vec();
    for (k, v) in changes {
        match fields.iter_mut().find(|(f, _)| f == k) {
            Some(field) => field.1 = v,
            None => fields.push((k, v)),
        }
    }
    if changes.iter().any(|(k, _)| *k == "y") {
        fields.retain(|(k, _)| *k != "x");
    }
    let body: Vec<String> = fields
        .iter()
        .map(|(k, v)| format!(r#""{k}": {v}"#))
        .collect();
    format!("{{{}}}", body.join(", "))
}

#[test]
fn kitchen_sink() {
    agree::<c::KitchenSinkMessage>("{}");
    agree::<c::KitchenSinkMessage>(&format!(r#"{{"val": {}}}"#, complex(&[])));
    let nested = complex(&[]);
    agree::<c::KitchenSinkMessage>(&format!(
        r#"{{"val": {}}}"#,
        complex(&[("nested", &nested), ("another", "{}")])
    ));
    for broken in [
        ("const", r#""abc""#),
        ("intConst", "4"),
        ("boolConst", "true"),
        ("floatVal", "0"),
        ("durVal", r#""20s""#),
        ("tsVal", r#""1970-01-01T00:00:07Z""#),
        ("floatConst", "8"),
        ("doubleIn", "1"),
        ("enumConst", "1"),
        ("bytesVal", r#""AA==""#),
        (
            "anyVal",
            r#"{"@type": "type.googleapis.com/google.protobuf.Timestamp", "value": "1970-01-01T00:00:00Z"}"#,
        ),
        (
            "repTsVal",
            r#"["1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z"]"#,
        ),
        ("mapVal", r#"{"1": "a", "-2": "b"}"#),
        ("y", "1"),
    ] {
        agree::<c::KitchenSinkMessage>(&format!(r#"{{"val": {}}}"#, complex(&[broken])));
        let nested = complex(&[broken]);
        agree::<c::KitchenSinkMessage>(&format!(
            r#"{{"val": {}}}"#,
            complex(&[("nested", &nested)])
        ));
    }
}

#[test]
fn message_expressions() {
    for json in [
        r#"{"a": 1, "b": 2, "c": 0, "d": 1, "e": {"a": 3, "b": 2}, "f": {"a": 3, "b": 1}}"#,
        r#"{"a": 2, "b": 1}"#,
        r#"{"a": 1, "b": 2, "c": 1, "d": 1}"#,
        r#"{"a": 1, "b": 2, "e": {"a": 1, "b": 2}, "f": {"a": 3, "b": 1}}"#,
        "{}",
    ] {
        agree::<cr::MessageExpressions>(json);
    }
    agree::<cr::FieldExpressionMultipleScalar>(r#"{"val": 1}"#);
    agree::<cr::FieldExpressionMultipleScalar>(r#"{"val": 3}"#);
    agree::<cr::MissingField>(r#"{"a": 1}"#);
}

#[test]
fn strings() {
    for v in ["", "foo", "foo@example.com", "foo@ex ample.com"] {
        agree::<c::StringEmail>(&format!(r#"{{"val": "{v}"}}"#));
    }
    for v in ["", "abc123", "abc!"] {
        agree::<c::StringPattern>(&format!(r#"{{"val": "{v}"}}"#));
    }
    for v in ["", "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "6ba7b810"] {
        agree::<c::StringUUID>(&format!(r#"{{"val": "{v}"}}"#));
    }
    for v in ["", "a", "abcdef"] {
        agree::<c::StringLen>(&format!(r#"{{"val": "{v}"}}"#));
    }
}

#[test]
fn repeated_and_maps() {
    agree::<c::RepeatedItemPattern>(r#"{"val": ["abc", "d-e", "fgh", "!"]}"#);
    agree::<c::RepeatedUnique>(r#"{"val": ["a", "b", "a"]}"#);
    agree::<c::RepeatedUnique>(r#"{"val": ["a", "b", "c"]}"#);
    agree::<c::RepeatedMin>(r#"{"val": [{"val": 1}]}"#);
    agree::<c::RepeatedMin>(r#"{"val": [{"val": 1}, {"val": -1}]}"#);
    agree::<c::MapValues>(r#"{"val": {"a": "ab", "b": "abcd"}}"#);
    agree::<c::MapKeys>(r#"{"val": {"1": "a", "-1": "b"}}"#);
    agree::<c::MapKeysPattern>(r#"{"val": {"a!": "x", "ok": "y"}}"#);
}

/// Encodings a decoder reads differently from how they are written: fields
/// repeated, out of order, split, cleared by a oneof sibling, or unknown.
#[test]
fn encodings() {
    // StringLen: val (1) has len == 3.
    agree_encoded::<c::StringLen>(b"\x0a\x01a\x0a\x03abc");
    agree_encoded::<c::StringLen>(b"\x0a\x03abc\x0a\x01a");
    // Unknown fields are skipped.
    agree_encoded::<c::StringLen>(b"\x10\x05\x0a\x03abc\x78\x01");
    // RepeatedMin: val (1), repeated Embed { val (1) > 0 }, min_items 2.
    agree_encoded::<c::RepeatedMin>(b"\x0a\x02\x08\x01\x12\x00\x0a\x02\x08\x7f");
    agree_encoded::<c::RepeatedMin>(b"\x0a\x00\x0a\x02\x08\x01");
    // RepeatedUnique, written twice over.
    agree_encoded::<c::RepeatedUnique>(b"\x0a\x01a\x0a\x01b\x0a\x01a");
    // MapKeys: map<sint64, string> keys < 0; a repeated key keeps the last.
    agree_encoded::<c::MapKeys>(b"\x0a\x05\x08\x01\x12\x01a\x0a\x05\x08\x01\x12\x01b");
    agree_encoded::<c::MapKeys>(b"\x0a\x05\x08\x01\x12\x01a");
    agree_encoded::<c::MapKeys>(b"\x0a\x00");
    agree_encoded::<c::MapKeysPattern>(
        b"\x0a\x07\x0a\x02a!\x12\x01x\x0a\x07\x0a\x02a!\x12\x01y\x0a\x07\x0a\x02ok\x12\x01y",
    );
    // MessageExpressions: e (5) split over two occurrences merges into
    // {a: 1, b: 2}, which fails `a > b`; f (6) is written whole.
    agree_encoded::<cr::MessageExpressions>(
        b"\x08\x01\x10\x02\x2a\x02\x08\x01\x2a\x02\x10\x02\x32\x04\x08\x03\x10\x01",
    );
    agree_encoded::<cr::MessageExpressions>(
        b"\x08\x01\x10\x02\x2a\x02\x10\x02\x2a\x02\x08\x03\x32\x04\x08\x03\x10\x01",
    );
    // An implicit-presence field written as zero is unset.
    agree_encoded::<cr::MessageExpressions>(b"\x08\x00\x10\x01");
    // KitchenSink's oneof o (x = 16, y = 17) is required: the last member
    // written is the one set.
    let complex = |tail: &[u8]| {
        let mut m = b"\x0a\x04abcd\x18\x05\x32\x02\x08\x03".to_vec();
        m.extend_from_slice(tail);
        let mut out = vec![0x0a];
        out.push(u8::try_from(m.len()).expect("short"));
        out.extend(m);
        out
    };
    agree_encoded::<c::KitchenSinkMessage>(&complex(b"\x82\x01\x01x\x88\x01\x01"));
    agree_encoded::<c::KitchenSinkMessage>(&complex(b"\x88\x01\x01\x82\x01\x01x"));
    agree_encoded::<c::KitchenSinkMessage>(&complex(b""));
    // dur_val (6) written twice: the second, 20s, breaks `lt: 17s`.
    agree_encoded::<c::KitchenSinkMessage>(&complex(b"\x32\x02\x08\x14\x82\x01\x01x"));
    // val (1) split in two, and its nested (2) split across the halves: the
    // halves merge, and so do the nested message's.
    let half = |m: &[u8]| {
        let mut out = vec![0x0a, u8::try_from(m.len()).expect("short")];
        out.extend_from_slice(m);
        out
    };
    let nested_a = b"\x0a\x04abcd";
    let nested_b = b"\x18\x05\x32\x02\x08\x03\x82\x01\x01x";
    for nested_b in [&nested_b[..], b"\x18\x04\x32\x02\x08\x03\x82\x01\x01x"] {
        let mut a = b"\x0a\x04abcd\x18\x05\x12".to_vec();
        a.push(u8::try_from(nested_a.len()).expect("short"));
        a.extend_from_slice(nested_a);
        let mut b = b"\x32\x02\x08\x03\x82\x01\x01x\x12".to_vec();
        b.push(u8::try_from(nested_b.len()).expect("short"));
        b.extend_from_slice(nested_b);
        let mut bytes = half(&a);
        bytes.extend(half(&b));
        agree_encoded::<c::KitchenSinkMessage>(&bytes);
    }
}
