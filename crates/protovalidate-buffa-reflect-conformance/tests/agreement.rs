//! The reflection validator and the plugin's generated validators report the
//! same violations, on the same messages, valid and not; and validating a
//! generated type agrees with validating the same message decoded dynamically.

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
    let reflected = summary(validator.validate(&typed));
    let dynamic = summary(validator.validate(&dynamic));
    assert_eq!(reflected, generated, "{json}");
    assert_eq!(dynamic, reflected, "{json}");
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
