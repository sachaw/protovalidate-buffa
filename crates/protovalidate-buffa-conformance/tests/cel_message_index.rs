#![warn(rust_2018_idioms)]

use buffa::{Message as _, MessageView as _};
use protovalidate_buffa::{Validate as _, ValidationError};

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    dead_code,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_html_tags,
    reason = "buffa-build generated code"
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}

use generated::buf::validate::conformance::cases::{
    __buffa::view::CelMessageListIndexView, CelMessageListIndex, cel_message_list_index::Child,
};

fn child(id: &str) -> Child {
    Child {
        id: id.to_owned(),
        ..Default::default()
    }
}

/// Validates `message` owned and as a view.
fn results(message: &CelMessageListIndex) -> [Result<(), ValidationError>; 2] {
    let bytes = message.encode_to_vec();
    let view = CelMessageListIndexView::decode_view(&bytes).unwrap();
    [message.validate(), view.validate()]
}

fn assert_rules(message: &CelMessageListIndex, expected: &[&str]) {
    for result in results(message) {
        let rules: Vec<String> = result.err().map_or_else(Vec::new, |e| {
            assert!(e.compile_error.is_none(), "{e:?}");
            assert!(e.runtime_error.is_none(), "{e:?}");
            e.violations.iter().map(|v| v.rule_id.to_string()).collect()
        });
        assert_eq!(rules, expected);
    }
}

#[test]
fn indexes_a_list_of_messages() {
    assert_rules(&CelMessageListIndex::default(), &[]);
    let valid = CelMessageListIndex {
        children: vec![child("a"), child("b")],
        picks: vec![0, 1],
        ..Default::default()
    };
    assert_rules(&valid, &[]);
    assert_rules(
        &CelMessageListIndex {
            children: vec![child(""), child("b")],
            ..valid.clone()
        },
        &["list.message_index"],
    );
    assert_rules(
        &CelMessageListIndex {
            children: vec![child("a"), child("bad")],
            ..valid
        },
        &["list.computed_index"],
    );
}

#[test]
fn indexes_nested_lists_of_messages() {
    let nested = |axis| CelMessageListIndex {
        children: vec![
            child("a"),
            Child {
                id: "b".to_owned(),
                children: vec![Child {
                    axis,
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    assert_rules(&nested(2), &[]);
    assert_rules(&nested(3), &["list.nested_index"]);
}

#[test]
fn indexes_a_list_of_messages_optionally() {
    let message = |third| CelMessageListIndex {
        children: vec![child("a"), child("b"), child(third)],
        ..Default::default()
    };
    assert_rules(&message("c"), &[]);
    assert_rules(&message("none"), &["list.optional_index"]);
}

#[test]
fn indexes_a_map_of_messages() {
    let named = |entries: &[(&str, &str)]| CelMessageListIndex {
        named: entries
            .iter()
            .map(|(k, id)| ((*k).to_owned(), child(id)))
            .collect(),
        ..Default::default()
    };
    assert_rules(&named(&[("k", "k"), ("z", "z")]), &[]);
    assert_rules(&named(&[("k", "x")]), &["map.message_index"]);
    assert_rules(&named(&[("z", "y")]), &["map.optional_index"]);
}

#[test]
fn indexing_a_list_of_messages_out_of_range_is_a_runtime_error() {
    for index in [2, u32::MAX] {
        let message = CelMessageListIndex {
            children: vec![child("a"), child("b")],
            picks: vec![index],
            ..Default::default()
        };
        for result in results(&message) {
            assert_eq!(
                result.unwrap_err().runtime_error,
                Some(
                    "cel runtime error in rule \"list.computed_index\": index out of range"
                        .to_owned()
                )
            );
        }
    }
}
