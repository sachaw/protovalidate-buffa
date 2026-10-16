//! Validators generated into their own crate validate types from another
//! crate, including messages embedded from a dependency module.

#![warn(rust_2018_idioms)]

// Rust only loads a dependency it is told about; this line is what makes
// the app.v1 validators exist in this crate.
use app_types::app::v1::{
    __buffa::{oneof::create_site_request::Target, view::CreateSiteRequestView},
    CreateSiteRequest, Kind, Tag,
};
use app_validate as _;
use buffa::{Message as _, MessageView as _};
use geo_types::geo::v1::{GeoPoint, geo_point::Accuracy};
// The geo.v1 validators are loaded too. `GeoPoint` then has a public
// validator from geo-validate and an embedded copy in app-validate; only
// the public one is a `Validate` impl, so calls stay unambiguous.
use geo_validate as _;
use protovalidate_buffa::{Validate, ValidationError, validator};

fn point(lat: f64, meters: f64) -> GeoPoint {
    GeoPoint {
        lat,
        lon: 2.0,
        accuracy: Accuracy {
            meters,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    }
}

fn valid() -> CreateSiteRequest {
    CreateSiteRequest {
        name: "hq".into(),
        location: point(1.0, 3.0).into(),
        tags: vec![Tag {
            value: "a".into(),
            ..Default::default()
        }],
        kind: Some(Kind::KIND_OFFICE.into()),
        ..Default::default()
    }
}

/// Every violation as `(dotted field path, rule id)`.
fn violations(result: Result<(), ValidationError>) -> Vec<(String, String)> {
    let Err(error) = result else {
        return Vec::new();
    };
    assert!(error.compile_error.is_none() && error.runtime_error.is_none());
    error
        .violations
        .iter()
        .map(|v| {
            let path = v
                .field
                .elements
                .iter()
                .map(|e| e.field_name.as_deref().unwrap_or_default())
                .collect::<Vec<_>>()
                .join(".");
            (path, v.rule_id.to_string())
        })
        .collect()
}

/// Validate the owned message and its view, which must agree.
fn check(request: &CreateSiteRequest) -> Vec<(String, String)> {
    let bytes = request.encode_to_vec();
    let view = CreateSiteRequestView::decode_view(&bytes).expect("decode view");
    let owned = violations(request.validate());
    assert_eq!(
        owned,
        violations(view.validate()),
        "owned and view disagree"
    );
    owned
}

fn pairs(expected: &[(&str, &str)]) -> Vec<(String, String)> {
    expected
        .iter()
        .map(|(path, rule)| ((*path).to_string(), (*rule).to_string()))
        .collect()
}

#[test]
fn valid_request_passes() {
    assert_eq!(check(&valid()), []);
}

#[test]
fn local_and_embedded_rules_report_nested_paths() {
    let mut request = valid();
    request.name.clear();
    request.location = point(99.0, 0.0).into();
    request.tags[0].value = "way-too-long".into();
    assert_eq!(
        check(&request),
        pairs(&[
            ("name", "string.min_len"),
            ("location.lat", "double.gte_lte"),
            ("location.accuracy.meters", "double.gt"),
            ("tags.value", "string.max_len"),
        ])
    );
}

#[test]
fn embedded_rules_apply_through_oneofs_and_maps() {
    let mut request = valid();
    request.target = Some(Target::Point(Box::new(point(-91.0, 1.0))));
    request.waypoints.insert("gate".into(), point(1.0, -1.0));
    assert_eq!(
        check(&request),
        pairs(&[
            ("waypoints.accuracy.meters", "double.gt"),
            ("point.lat", "double.gte_lte"),
        ])
    );
}

#[test]
fn required_imported_message() {
    let mut request = valid();
    request.location = buffa::MessageField::none();
    assert_eq!(check(&request), pairs(&[("location", "required")]));
}

/// Regression: enum rules on an explicit-presence enum field
/// (`Option<EnumValue<_>>`) were not emitted at all.
#[test]
fn explicit_presence_enum_rules_apply() {
    let mut request = valid();
    request.kind = None;
    assert_eq!(check(&request), []);
    request.kind = Some(Kind::KIND_UNSPECIFIED.into());
    assert_eq!(check(&request), pairs(&[("kind", "enum.not_in")]));
    request.kind = Some(buffa::EnumValue::from(99));
    assert_eq!(check(&request), pairs(&[("kind", "enum.defined_only")]));
}

#[test]
fn dependency_module_validators_are_unambiguous() {
    // geo-validate's public impl, alongside app-validate's embedded copy.
    assert_eq!(violations(point(99.0, 1.0).validate()).len(), 1);
    assert_eq!(
        violations(Validate::<geo_validate::geo::v1::__Validators>::validate(
            &point(1.0, 0.0)
        )),
        pairs(&[("accuracy.meters", "double.gt")])
    );
}

/// Generic code carries the set as a parameter or erases it.
#[test]
fn generic_and_erased_validation() {
    fn failures<M: Validate<S>, S>(messages: &[M]) -> usize {
        messages.iter().filter(|m| m.validate().is_err()).count()
    }
    let invalid = CreateSiteRequest::default();
    assert_eq!(failures(&[valid(), invalid.clone()]), 1);

    let check = validator::<CreateSiteRequest, _>();
    assert!(check(&valid()).is_ok());
    assert!(check(&invalid).is_err());
}

/// Each file embeds only the imported messages it reaches that carry rules.
#[test]
fn embedded_copies_are_pruned() {
    let source = include_str!(concat!(env!("OUT_DIR"), "/app.v1.rs"));
    let source = source.split_whitespace().collect::<Vec<_>>().join(" ");
    for embedded in [
        "GeoPoint {",
        "__buffa::view::GeoPointView<'_> {",
        "geo_point::Accuracy {",
        "__buffa::view::geo_point::AccuracyView<'_> {",
    ] {
        let header = format!(
            "impl ::protovalidate_buffa::__private::Embedded<__Validators> for ::geo_types::geo::v1::{embedded}"
        );
        assert!(source.contains(&header), "missing {header}");
    }
    // `Label` has no rules and `Unrelated` is not referenced.
    assert!(!source.contains("Label"));
    assert!(!source.contains("Unrelated"));
}
