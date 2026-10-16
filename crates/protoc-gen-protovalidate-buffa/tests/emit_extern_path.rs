//! `extern_path` / `buffa_module`: validators for types generated elsewhere.
#![warn(rust_2018_idioms)]

use buffa_codegen::generated::{
    compiler::CodeGeneratorRequest,
    descriptor::{
        DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorProto,
        field_descriptor_proto::{Label, Type},
    },
};
use protoc_gen_protovalidate_buffa::emit::{self, Options};

/// `app.v1.Site` embeds `geo.v1.Point` and `geo.v1.Point.Kind` from a
/// dependency file that is not generated.
fn request(parameter: &str) -> CodeGeneratorRequest {
    let field = |name: &str, number: i32, r#type: Type, type_name: &str| FieldDescriptorProto {
        name: Some(name.into()),
        number: Some(number),
        label: Some(Label::LABEL_OPTIONAL),
        r#type: Some(r#type),
        type_name: Some(type_name.into()),
        ..Default::default()
    };
    CodeGeneratorRequest {
        file_to_generate: vec!["app/v1/site.proto".into()],
        parameter: Some(parameter.into()),
        proto_file: vec![
            FileDescriptorProto {
                name: Some("geo/v1/point.proto".into()),
                package: Some("geo.v1".into()),
                syntax: Some("proto3".into()),
                message_type: vec![DescriptorProto {
                    name: Some("Point".into()),
                    enum_type: vec![EnumDescriptorProto {
                        name: Some("Kind".into()),
                        ..Default::default()
                    }],
                    ..Default::default()
                }],
                ..Default::default()
            },
            FileDescriptorProto {
                name: Some("app/v1/site.proto".into()),
                package: Some("app.v1".into()),
                dependency: vec!["geo/v1/point.proto".into()],
                syntax: Some("proto3".into()),
                message_type: vec![DescriptorProto {
                    name: Some("Site".into()),
                    field: vec![
                        field("location", 1, Type::TYPE_MESSAGE, ".geo.v1.Point"),
                        field("kind", 2, Type::TYPE_ENUM, ".geo.v1.Point.Kind"),
                    ],
                    ..Default::default()
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
}

fn render(parameter: &str) -> anyhow::Result<Vec<(String, String)>> {
    let request = request(parameter);
    let files = emit::render_request(&request, &Options::parse(parameter)?)?;
    Ok(files
        .into_iter()
        .map(|f| {
            let content = f.content.unwrap_or_default();
            let flat = content.split_whitespace().collect::<Vec<_>>().join(" ");
            (f.name.unwrap_or_default(), flat)
        })
        .collect())
}

#[test]
fn parses_repeatable_extern_paths_and_buffa_module() {
    let options = Options::parse(
        "extern_path=.app=::app_types::app, extern_path=geo=::geo_types::geo,buffa_module=crate::pb",
    )
    .unwrap();
    assert_eq!(
        options.extern_paths,
        [
            (".app".to_string(), "::app_types::app".to_string()),
            (".geo".to_string(), "::geo_types::geo".to_string()),
            (".".to_string(), "crate::pb".to_string()),
        ]
    );
    for invalid in [
        "extern_path=.app",
        "extern_path==::x",
        "extern_path=.app=",
        "buffa_module",
        "buffa_module=",
    ] {
        assert!(Options::parse(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn extern_paths_name_types_absolutely_in_package_named_files() {
    let files = render(
        "packaging=false,file_per_package=true,\
         extern_path=.app=::app_types::app,extern_path=.geo=::geo_types::geo",
    )
    .unwrap();
    assert_eq!(files.len(), 1);
    let (name, content) = &files[0];
    // The BSR synthesizes `lib.rs` from `<package>.rs` files.
    assert_eq!(name, "app.v1.rs");
    assert!(content.contains("for ::app_types::app::v1::Site {"));
    assert!(content.contains("for ::app_types::app::v1::__buffa::view::SiteView<'_> {"));
    assert!(!content.contains("use super::*"));
}

#[test]
fn buffa_module_maps_every_package() {
    let files = render("packaging=false,file_per_package=true,buffa_module=crate::pb").unwrap();
    assert_eq!(files[0].0, "app.v1.rs");
    assert!(files[0].1.contains("for crate::pb::app::v1::Site {"));
}

#[test]
fn proto_module_is_an_extern_path_catch_all_in_packaging_mode() {
    let files = render("proto_module=crate::pb").unwrap();
    let site = files
        .iter()
        .find(|(name, _)| name == "app.v1.site.rs")
        .unwrap();
    assert!(site.1.contains("for crate::pb::app::v1::Site {"));
    // An explicit catch-all wins over `proto_module`.
    let files = render("proto_module=crate::pb,extern_path=.=crate::types").unwrap();
    let site = files
        .iter()
        .find(|(name, _)| name == "app.v1.site.rs")
        .unwrap();
    assert!(site.1.contains("for crate::types::app::v1::Site {"));
}

#[test]
fn uncovered_packages_are_an_error() {
    let error = render("packaging=false,extern_path=.geo=::geo_types::geo")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("app.v1.Site is not covered by any extern_path"),
        "{error}"
    );
}

#[test]
fn without_extern_paths_flat_output_stays_beside_the_types() {
    let files = render("packaging=false,file_per_package=true").unwrap();
    assert_eq!(files[0].0, "app.v1.validate.rs");
    assert!(files[0].1.contains("for Site {"));
}
