//! Conformance cases as reflective buffa types, with the plugin's generated
//! validators, for comparing the two validators on the same messages.

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
    reason = "buffa-build and plugin generated code"
)]
pub mod cases {
    include!(concat!(env!("OUT_DIR"), "/_include.rs"));
}
