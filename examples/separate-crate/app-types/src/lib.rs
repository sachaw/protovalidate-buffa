//! Buffa types for `app.v1`, laid out like a registry SDK crate.
#![warn(rust_2018_idioms)]

#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    elided_lifetimes_in_paths,
    non_camel_case_types,
    unused_imports,
    reason = "Buffa generated code"
)]
pub mod app {
    pub mod v1 {
        include!(concat!(env!("OUT_DIR"), "/app.v1.rs"));
    }
}
