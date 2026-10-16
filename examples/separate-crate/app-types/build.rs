//! Generate the app.v1 Buffa types; geo.v1 types come from their own crate.

include!("../build_support.rs");

fn main() -> anyhow::Result<()> {
    types(&["app/v1/app.proto"], &[(".geo", "::geo_types::geo")])
}
