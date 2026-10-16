//! Generate the geo.v1 validators against the geo.v1 types crate.

include!("../build_support.rs");

fn main() -> anyhow::Result<()> {
    validators(
        &["geo/v1/geo.proto"],
        "packaging=false,file_per_package=true,extern_path=.geo=::geo_types::geo",
    )
}
