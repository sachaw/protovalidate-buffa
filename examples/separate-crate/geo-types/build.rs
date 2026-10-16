//! Generate the geo.v1 Buffa types.

include!("../build_support.rs");

fn main() -> anyhow::Result<()> {
    types(&["geo/v1/geo.proto"], &[])
}
