//! Generate the app.v1 validators against the types crates. Rules for the
//! geo.v1 messages that app.v1 embeds are copied in, so this crate does not
//! depend on the geo.v1 validators.

include!("../build_support.rs");

fn main() -> anyhow::Result<()> {
    validators(
        &["app/v1/app.proto"],
        "packaging=false,file_per_package=true,\
         extern_path=.app=::app_types::app,extern_path=.geo=::geo_types::geo",
    )
}
