// The validator crate is a dependency but nothing names it, so Rust never
// loads it and no validators exist. This is the call `#[connect_impl]`
// expands to.
use app_types::app::v1::Tag;

fn main() {
    let _ = <_ as protovalidate_buffa::Validate<_>>::validate(&Tag::default());
}
