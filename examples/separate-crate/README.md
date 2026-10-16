# Validators in their own crate

These four crates mirror Buffer Schema Registry SDKs: one Buffa types crate
per module and one validator crate per module, with `app.v1` importing
`geo.v1`.

| Crate | Contents | Depends on |
| --- | --- | --- |
| [`geo-types`](geo-types/) | Buffa types for [`geo.v1`](proto/geo/v1/geo.proto) | `buffa` |
| [`app-types`](app-types/) | Buffa types for [`app.v1`](proto/app/v1/app.proto) | `geo-types` |
| [`geo-validate`](geo-validate/) | Validators for `geo.v1` | `geo-types` |
| [`app-validate`](app-validate/) | Validators for `app.v1` | `app-types`, `geo-types` |

`app-validate` does not depend on `geo-validate`. The `geo.v1` messages that
`app.v1` embeds carry rules, so the plugin copies those rules into
`app.v1.rs`. `geo.v1.Label` has no rules and `geo.v1.Unrelated` is never
referenced, so neither is copied.

Each build script compiles the schemas with `protoc` and runs the generator
in-process. The validator crates use the options a `buf.gen.yaml` would pass:

```text
packaging=false,file_per_package=true,
extern_path=.app=::app_types::app,extern_path=.geo=::geo_types::geo
```

Code that validates these types loads the validator crates once, at its crate
root:

```rust
use app_validate as _;
```

The [integration tests](app-validate/tests/) are separate crates that use
the validators this way. They validate owned messages and views, nested and
embedded messages through singular, oneof and map fields, an
explicit-presence enum, generic and type-erased calls, and `#[connect_impl]`
with an explicit `set`. The [UI tests](app-validate/tests/ui/) check the
compile errors for an unloaded validator crate and for two validator sets for
one type.

You need Rust and `protoc` on `PATH`, or set `PROTOC` to its executable. From
the repository root:

```sh
cargo test -p protovalidate-buffa-separate-crate-app-validate
```
