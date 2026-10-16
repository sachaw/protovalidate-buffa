//! Runtime companion for `protoc-gen-protovalidate-buffa`.
//!
//! Provides the [`Validate`] trait, the [`ValidationError`] /
//! [`Violation`] / [`FieldPath`] types returned from generated
//! `validate()` methods, the [`cel`] module of thin helpers that
//! compile-time-expanded CEL rules call into (scalar widening,
//! Duration/Timestamp converters, `now`), and the [`rules`] module
//! of pure-Rust helpers used by generated code (UUID / ULID / IP /
//! URI / hostname checks and friends, mostly thin wrappers over
//! `uuid`, `ulid`, `ipnet`, and `fluent-uri`).
//!
//! There is **no CEL interpreter at runtime**: the paired
//! `protoc-gen-protovalidate-buffa` plugin transpiles every CEL rule
//! to native Rust at codegen time. Generated `validate()` methods are
//! direct field-access checks without per-call dynamic CEL `Value`
//! materialization. Rules that need scratch state, such as repeated-value
//! uniqueness, allocate it directly.
//!
//! [`ValidationError`] carries three orthogonal signals:
//!
//! - `violations`: list of per-field rule failures (the common case).
//! - `compile_error`: non-empty when the codegen plugin detected a
//!   schema-level mismatch (rule type / field type, duplicate / unknown
//!   fields in `message.oneof`, CEL referencing a non-existent field).
//! - `runtime_error`: non-empty when a rule's precondition could not be
//!   evaluated (e.g. `bytes.pattern` on non-UTF-8 input, or a CEL rule
//!   that compiled-time analysis flagged as always-runtime-error such as
//!   `dyn(this).<unknown_field>`).
//!
//! The full upstream `protovalidate-conformance` suite (2872 cases,
//! covering proto2, proto3, and editions 2023) passes against code
//! emitted by the paired plugin.
//!
//! # Validators in their own crate
//!
//! Generated validators can live in the same crate as the Buffa message
//! types or in a separate crate that depends on a types crate (for example a
//! Buffa SDK from the Buffer Schema Registry). A crate that uses validators
//! from another crate must load it once, at its crate root:
//!
//! ```ignore
//! use acme_protovalidate as _;
//! ```
//!
//! Rust ignores a dependency that is never referenced, so without this line
//! no validator impls exist and calls to `validate()` fail to compile with a
//! note pointing here. See [`Validate`].

#[doc(hidden)]
pub mod __private;
pub mod cel;
mod error;
#[cfg(feature = "protos")]
mod error_proto;
pub mod rules;

#[cfg(feature = "connect")]
mod connect;
// Re-export `regex` so generated patterns (`::protovalidate_buffa::regex::Regex`)
// resolve without each downstream crate having to add a direct `regex` dep.
// `buffa` is re-exported for convenience but generated code uses the
// `::buffa::` path directly; downstream crates already depend on buffa for
// their message types.
pub use buffa;
/// Date/time types and traits used by generated CEL timestamp expressions.
pub use chrono;
/// IANA timezone database, re-exported so generated code can reference
/// `::protovalidate_buffa::chrono_tz::Tz` when a CEL rule uses the
/// timezone-argument form of a timestamp accessor
/// (`t.getHours("America/New_York")`). Only exported when the `tz`
/// feature is enabled — rules without tz args don't need this dep.
#[cfg(feature = "tz")]
pub use chrono_tz;
#[cfg(feature = "connect")]
pub use connect::{DecodeViolationsError, decode_violations};
pub use error::{FieldPath, FieldPathElement, FieldType, Subscript, ValidationError, Violation};
/// `#[connect_impl]` — attribute macro applied to a Connect service `impl`
/// block that validates the borrowed request view at the top of every handler
/// method, without converting it to an owned message. Requires `Validate` on
/// the generated view type.
/// Guarantees protovalidate runs for every RPC without relying on per-handler
/// discipline.
///
/// Only exported when the `connect` feature is enabled (the default), since
/// the emitted code calls [`ValidationError::into_connect_error`].
#[cfg(feature = "connect")]
pub use protovalidate_buffa_macros::connect_impl;
/// Canonical generated `buf.validate` messages, including `Violations`.
///
/// Requires the `protos` feature (also enabled by `connect`). These are the
/// types from `protovalidate-buffa-protos`; callers need no duplicate codegen.
#[cfg(feature = "protos")]
#[doc(no_inline)]
pub use protovalidate_buffa_protos::buf::validate as proto;
pub use regex;

/// Validation for a generated message or view.
///
/// `protoc-gen-protovalidate-buffa` implements this trait for every message
/// and view type in the files it generates. `Set` is a hidden marker type
/// (`__Validators`) that each generated file declares. Because the marker is
/// local to the generated code, the impls are legal even when the message
/// types come from another crate, so validators can live in their own crate
/// beside a Buffa types crate.
///
/// Call sites never name `Set`; Rust infers it:
///
/// ```ignore
/// use protovalidate_buffa::Validate as _;
///
/// request.validate()?;
/// ```
///
/// # Loading validators from another crate
///
/// Rust only links a dependency's impls when the crate is referenced. A
/// validator crate that only appears in `Cargo.toml` contributes nothing, so
/// reference it once at the crate root:
///
/// ```ignore
/// use acme_protovalidate as _;
/// ```
///
/// Validators generated into the same crate as the code that calls them
/// need no such line.
///
/// # Generic code
///
/// Carry the set as a type parameter, `fn check<M: Validate<S>, S>(m: &M)`, or
/// erase it with [`validator`].
///
/// # Several validator sets for one type
///
/// If two validator sets for the same type are loaded (for example a
/// registry SDK and a local regeneration), inference reports the ambiguity
/// (`E0283`). Pick one explicitly:
/// `Validate::<acme_protovalidate::acme::v1::__Validators>::validate(&m)`, or
/// `#[connect_impl(set = acme_protovalidate::acme::v1::__Validators)]`.
#[diagnostic::on_unimplemented(
    message = "no protovalidate validators for `{Self}` are loaded",
    label = "no validators for this type are loaded",
    note = "load the crate protoc-gen-protovalidate-buffa generated for this type's module with `use <crate> as _;` at your crate root"
)]
pub trait Validate<Set> {
    /// Runs every rule attached to this message (and any nested messages),
    /// collecting violations rather than short-circuiting on the first.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] containing one or more [`Violation`]s
    /// when any rule fails, or compilation/evaluation diagnostics when a rule
    /// cannot run. For RPC requests, `ValidationError::into_connect_error`
    /// (the `connect` feature) maps violations to `invalid_argument` and
    /// validator defects to `internal`.
    fn validate(&self) -> Result<(), ValidationError>;
}

/// The validator for `M` as a plain function pointer, with the validator set
/// erased.
///
/// Generic code that stores validation for later, such as a store keyed by
/// message type, cannot add a `Set` parameter to an impl that does not use
/// it. Capture the function where `M` is concrete instead and store it:
///
/// ```
/// use protovalidate_buffa::{Validate, ValidationError, validator};
///
/// struct Store<M> {
///     check: fn(&M) -> Result<(), ValidationError>,
///     items: Vec<M>,
/// }
///
/// impl<M> Store<M> {
///     fn new<S>() -> Self
///     where
///         M: Validate<S>,
///     {
///         Self { check: validator::<M, S>(), items: Vec::new() }
///     }
///
///     fn insert(&mut self, item: M) -> Result<(), ValidationError> {
///         (self.check)(&item)?;
///         self.items.push(item);
///         Ok(())
///     }
/// }
///
/// # enum Local {}
/// # struct Name(String);
/// # impl Validate<Local> for Name {
/// #     fn validate(&self) -> Result<(), ValidationError> {
/// #         if self.0.is_empty() { Err(ValidationError::default()) } else { Ok(()) }
/// #     }
/// # }
/// let mut names = Store::<Name>::new();
/// assert!(names.insert(Name("ada".into())).is_ok());
/// assert!(names.insert(Name(String::new())).is_err());
/// ```
#[must_use]
pub const fn validator<M, Set>() -> fn(&M) -> Result<(), ValidationError>
where
    M: Validate<Set> + ?Sized,
{
    <M as Validate<Set>>::validate
}

#[macro_export]
macro_rules! field_path {
    ( $( $part:expr ),* $(,)? ) => {{
        let mut elements = ::std::vec::Vec::new();
        $(
            elements.push($crate::FieldPathElement {
                field_number: None,
                field_name: Some(::std::borrow::Cow::Borrowed($part)),
                field_type: None,
                key_type: None,
                value_type: None,
                subscript: None,
            });
        )*
        $crate::FieldPath { elements }
    }};
}
