//! `#[connect_impl(set = ...)]` picks one of several loaded validator sets.
//!
//! Two sets implement `Validate` for the same request type, so the inferred
//! form would be ambiguous (E0283); naming the set selects its rules.

#![warn(rust_2018_idioms)]
#![cfg(feature = "connect")]
#![allow(
    clippy::result_large_err,
    clippy::used_underscore_binding,
    reason = "test scaffolding: fake connectrpc trait signature + macro-expanded bindings named _var"
)]

use protovalidate_buffa::{FieldPath, Validate, ValidationError, Violation, connect_impl};

struct Request;

/// Accepts every request.
enum Lenient {}

/// Rejects every request.
mod strict {
    pub enum Validators {}
}

impl Validate<Lenient> for Request {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl Validate<strict::Validators> for Request {
    fn validate(&self) -> Result<(), ValidationError> {
        Err(ValidationError {
            violations: vec![Violation {
                field: FieldPath::default(),
                rule: FieldPath::default(),
                rule_id: "strict".into(),
                message: "strict fails".into(),
                for_key: false,
            }],
            ..Default::default()
        })
    }
}

struct ServiceRequest<'a, T>(&'a T);

impl<T> ServiceRequest<'_, T> {
    const fn view(&self) -> &T {
        self.0
    }
}

trait Service {
    fn handle(
        &self,
        request: ServiceRequest<'_, Request>,
    ) -> Result<(), ::connectrpc::ConnectError>;
}

struct LenientServer;
struct StrictServer;

#[connect_impl(set = Lenient)]
impl Service for LenientServer {
    fn handle(
        &self,
        _request: ServiceRequest<'_, Request>,
    ) -> Result<(), ::connectrpc::ConnectError> {
        Ok(())
    }
}

#[connect_impl(set = strict::Validators)]
impl Service for StrictServer {
    fn handle(
        &self,
        _request: ServiceRequest<'_, Request>,
    ) -> Result<(), ::connectrpc::ConnectError> {
        Ok(())
    }
}

#[test]
fn named_set_selects_its_validator() {
    LenientServer.handle(ServiceRequest(&Request)).unwrap();
    let err = StrictServer.handle(ServiceRequest(&Request)).unwrap_err();
    assert_eq!(err.code, ::connectrpc::ErrorCode::InvalidArgument);
    let details = protovalidate_buffa::decode_violations(&err.details[0])
        .unwrap()
        .unwrap();
    assert_eq!(details.violations[0].rule_id.as_deref(), Some("strict"));
}

#[test]
fn explicit_set_and_erased_validator_agree() {
    assert!(Validate::<Lenient>::validate(&Request).is_ok());
    assert!(<Request as Validate<strict::Validators>>::validate(&Request).is_err());
    let strict = protovalidate_buffa::validator::<Request, strict::Validators>();
    assert!(strict(&Request).is_err());
}
