//! `#[connect_impl]` validates request views of types from another crate
//! with the validator set it is given.

#![warn(rust_2018_idioms)]
#![allow(
    clippy::result_large_err,
    reason = "handler signatures return connectrpc::ConnectError"
)]

use app_types::app::v1::{__buffa::view::CreateSiteRequestView, CreateSiteRequest};
use app_validate as _;
use buffa::{Message as _, MessageView as _, OwnedView, bytes::Bytes};
use connectrpc::{ConnectError, ServiceRequest};
use protovalidate_buffa::{Validate, ValidationError, connect_impl};

/// A second, local validator set for the same request view, which accepts
/// everything. With it loaded, `CreateSiteRequestView` has two `Validate`
/// impls, so `#[connect_impl]` must be told which one to use.
enum AcceptAll {}

impl Validate<AcceptAll> for CreateSiteRequestView<'_> {
    fn validate(&self) -> Result<(), ValidationError> {
        Ok(())
    }
}

trait SiteService {
    fn create_site(
        &self,
        request: ServiceRequest<'_, CreateSiteRequest>,
    ) -> Result<usize, ConnectError>;
}

trait OwnedSiteService {
    fn create_site(
        &self,
        request: OwnedView<CreateSiteRequestView<'static>>,
    ) -> Result<usize, ConnectError>;
}

struct Generated;
struct Local;

#[connect_impl(set = app_validate::app::v1::__Validators)]
impl SiteService for Generated {
    fn create_site(
        &self,
        request: ServiceRequest<'_, CreateSiteRequest>,
    ) -> Result<usize, ConnectError> {
        Ok(request.name.len())
    }
}

#[connect_impl(set = AcceptAll)]
impl OwnedSiteService for Local {
    fn create_site(
        &self,
        request: OwnedView<CreateSiteRequestView<'static>>,
    ) -> Result<usize, ConnectError> {
        Ok(request.reborrow().name.len())
    }
}

#[test]
fn named_sets_select_the_validator() {
    let body = Bytes::from(CreateSiteRequest::default().encode_to_vec());
    let view = CreateSiteRequestView::decode_view(&body).unwrap();
    let request = ServiceRequest::<CreateSiteRequest>::from_parts(&view, &body);
    let error = Generated.create_site(request).unwrap_err();
    assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);

    let request = OwnedView::<CreateSiteRequestView<'static>>::decode(body).unwrap();
    assert_eq!(Local.create_site(request).unwrap(), 0);
}
