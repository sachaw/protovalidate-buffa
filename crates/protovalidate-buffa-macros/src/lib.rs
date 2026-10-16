//! `#[connect_impl]` — validates the request view at the top of every Connect
//! service handler method in an `impl` block whose request parameter is an
//! `OwnedView<_>` or `connectrpc::ServiceRequest<'_, _>`. Single-site safety
//! net: add it once to the service impl and every present-and-future handler is
//! validated on entry.
//!
//! Validation borrows `OwnedView::reborrow()` or `ServiceRequest::view()` and
//! requires `Validate` on the generated view type. It does not convert the
//! request to an owned message.
//!
//! Non-handler `async fn`s inside the same `impl` block are left alone
//! (they lack a recognized request parameter, so the macro skips them).
//!
//! The validator set is inferred. When more than one set of validators for a
//! request type is loaded, name the one to use:
//! `#[connect_impl(set = acme_protovalidate::acme::v1::__Validators)]`.

use proc_macro::TokenStream;
use quote::{quote, quote_spanned};
use syn::{
    Error, FnArg, ImplItem, ItemImpl, PatType, Token, Type, TypePath,
    parse::{ParseStream, Parser as _},
    parse_macro_input,
};

#[proc_macro_attribute]
pub fn connect_impl(attr: TokenStream, input: TokenStream) -> TokenStream {
    let set = if attr.is_empty() {
        quote! { _ }
    } else {
        match parse_set.parse(attr) {
            Ok(set) => quote! { #set },
            Err(error) => return error.to_compile_error().into(),
        }
    };

    let mut item = parse_macro_input!(input as ItemImpl);

    for impl_item in &mut item.items {
        if let ImplItem::Fn(f) = impl_item
            && let Some((arg_ident, request_type)) = find_request_arg(&f.sig)
        {
            // Point missing view-validator errors at the request parameter.
            let span = arg_ident.span();
            let view = match request_type {
                RequestType::OwnedView => quote_spanned! {span=> #arg_ident.reborrow() },
                RequestType::ServiceRequest => quote_spanned! {span=> #arg_ident.view() },
            };
            let validate: syn::Stmt = syn::parse_quote_spanned! {span=>
                <_ as ::protovalidate_buffa::Validate<#set>>::validate(#view)
                    .map_err(::protovalidate_buffa::ValidationError::into_connect_error)?;
            };

            f.block.stmts.insert(0, validate);
        }
    }

    TokenStream::from(quote! { #item })
}

/// Parse the optional `set = <validator set>` argument.
fn parse_set(input: ParseStream<'_>) -> syn::Result<Type> {
    let key: syn::Ident = input.parse()?;
    if key != "set" {
        return Err(Error::new(
            key.span(),
            "protovalidate_buffa::connect_impl accepts only `set = <validator set>`",
        ));
    }
    input.parse::<Token![=]>()?;
    let set = input.parse()?;
    if !input.is_empty() {
        return Err(input.error("unexpected tokens after the validator set"));
    }
    Ok(set)
}

enum RequestType {
    OwnedView,
    ServiceRequest,
}

/// Returns the first recognized request parameter and its view accessor kind.
/// Non-handler methods that lack such a parameter return `None`.
fn find_request_arg(sig: &syn::Signature) -> Option<(syn::Ident, RequestType)> {
    for arg in &sig.inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = arg
            && let Some(request_type) = request_type(ty)
            && let syn::Pat::Ident(pat_ident) = pat.as_ref()
        {
            return Some((pat_ident.ident.clone(), request_type));
        }
    }
    None
}

fn request_type(ty: &Type) -> Option<RequestType> {
    if let Type::Path(TypePath { path, .. }) = ty
        && let Some(last) = path.segments.last()
    {
        if last.ident == "OwnedView" {
            return Some(RequestType::OwnedView);
        }
        if last.ident == "ServiceRequest" {
            return Some(RequestType::ServiceRequest);
        }
    }
    None
}
