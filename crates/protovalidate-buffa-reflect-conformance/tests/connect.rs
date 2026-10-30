//! The Connect interceptor validates requests from the service descriptors
//! alone.

use std::sync::Arc;

use buffa_descriptor::DescriptorPool;
use bytes::Bytes;
use connectrpc::{CodecFormat, ErrorCode, Payload};
use protovalidate_buffa_reflect::ValidateInterceptor;

const GREETER: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/greeter.fds"));
const GREET: &str = "/example.v1.GreeterService/Greet";

fn interceptor() -> ValidateInterceptor {
    ValidateInterceptor::new(Arc::new(
        DescriptorPool::decode(GREETER).expect("descriptors"),
    ))
}

fn proto(bytes: &'static [u8]) -> Payload {
    Payload::new(Bytes::from_static(bytes), CodecFormat::Proto)
}

#[test]
fn accepts_a_valid_request() {
    // name: "x"
    assert!(interceptor().check(GREET, &proto(b"\x0a\x01x")).is_ok());
}

#[test]
fn rejects_an_invalid_request() {
    // tags: ["a", "a"], and no name.
    let error = interceptor()
        .check(GREET, &proto(b"\x12\x01a\x12\x01a"))
        .expect_err("invalid");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.details.len(), 1);
}

#[test]
fn reads_json_requests() {
    let json = |s: &'static str| Payload::new(Bytes::from_static(s.as_bytes()), CodecFormat::Json);
    let interceptor = interceptor();
    assert!(interceptor.check(GREET, &json(r#"{"name": "x"}"#)).is_ok());
    let error = interceptor
        .check(GREET, &json(r#"{"name": ""}"#))
        .expect_err("invalid");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn validates_each_message_of_a_stream_method() {
    let error = interceptor()
        .check("/example.v1.GreeterService/GreetMany", &proto(b""))
        .expect_err("no name");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn leaves_what_it_cannot_read_to_the_handler() {
    let interceptor = interceptor();
    assert!(
        interceptor
            .check("/other.Service/Method", &proto(b""))
            .is_ok()
    );
    assert!(interceptor.check(GREET, &proto(b"\xff\xff")).is_ok());
}
