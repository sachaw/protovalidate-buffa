//! Executor for the upstream `protovalidate-conformance` harness, validating
//! through reflection: each case is decoded as a [`DynamicMessage`] against
//! the descriptors the harness sends, as protovalidate-go's executor does.
//!
//! Protocol: a `TestConformanceRequest` on stdin, a `TestConformanceResponse`
//! on stdout.

use std::{
    io::{self, Read, Write},
    sync::Arc,
};

use anyhow::{Context, anyhow};
use buffa::Message;
use buffa_descriptor::{
    DescriptorPool,
    reflect::{
        DynamicMessage, MapKey, MapValue, ReflectMessage, ReflectMessageMut, Value, ValueRef,
    },
};
use protovalidate_buffa_reflect::Validator;

const HARNESS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/harness.fds"));

fn main() -> anyhow::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let harness = Arc::new(DescriptorPool::decode(HARNESS)?);
    let request = DynamicMessage::new_by_name(
        Arc::clone(&harness),
        "buf.validate.conformance.harness.TestConformanceRequest",
    )
    .context("harness request type")?;
    let mut request = request;
    request.merge(&input)?;

    let fdset = match field(&request, "fdset") {
        Some(ValueRef::Message(m)) => m.to_dynamic().encode_to_vec(),
        _ => return Err(anyhow!("request has no fdset")),
    };
    let cases = Arc::new(DescriptorPool::decode(&fdset)?);
    let validator = Validator::new();

    let mut results = Vec::new();
    if let Some(ValueRef::Map(map)) = field(&request, "cases") {
        let mut err = None;
        map.for_each(&mut |name, any| {
            let buffa_descriptor::reflect::MapKeyRef::String(name) = name else {
                return;
            };
            let ValueRef::Message(any) = any else { return };
            match run(&harness, &cases, &validator, &*any) {
                Ok(result) => {
                    results.push((MapKey::String(name.to_owned()), Value::Message(result)))
                }
                Err(e) => err = Some(e),
            }
        });
        if let Some(e) = err {
            return Err(e);
        }
    }

    let mut response = DynamicMessage::new_by_name(
        Arc::clone(&harness),
        "buf.validate.conformance.harness.TestConformanceResponse",
    )
    .context("harness response type")?;
    let results_fd = harness
        .message_by_name("buf.validate.conformance.harness.TestConformanceResponse")
        .and_then(|md| md.field_by_name("results"))
        .context("results field")?;
    response.set(results_fd, Value::Map(MapValue::from_entries(results)));
    io::stdout().write_all(&response.encode_to_vec())?;
    Ok(())
}

fn field<'m>(m: &'m dyn ReflectMessage, name: &str) -> Option<ValueRef<'m>> {
    let fd = m.message_descriptor().field_by_name(name)?;
    Some(m.get(fd))
}

fn run(
    harness: &Arc<DescriptorPool>,
    cases: &Arc<DescriptorPool>,
    validator: &Validator,
    any: &dyn ReflectMessage,
) -> anyhow::Result<DynamicMessage> {
    let mut result = DynamicMessage::new_by_name(
        Arc::clone(harness),
        "buf.validate.conformance.harness.TestResult",
    )
    .context("harness result type")?;
    let (Some(ValueRef::String(url)), Some(ValueRef::Bytes(bytes))) =
        (field(any, "type_url"), field(any, "value"))
    else {
        return Err(anyhow!("case is not an Any"));
    };
    let name = url.rsplit_once('/').map_or(url, |(_, n)| n);
    let result_md = harness
        .message_by_name("buf.validate.conformance.harness.TestResult")
        .context("harness result type")?;
    let mut set = |name: &str, value: Value| {
        let fd = result_md
            .field_by_name(name)
            .expect("TestResult declares every outcome");
        result.set(fd, value);
    };
    let Some(message) = DynamicMessage::new_by_name(Arc::clone(cases), name) else {
        set(
            "unexpected_error",
            Value::String(format!("unknown message type {name}")),
        );
        return Ok(result);
    };
    let mut message = message;
    if let Err(e) = message.merge(bytes) {
        set(
            "unexpected_error",
            Value::String(format!("decoding {name}: {e}")),
        );
        return Ok(result);
    }
    match validator.validate(&message) {
        Ok(()) => set("success", Value::Bool(true)),
        Err(e) if e.compile_error.is_some() => {
            set(
                "compilation_error",
                Value::String(e.compile_error.unwrap_or_default()),
            );
        }
        Err(e) if e.runtime_error.is_some() => {
            set(
                "runtime_error",
                Value::String(e.runtime_error.unwrap_or_default()),
            );
        }
        Err(e) => {
            let violations =
                DynamicMessage::new_by_name(Arc::clone(harness), "buf.validate.Violations")
                    .context("violations type")?;
            let mut violations = violations;
            violations.merge(&e.to_proto().encode_to_vec())?;
            set("validation_error", Value::Message(violations));
        }
    }
    Ok(result)
}
