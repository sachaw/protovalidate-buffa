//! The descriptor-driven validator against the plugin's generated validators,
//! on the same conformance messages: time and heap allocations per validation
//! of a valid message. A message in hand is validated by the generated
//! validator, or encoded and validated; an encoded one (a request) by
//! decoding it for the generated validator, or validating its encoding.
//!
//! `cargo bench -p protovalidate-buffa-reflect-conformance`

use std::{
    alloc::{GlobalAlloc, Layout, System},
    hint::black_box,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::Relaxed},
    },
    time::Instant,
};

use buffa::{
    Message,
    view::{HasMessageView, OwnedView},
};
use buffa_descriptor::reflect::{DynamicMessage, ReflectMessage};
use bytes::Bytes;
use protovalidate_buffa::Validate;
use protovalidate_buffa_reflect::Validator;
use protovalidate_buffa_reflect_conformance::cases::buf::validate::conformance::cases::{
    self as c, custom_rules as cr,
};

struct Counting;
static ALLOCS: AtomicU64 = AtomicU64::new(0);

// SAFETY: forwards to the system allocator, counting calls.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        // SAFETY: as the caller's.
        unsafe { System.alloc(l) }
    }

    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        // SAFETY: as the caller's.
        unsafe { System.dealloc(p, l) }
    }

    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        // SAFETY: as the caller's.
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// `cargo bench` passes `--bench`; `cargo test --all-targets` runs this
/// binary too, without it, to check it still works, not to time it.
fn timing() -> bool {
    std::env::args().any(|a| a == "--bench")
}

/// Best of seven runs: nanoseconds and allocations per call.
fn measure(mut f: impl FnMut()) -> (f64, f64) {
    let (warm, n) = if timing() {
        (20_000, 200_000u32)
    } else {
        (1, 1)
    };
    for _ in 0..warm {
        f();
    }
    let mut best = (f64::MAX, 0.0);
    for _ in 0..7 {
        let a0 = ALLOCS.load(Relaxed);
        let t = Instant::now();
        for _ in 0..n {
            f();
        }
        let ns = t.elapsed().as_secs_f64() * 1e9 / f64::from(n);
        #[expect(clippy::cast_precision_loss, reason = "a count of allocations")]
        let allocs = (ALLOCS.load(Relaxed) - a0) as f64 / f64::from(n);
        if ns < best.0 {
            best = (ns, allocs);
        }
    }
    best
}

fn bench<M>(name: &str, json: &str)
where
    M: Message + ReflectMessage + Validate + Default + HasMessageView,
{
    // `cargo bench -- <name>` runs the cases whose names contain it.
    if std::env::args()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .is_some_and(|filter| !name.contains(&filter))
    {
        return;
    }
    let pool = c::__buffa::reflect::descriptor_pool();
    let template = M::default();
    let idx = pool
        .message_index(template.message_descriptor().full_name())
        .expect("a case type");
    let dynamic = DynamicMessage::from_json(Arc::clone(pool), idx, json).expect("valid JSON");
    let bytes = dynamic.encode_to_vec();
    let typed = M::decode_from_slice(&bytes).expect("decodes");
    let validator = Validator::new();
    assert!(
        typed.validate().is_ok(),
        "{name}: the generated validator rejects the input"
    );
    assert!(
        validator.validate_encoded(pool, idx, &bytes).is_ok(),
        "{name}: the validator rejects the input: {:?}",
        validator.validate_encoded(pool, idx, &bytes)
    );

    let generated = measure(|| black_box(black_box(&typed).validate()).expect("valid"));
    let typed_ns = measure(|| black_box(validator.validate(black_box(&typed))).expect("valid"));
    let decode_generated = measure(|| {
        let m = M::decode_from_slice(black_box(&bytes)).expect("decodes");
        black_box(m.validate()).expect("valid");
    });
    let view = OwnedView::<M::View<'static>>::decode(Bytes::from(bytes.clone())).expect("decodes");
    let viewed = measure(|| black_box(validator.validate_view(black_box(&view))).expect("valid"));
    let plan = validator.plan(pool, idx);
    let encoded = measure(|| black_box(plan.validate(black_box(&bytes))).expect("valid"));
    println!(
        "{name:<29} {:>4} B | message: generated {:>5.0} ns, encode+validate {:>5.0} ns ({:>4.1}x), view {:>5.0} ns | encoded: decode+generated {:>5.0} ns {:>4.1} alloc, validate {:>5.0} ns {:>3.1} alloc ({:>4.2}x)",
        bytes.len(),
        generated.0,
        typed_ns.0,
        typed_ns.0 / generated.0,
        viewed.0,
        decode_generated.0,
        decode_generated.1,
        encoded.0,
        encoded.1,
        encoded.0 / decode_generated.0,
    );
}

fn main() {
    let complex = r#"{
        "const": "abcd", "intConst": 5, "boolConst": false, "floatVal": 1.5,
        "durVal": "3s", "tsVal": "1970-01-01T00:00:08Z", "floatConst": 7,
        "doubleIn": 123, "enumConst": 2,
        "anyVal": {"@type": "type.googleapis.com/google.protobuf.Duration", "value": "1s"},
        "repTsVal": ["1970-01-01T00:00:01Z", "1970-01-01T00:00:02Z"],
        "mapVal": {"-1": "a", "-2": "b"}, "bytesVal": "AJk=", "x": "x"
    }"#;
    let kitchen_sink = format!(
        r#"{{"val": {{ {}, "nested": {complex}, "another": {complex} }} }}"#,
        complex.trim().trim_start_matches('{').trim_end_matches('}')
    );
    println!("valid messages; best of 7 runs of 200k validations");
    bench::<c::KitchenSinkMessage>("KitchenSinkMessage", &kitchen_sink);
    bench::<cr::MessageExpressions>(
        "MessageExpressions",
        r#"{"a": 1, "b": 2, "c": 0, "d": 1, "e": {"a": 3, "b": 2}, "f": {"a": 3, "b": 1}}"#,
    );
    bench::<cr::FieldExpressionMultipleScalar>("FieldExpressionMultipleScalar", r#"{"val": 3}"#);
    bench::<c::StringEmail>("StringEmail", r#"{"val": "someone@example.com"}"#);
    bench::<c::StringPattern>("StringPattern", r#"{"val": "abc123"}"#);
    bench::<c::StringUUID>(
        "StringUUID",
        r#"{"val": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}"#,
    );
    bench::<c::RepeatedItemPattern>(
        "RepeatedItemPattern",
        r#"{"val": ["abc", "def", "ghi", "jkl", "mno", "pqr", "stu", "vwx"]}"#,
    );
    bench::<c::RepeatedUnique>(
        "RepeatedUnique",
        r#"{"val": ["a", "b", "c", "d", "e", "f"]}"#,
    );
    bench::<c::MapValues>(
        "MapValues",
        r#"{"val": {"a": "abcd", "b": "bcde", "c": "cdef"}}"#,
    );
}
