//! [Protovalidate] for buffa messages, through reflection.
//!
//! A [`Validator`] reads a message type's `buf.validate` rules from its
//! descriptors the first time it sees the type, compiles them into a plan,
//! and caches the plan. As in protovalidate's other implementations (Go,
//! Java, Python, C++, ES), nothing is generated per message: any message the
//! descriptor pool describes can be validated, including one whose schema is
//! only known at runtime.
//!
//! Validation reads the message's encoding, not a decoded message: one pass
//! over each message's fields finds what its rules read, straight from the
//! bytes, as a decoder would read them. A server can validate a request
//! before decoding it ([`Validator::validate_encoded`]); a message in hand
//! is encoded first ([`Validator::validate`]), which costs less than reading
//! it through reflection.
//!
//! Standard rules are the CEL in `validate.proto` itself, compiled with the
//! rule's values folded in. A rule that folds to a test of the value and its
//! fields, as every standard rule and most custom rules do, runs as a native
//! check; other CEL is compiled to a typed tree evaluated over reflection;
//! what that tree does not express runs on the [`cel`] interpreter. A valid
//! message validates without allocating.
//!
//! Generated types need reflection (`generate_reflection(true)` in
//! `buffa-build`, or the plugin's `reflection` option).
//!
//! ```ignore
//! let validator = protovalidate_buffa_reflect::Validator::new();
//! validator.validate(&request)?;
//! ```
//!
//! [Protovalidate]: https://protovalidate.com
//! [`cel`]: https://docs.rs/cel

mod cel;
#[cfg(feature = "connect")]
mod connect;
mod plan;
mod walk;
mod wire;

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    sync::{
        Arc, LazyLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use buffa::Message;
use buffa_descriptor::{DescriptorPool, MessageDescriptor, MessageIndex, reflect::ReflectMessage};
#[cfg(feature = "connect")]
pub use connect::ValidateInterceptor;
pub use protovalidate_buffa::{
    FieldPath, FieldPathElement, FieldType, Subscript, ValidationError, Violation,
};

use crate::{
    cel::value::Msg,
    plan::{Builder, Plans},
    walk::{Abort, Walker},
    wire::{Malformed, Src},
};

/// Validates messages against the rules in their descriptors.
///
/// Plans are cached per message type for the validator's lifetime, so keep
/// one validator (or use [`validate`], which shares one) rather than making
/// one per call. A validator is `Send + Sync`.
pub struct Validator {
    /// Unique for the process's lifetime: see [`LAST`].
    id: u64,
    /// By descriptor address, which the plans' hold on their pool keeps from
    /// being reused.
    plans: RwLock<HashMap<usize, Arc<Plans>, BuildHasherDefault<AddressHasher>>>,
}

thread_local! {
    /// The plans this thread last used, by validator id and descriptor
    /// address. Validating the same type again, the common case, then takes
    /// no lock.
    static LAST: RefCell<Option<(u64, usize, Arc<Plans>)>> = const { RefCell::new(None) };
    /// A buffer to encode messages into, kept between validations.
    static BUFFER: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

impl Default for Validator {
    fn default() -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            plans: RwLock::default(),
        }
    }
}

impl Validator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates `message` and every message it holds.
    ///
    /// The message is encoded, and its encoding validated as
    /// [`validate_encoded`](Self::validate_encoded) does.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] with the violations found, or with
    /// `compile_error` set when the message's rules cannot be compiled, or
    /// `runtime_error` when a rule cannot be evaluated.
    pub fn validate<M: Message + ReflectMessage>(
        &self,
        message: &M,
    ) -> Result<(), ValidationError> {
        let mut buffer = BUFFER.take();
        buffer.clear();
        message.encode(&mut buffer);
        let md = message.message_descriptor();
        let result = self.with_plans(md, message.pool(), |plans| run(plans, &buffer));
        BUFFER.set(buffer);
        result.unwrap_or_else(|Malformed| Err(malformed(md)))
    }

    /// Validates an encoded message of type `message` in `pool`, without
    /// decoding it: fields are read from the encoding as a decoder reads
    /// them. A [`DynamicMessage`](buffa_descriptor::reflect::DynamicMessage)
    /// is validated through its encoding.
    ///
    /// Bytes that are not an encoding of the message are a `runtime_error`
    /// where the validation reads them; parts it does not read are not
    /// checked, so decoding may still fail.
    ///
    /// # Errors
    ///
    /// As [`validate`](Self::validate).
    pub fn validate_encoded(
        &self,
        pool: &Arc<DescriptorPool>,
        message: MessageIndex,
        bytes: &[u8],
    ) -> Result<(), ValidationError> {
        let md = pool.message(message);
        self.with_plans(md, pool, |plans| run(plans, bytes))
            .unwrap_or_else(|Malformed| Err(malformed(md)))
    }

    /// [`validate_encoded`](Self::validate_encoded), telling bytes that do
    /// not decode apart.
    #[cfg(feature = "connect")]
    fn validate_wire(
        &self,
        pool: &Arc<DescriptorPool>,
        message: MessageIndex,
        bytes: &[u8],
    ) -> Result<Result<(), ValidationError>, Malformed> {
        self.with_plans(pool.message(message), pool, |plans| run(plans, bytes))
    }

    fn with_plans<R>(
        &self,
        md: &MessageDescriptor,
        pool: &Arc<DescriptorPool>,
        f: impl FnOnce(&Plans) -> R,
    ) -> R {
        let key = std::ptr::from_ref::<MessageDescriptor>(md) as usize;
        LAST.with(|last| {
            let plans = {
                let Ok(cached) = last.try_borrow() else {
                    return f(&self.plans(md, key, pool));
                };
                match &*cached {
                    Some((id, k, plans)) if *id == self.id && *k == key => return f(plans),
                    _ => self.plans(md, key, pool),
                }
            };
            if let Ok(mut cached) = last.try_borrow_mut() {
                *cached = Some((self.id, key, Arc::clone(&plans)));
            }
            f(&plans)
        })
    }

    fn plans(&self, md: &MessageDescriptor, key: usize, pool: &Arc<DescriptorPool>) -> Arc<Plans> {
        let found = self
            .plans
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .map(Arc::clone);
        found.unwrap_or_else(|| {
            let idx = pool
                .message_index(md.full_name())
                .expect("a message's descriptor is in its own pool");
            let built = Arc::new(Builder::new(pool).build(idx));
            let mut map = self
                .plans
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(map.entry(key).or_insert(built))
        })
    }
}

fn run(plans: &Plans, bytes: &[u8]) -> Result<Result<(), ValidationError>, Malformed> {
    let mut walker = Walker::new(plans);
    let root = Msg::new(Src::Bytes(bytes), plans.root, &plans.pool);
    Ok(match walker.root(&root) {
        Ok(()) if walker.violations.is_empty() => Ok(()),
        Ok(()) => Err(ValidationError {
            violations: walker.violations,
            ..ValidationError::default()
        }),
        Err(Abort::Compile(e)) => Err(ValidationError {
            compile_error: Some(e),
            ..ValidationError::default()
        }),
        Err(Abort::Runtime(e)) => Err(ValidationError {
            runtime_error: Some(e),
            ..ValidationError::default()
        }),
        Err(Abort::Malformed) => return Err(Malformed),
    })
}

fn malformed(md: &MessageDescriptor) -> ValidationError {
    ValidationError {
        runtime_error: Some(format!("malformed encoding of {}", md.full_name())),
        ..ValidationError::default()
    }
}

/// Validates `message` with a validator shared by the process.
///
/// # Errors
///
/// As [`Validator::validate`].
pub fn validate<M: Message + ReflectMessage>(message: &M) -> Result<(), ValidationError> {
    static SHARED: LazyLock<Validator> = LazyLock::new(Validator::new);
    SHARED.validate(message)
}

/// Hashes a descriptor's address: already unique, it needs no mixing beyond
/// dropping the alignment bits.
#[derive(Default)]
struct AddressHasher(u64);

impl Hasher for AddressHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0 << 8) | u64::from(b);
        }
    }

    fn write_usize(&mut self, n: usize) {
        self.0 = (n as u64 >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    }
}

// Plans hold compiled programs and descriptors; nothing in them is tied to a
// thread.
const _: () = {
    const fn sync<T: Send + Sync>() {}
    sync::<Validator>();
};
