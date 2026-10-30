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
    cell::RefCell,
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
    wire::{Found, Src},
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
    static CACHE: RefCell<Cache> = const {
        RefCell::new(Cache {
            last: None,
            buffer: Vec::new(),
            spare: Vec::new(),
        })
    };
}

/// What a thread keeps between validations.
struct Cache {
    /// The plans this thread last used, by validator id and descriptor
    /// address. Validating the same type again, the common case, then takes
    /// no lock.
    last: Option<(u64, usize, Arc<Plans>)>,
    /// A buffer to encode messages into.
    buffer: Vec<u8>,
    /// The walker's slot buffers.
    spare: Vec<Vec<Found>>,
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
        let md = message.message_descriptor();
        let encode = |buffer: &mut Vec<u8>| {
            buffer.clear();
            message.encode(buffer);
        };
        self.with_cache(md, message.pool(), |plans, scratch| {
            encode(scratch.buffer);
            run(plans, scratch.buffer, scratch.spare)
        })
        .map_err(|f| f.into_error(md))
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
        self.with_cache(md, pool, |plans, scratch| run(plans, bytes, scratch.spare))
            .map_err(|f| f.into_error(md))
    }

    /// [`validate_encoded`](Self::validate_encoded), telling bytes that do
    /// not decode apart.
    #[cfg(feature = "connect")]
    fn validate_wire(
        &self,
        pool: &Arc<DescriptorPool>,
        message: MessageIndex,
        bytes: &[u8],
    ) -> Result<(), Box<Failure>> {
        self.with_cache(pool.message(message), pool, |plans, scratch| {
            run(plans, bytes, scratch.spare)
        })
    }

    #[cfg(test)]
    pub(crate) fn probe_cache(&self, md: &MessageDescriptor, pool: &Arc<DescriptorPool>) -> usize {
        self.with_cache(md, pool, |p, _| p.messages.len())
    }

    #[cfg(test)]
    pub(crate) fn probe_run(
        &self,
        md: &MessageDescriptor,
        pool: &Arc<DescriptorPool>,
        b: &[u8],
    ) -> bool {
        self.with_cache(md, pool, |p, s| run(p, b, s.spare).is_ok())
    }

    /// Calls `f` with the plans for `md`, and the thread's buffers unless a
    /// validation on this thread is already using them.
    fn with_cache<R>(
        &self,
        md: &MessageDescriptor,
        pool: &Arc<DescriptorPool>,
        f: impl FnOnce(&Plans, Scratch<'_>) -> R,
    ) -> R {
        let key = std::ptr::from_ref::<MessageDescriptor>(md) as usize;
        CACHE.with(|cache| {
            let Ok(mut cache) = cache.try_borrow_mut() else {
                let (mut buffer, mut spare) = (Vec::new(), Vec::new());
                let scratch = Scratch {
                    buffer: &mut buffer,
                    spare: &mut spare,
                };
                return f(&self.plans(md, key, pool), scratch);
            };
            let Cache {
                last,
                buffer,
                spare,
            } = &mut *cache;
            let plans = match last {
                Some((id, k, plans)) if *id == self.id && *k == key => plans,
                _ => &*last.insert((self.id, key, self.plans(md, key, pool))).2,
            };
            f(plans, Scratch { buffer, spare })
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

/// The thread's buffers, lent to one validation.
struct Scratch<'c> {
    buffer: &'c mut Vec<u8>,
    spare: &'c mut Vec<Vec<Found>>,
}

/// Why a validation did not pass, boxed so that passing, the common case,
/// returns in a register.
enum Failure {
    Invalid(ValidationError),
    Malformed,
}

impl Failure {
    fn into_error(self: Box<Self>, md: &MessageDescriptor) -> ValidationError {
        match *self {
            Self::Invalid(e) => e,
            Self::Malformed => ValidationError {
                runtime_error: Some(format!("malformed encoding of {}", md.full_name())),
                ..ValidationError::default()
            },
        }
    }
}

fn run(plans: &Plans, bytes: &[u8], spare: &mut Vec<Vec<Found>>) -> Result<(), Box<Failure>> {
    let mut walker = Walker::new(plans, std::mem::take(spare));
    let root = Msg::new(Src::Bytes(bytes), plans.root, &plans.pool);
    let result = walker.root(&root);
    *spare = std::mem::take(&mut walker.spare);
    let error = match result.map_err(|abort| *abort) {
        Ok(()) if walker.violations.is_empty() => return Ok(()),
        Ok(()) => ValidationError {
            violations: walker.violations,
            ..ValidationError::default()
        },
        Err(Abort::Compile(e)) => ValidationError {
            compile_error: Some(e),
            ..ValidationError::default()
        },
        Err(Abort::Runtime(e)) => ValidationError {
            runtime_error: Some(e),
            ..ValidationError::default()
        },
        Err(Abort::Malformed) => return Err(Box::new(Failure::Malformed)),
    };
    Err(Box::new(Failure::Invalid(error)))
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
