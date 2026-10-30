//! [Protovalidate] for buffa messages, through reflection.
//!
//! A [`Validator`] reads a message type's `buf.validate` rules from its
//! descriptors the first time it sees the type, compiles them into a plan,
//! and caches the plan. Validating walks the message through
//! [`ReflectMessage`] against that plan. This is how protovalidate's other
//! implementations work (Go, Java, Python, C++, ES): nothing is generated
//! per message, any message the descriptor pool describes can be validated,
//! including a [`DynamicMessage`](buffa_descriptor::reflect::DynamicMessage)
//! decoded from a schema only known at runtime.
//!
//! Standard rules are the CEL in `validate.proto` itself, compiled with the
//! rule's values folded in, so most become a single comparison against a
//! literal. CEL is compiled to a typed tree that evaluates without
//! allocating; what that tree does not express runs on the [`cel`]
//! interpreter.
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

use std::{
    cell::Cell,
    collections::HashMap,
    hash::{BuildHasherDefault, Hasher},
    sync::{
        LazyLock, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use buffa_descriptor::{MessageDescriptor, reflect::ReflectMessage};
#[cfg(feature = "connect")]
pub use connect::ValidateInterceptor;
pub use protovalidate_buffa::{
    FieldPath, FieldPathElement, FieldType, Subscript, ValidationError, Violation,
};

use crate::{
    plan::{Builder, Plans},
    walk::{Abort, Walker},
};

/// Validates messages against the rules in their descriptors.
///
/// Plans are cached per message type for the validator's lifetime, so keep
/// one validator (or use [`validate`], which shares one) rather than making
/// one per call. A validator is `Send + Sync`.
pub struct Validator {
    /// Unique for the process's lifetime: see [`LAST`].
    id: u64,
    /// Boxed so a plan's address is stable; plans are never removed.
    plans: RwLock<HashMap<usize, Box<Plans>, BuildHasherDefault<AddressHasher>>>,
}

thread_local! {
    /// The plans this thread last used: validator id, descriptor address, plans.
    /// Validating the same type again, the common case, then takes no lock.
    static LAST: Cell<(u64, usize, *const Plans)> = const { Cell::new((u64::MAX, 0, std::ptr::null())) };
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
    /// # Errors
    ///
    /// Returns a [`ValidationError`] with the violations found, or with
    /// `compile_error` set when the message's rules cannot be compiled, or
    /// `runtime_error` when a rule cannot be evaluated.
    pub fn validate(&self, message: &dyn ReflectMessage) -> Result<(), ValidationError> {
        let plans = self.plans(message);
        let mut walker = Walker::new(plans);
        match walker.root(message) {
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
        }
    }

    fn plans(&self, message: &dyn ReflectMessage) -> &Plans {
        let md = message.message_descriptor();
        let key = std::ptr::from_ref::<MessageDescriptor>(md) as usize;
        let (id, last_key, last) = LAST.get();
        if id == self.id && last_key == key {
            // SAFETY: `last` points into a box this validator owns: ids are
            // never reused, plans are never removed, and `self` outlives the
            // returned borrow.
            return unsafe { &*last };
        }
        let found = self
            .plans
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&key)
            .map(|p| std::ptr::from_ref::<Plans>(p));
        let plans = found.unwrap_or_else(|| {
            let pool = message.pool();
            let idx = pool
                .message_index(md.full_name())
                .expect("a message's descriptor is in its own pool");
            let built = Box::new(Builder::new(pool).build(idx));
            let mut map = self
                .plans
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::ptr::from_ref::<Plans>(map.entry(key).or_insert(built))
        });
        LAST.set((self.id, key, plans));
        // SAFETY: as above.
        unsafe { &*plans }
    }
}

/// Validates `message` with a validator shared by the process.
///
/// # Errors
///
/// As [`Validator::validate`].
pub fn validate(message: &dyn ReflectMessage) -> Result<(), ValidationError> {
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
