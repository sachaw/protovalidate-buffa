//! Implementation details shared with generated validators.

use std::borrow::Borrow;

use crate::ValidationError;

/// Validation for a message from another module, copied into a generated
/// file.
///
/// When a generated message embeds a message whose file is not being
/// generated (for example a type from a dependency module), the plugin copies
/// that message's rules into the same file as impls of this trait, keyed by
/// the file's validator-set marker. Nested validation then never depends on
/// another validator crate. Keeping the copies off [`crate::Validate`] means
/// they can never make a user's `validate()` call ambiguous.
pub trait Embedded<Set> {
    /// Runs every rule attached to this message and its nested messages.
    ///
    /// # Errors
    ///
    /// Returns a [`ValidationError`] as [`crate::Validate::validate`] does.
    fn validate(&self) -> Result<(), ValidationError>;
}

/// A zero-allocation, last-write-wins adapter over a protobuf map view.
///
/// Buffa's [`buffa::MapView`] retains duplicate wire entries. Validation must
/// instead observe protobuf map semantics, where only the last value for each
/// key exists. Buffa's unique iterator provides that behavior without copying
/// keys or values, at O(n²) worst-case cost.
#[derive(Debug)]
pub struct CanonicalMap<'view, 'buffer, K, V> {
    view: &'view buffa::MapView<'buffer, K, V>,
}

impl<'view, 'buffer, K, V> CanonicalMap<'view, 'buffer, K, V>
where
    K: PartialEq,
{
    /// Borrow a Buffa map view with canonical protobuf map semantics.
    #[must_use]
    pub const fn from_view(view: &'view buffa::MapView<'buffer, K, V>) -> Self {
        Self { view }
    }

    /// Return the number of distinct keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.view.len_unique()
    }

    /// Return whether the canonical map contains no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.view.is_empty()
    }

    /// Return the last value associated with `key`.
    #[must_use]
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.view.get(key)
    }

    /// Return whether `key` is present.
    #[must_use]
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: PartialEq + ?Sized,
    {
        self.view.contains_key(key)
    }

    /// Iterate over distinct keys at their last wire position.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.view.iter_unique().map(|(key, _)| key)
    }

    /// Iterate over distinct key/value pairs at their last wire position.
    pub fn iter(&self) -> impl Iterator<Item = &(K, V)> {
        self.view.iter_unique()
    }
}
