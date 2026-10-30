//! Static types, for resolving fields and refusing impossible expressions at
//! compile time.

use buffa_descriptor::{
    DescriptorPool, FieldDescriptor, FieldKind, MessageIndex, ScalarType, SingularKind,
};

use super::value::{self, Const, Wkt};

/// The static type of an expression. `Dyn` is anything, checked when it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ty {
    Dyn,
    Null,
    Bool,
    Int,
    Uint,
    Double,
    String,
    Bytes,
    Duration,
    Timestamp,
    Message(MessageIndex),
    List(Box<Self>),
    Map(Box<Self>, Box<Self>),
    Type,
}

impl Ty {
    pub fn of_field(fd: &FieldDescriptor, pool: &DescriptorPool) -> Self {
        match fd.kind() {
            FieldKind::Singular(k) => Self::of_singular(k, pool),
            FieldKind::List(k) => Self::List(Box::new(Self::of_singular(k, pool))),
            FieldKind::Map { key, value } => Self::Map(
                Box::new(Self::of_scalar(key)),
                Box::new(Self::of_singular(value, pool)),
            ),
        }
    }

    /// The type of one element of a field: the field's own type, unless it
    /// is repeated or a map, where it is the item or the value.
    pub fn of_singular(k: SingularKind, pool: &DescriptorPool) -> Self {
        match k {
            SingularKind::Scalar(s) => Self::of_scalar(s),
            SingularKind::Enum(_) => Self::Int,
            SingularKind::Message(idx) => Self::of_message(idx, pool),
        }
    }

    pub fn of_message(idx: MessageIndex, pool: &DescriptorPool) -> Self {
        let md = pool.message(idx);
        match value::wkt(md) {
            Some(Wkt::Timestamp) => Self::Timestamp,
            Some(Wkt::Duration) => Self::Duration,
            Some(Wkt::Struct) => Self::Map(Box::new(Self::String), Box::new(Self::Dyn)),
            Some(Wkt::ListValue) => Self::List(Box::new(Self::Dyn)),
            Some(Wkt::Wrapper | Wkt::Value) => Self::Dyn,
            _ => Self::Message(idx),
        }
    }

    pub const fn of_scalar(s: ScalarType) -> Self {
        match s {
            ScalarType::Double | ScalarType::Float => Self::Double,
            ScalarType::Int64
            | ScalarType::Sfixed64
            | ScalarType::Sint64
            | ScalarType::Int32
            | ScalarType::Sfixed32
            | ScalarType::Sint32 => Self::Int,
            ScalarType::Uint64 | ScalarType::Fixed64 | ScalarType::Uint32 | ScalarType::Fixed32 => {
                Self::Uint
            }
            ScalarType::Bool => Self::Bool,
            ScalarType::String => Self::String,
            ScalarType::Bytes => Self::Bytes,
        }
    }

    pub fn of_const(c: &Const, pool: &DescriptorPool) -> Self {
        match c {
            Const::Null => Self::Null,
            Const::Bool(_) => Self::Bool,
            Const::Int(_) => Self::Int,
            Const::Uint(_) => Self::Uint,
            Const::Double(_) => Self::Double,
            Const::String(_) => Self::String,
            Const::Bytes(_) => Self::Bytes,
            Const::Duration(_) => Self::Duration,
            Const::Timestamp(_) => Self::Timestamp,
            Const::Message(m) => Self::of_message(m.index, pool),
            Const::List(items) => Self::List(Box::new(
                items.first().map_or(Self::Dyn, |i| Self::of_const(i, pool)),
            )),
            Const::Map(_) => Self::Map(Box::new(Self::Dyn), Box::new(Self::Dyn)),
            Const::Type(_) => Self::Type,
        }
    }

    pub const fn is_dyn(&self) -> bool {
        matches!(self, Self::Dyn)
    }

    /// Whether a value of this type could be a `want`.
    pub fn admits(&self, want: &Self) -> bool {
        match (self, want) {
            (Self::Dyn, _) | (_, Self::Dyn) => true,
            (Self::List(a), Self::List(b)) => a.admits(b),
            (Self::Map(ak, av), Self::Map(bk, bv)) => ak.admits(bk) && av.admits(bv),
            (a, b) => a == b,
        }
    }

    pub const fn is_number(&self) -> bool {
        matches!(self, Self::Int | Self::Uint | Self::Double | Self::Dyn)
    }

    pub fn name(&self, pool: &DescriptorPool) -> String {
        match self {
            Self::Dyn => "dyn".into(),
            Self::Null => "null_type".into(),
            Self::Bool => "bool".into(),
            Self::Int => "int".into(),
            Self::Uint => "uint".into(),
            Self::Double => "double".into(),
            Self::String => "string".into(),
            Self::Bytes => "bytes".into(),
            Self::Duration => "google.protobuf.Duration".into(),
            Self::Timestamp => "google.protobuf.Timestamp".into(),
            Self::Message(idx) => pool.message(*idx).full_name().into(),
            Self::List(t) => format!("list({})", t.name(pool)),
            Self::Map(k, v) => format!("map({}, {})", k.name(pool), v.name(pool)),
            Self::Type => "type".into(),
        }
    }
}
