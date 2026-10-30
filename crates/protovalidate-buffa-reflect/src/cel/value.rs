//! CEL values over reflected messages.
//!
//! A [`Value`] borrows from the message being validated, or from a rule's
//! constants, so reading a field, a string or a list costs no allocation.
//! Values an expression builds (concatenations, `map()` results) are
//! reference counted.

use std::{cmp::Ordering, fmt, rc::Rc, sync::Arc};

use buffa_descriptor::{
    DescriptorPool, FieldDescriptor, FieldKind, MessageDescriptor, ScalarType, SingularKind,
    reflect::{
        DynamicMessage, MapKey, MapKeyRef, ReflectCow, ReflectList, ReflectMap, ReflectMessage,
        ValueRef,
    },
};
use chrono::{DateTime, TimeDelta, Utc};

use super::Error;

/// A CEL value.
#[derive(Clone)]
pub enum Value<'a> {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(f64),
    String(Str<'a>),
    Bytes(Bin<'a>),
    Duration(TimeDelta),
    Timestamp(DateTime<Utc>),
    Message(Msg<'a>),
    List(List<'a>),
    Map(Map<'a>),
    Type(Type),
}

/// A string, borrowed or built.
#[derive(Clone)]
pub enum Str<'a> {
    Ref(&'a str),
    Rc(Rc<str>),
}

/// A byte string, borrowed or built.
#[derive(Clone)]
pub enum Bin<'a> {
    Ref(&'a [u8]),
    Rc(Rc<[u8]>),
}

/// A message.
#[derive(Clone)]
pub enum Msg<'a> {
    Ref(&'a dyn ReflectMessage),
    /// An unset message field, read as its default without building one.
    Default(&'a MessageDescriptor, &'a Arc<DescriptorPool>),
    /// A snapshot from a bridge-mode type, which reflection hands out owned.
    Owned(Rc<DynamicMessage>),
}

/// A list.
#[derive(Clone)]
pub enum List<'a> {
    Reflect(&'a dyn ReflectList),
    Owned(Rc<[Value<'a>]>),
    Const(&'a [Const]),
}

/// A map.
#[derive(Clone)]
pub enum Map<'a> {
    Reflect(&'a dyn ReflectMap, ScalarType),
    Owned(Rc<[(Value<'a>, Value<'a>)]>),
    Const(&'a [(Const, Const)]),
}

/// A CEL type, as `type()` returns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::enum_variant_names,
    reason = "`type` is CEL's name for the type of types"
)]
pub enum Type {
    Null,
    Bool,
    Int,
    Uint,
    Double,
    String,
    Bytes,
    Duration,
    Timestamp,
    Message,
    List,
    Map,
    Type,
}

impl Type {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Null => "null_type",
            Self::Bool => "bool",
            Self::Int => "int",
            Self::Uint => "uint",
            Self::Double => "double",
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::Duration => "google.protobuf.Duration",
            Self::Timestamp => "google.protobuf.Timestamp",
            Self::Message => "message",
            Self::List => "list",
            Self::Map => "map",
            Self::Type => "type",
        }
    }
}

/// An owned value: a folded constant, or a rule's value, kept in a plan.
#[derive(Clone, Debug)]
pub enum Const {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Double(f64),
    String(Box<str>),
    Bytes(Box<[u8]>),
    Duration(TimeDelta),
    Timestamp(DateTime<Utc>),
    Message(Arc<DynamicMessage>),
    List(Box<[Self]>),
    Map(Box<[(Self, Self)]>),
    Type(Type),
}

impl std::ops::Deref for Str<'_> {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            Self::Ref(s) => s,
            Self::Rc(s) => s,
        }
    }
}

impl std::ops::Deref for Bin<'_> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Ref(b) => b,
            Self::Rc(b) => b,
        }
    }
}

impl<'a> Msg<'a> {
    pub fn descriptor(&self) -> &MessageDescriptor {
        match self {
            Self::Ref(m) => m.message_descriptor(),
            Self::Default(md, _) => md,
            Self::Owned(m) => m.message_descriptor(),
        }
    }

    fn pool(&self) -> &Arc<DescriptorPool> {
        match self {
            Self::Ref(m) => m.pool(),
            Self::Default(_, pool) => pool,
            Self::Owned(m) => m.pool(),
        }
    }

    pub fn has(&self, fd: &FieldDescriptor) -> bool {
        match self {
            Self::Ref(m) => m.has(fd),
            Self::Default(..) => false,
            Self::Owned(m) => m.has(fd),
        }
    }

    /// The field with the given index in the message's descriptor, read as
    /// CEL reads it: unset fields as their defaults, well-known types as
    /// their CEL values.
    pub fn field(&self, index: usize) -> Value<'a> {
        let fd = &self.descriptor().fields()[index];
        let read = match fd.kind() {
            FieldKind::Singular(SingularKind::Message(idx)) => {
                Read::Message(wkt(self.pool().message(idx)))
            }
            _ => Read::Value,
        };
        self.read(index, read, None)
    }

    /// Reads a field whose [`Read`] was worked out when compiling; `present`
    /// when the caller already asked.
    pub fn read(&self, index: usize, read: Read, present: Option<bool>) -> Value<'a> {
        if let (Self::Ref(m), Read::Message(w)) = (self, read) {
            let fd = &m.message_descriptor().fields()[index];
            if !present.unwrap_or_else(|| m.has(fd)) {
                let FieldKind::Singular(SingularKind::Message(idx)) = fd.kind() else {
                    unreachable!("read as a message field");
                };
                return default_message(m.pool().message(idx), m.pool());
            }
            return match m.get(fd) {
                ValueRef::Message(ReflectCow::Borrowed(r)) => message_as(Msg::Ref(r), w),
                v => from_field(v, fd),
            };
        }
        if let (Self::Ref(m), Read::Value) = (self, read) {
            let fd = &m.message_descriptor().fields()[index];
            return from_field(m.get(fd), fd);
        }
        self.field_slow(index)
    }

    fn field_slow(&self, index: usize) -> Value<'a> {
        match self {
            Self::Ref(m) => {
                let fd = &m.message_descriptor().fields()[index];
                if let FieldKind::Singular(SingularKind::Message(idx)) = fd.kind()
                    && !m.has(fd)
                {
                    return default_message(m.pool().message(idx), m.pool());
                }
                from_field(m.get(fd), fd)
            }
            Self::Default(md, pool) => default_field(&md.fields()[index], pool),
            Self::Owned(m) => {
                let fd = &m.message_descriptor().fields()[index];
                if let FieldKind::Singular(SingularKind::Message(idx)) = fd.kind()
                    && !m.has(fd)
                {
                    return owned(&default_message(m.pool().message(idx), m.pool()));
                }
                owned(&from_field(m.get(fd), fd))
            }
        }
    }

    pub fn field_by_name(&self, name: &str) -> Option<Value<'a>> {
        let index = self
            .descriptor()
            .fields()
            .iter()
            .position(|f| f.name() == name)?;
        Some(self.field(index))
    }

    pub fn has_by_name(&self, name: &str) -> Option<bool> {
        let fd = self.descriptor().field_by_name(name)?;
        Some(self.has(fd))
    }

    pub fn to_dynamic(&self) -> DynamicMessage {
        match self {
            Self::Ref(m) => m.to_dynamic(),
            Self::Default(md, pool) => {
                let idx = pool
                    .message_index(md.full_name())
                    .expect("a message's descriptor is in its own pool");
                DynamicMessage::new(Arc::clone(pool), idx)
            }
            Self::Owned(m) => (**m).clone(),
        }
    }

    fn same_type(&self, other: &Self) -> bool {
        self.descriptor().full_name() == other.descriptor().full_name()
    }
}

/// Converts a value read from a field.
pub fn from_field<'a>(v: ValueRef<'a>, fd: &FieldDescriptor) -> Value<'a> {
    match (v, fd.kind()) {
        (ValueRef::Map(m), FieldKind::Map { key, .. }) => Value::Map(Map::Reflect(m, key)),
        (v, _) => from_ref(v),
    }
}

/// Converts a reflected value. A map read this way has no key type and is
/// looked up by string; [`from_field`] keeps the key type.
pub fn from_ref(v: ValueRef<'_>) -> Value<'_> {
    match v {
        ValueRef::Bool(b) => Value::Bool(b),
        ValueRef::I32(i) | ValueRef::EnumNumber(i) => Value::Int(i64::from(i)),
        ValueRef::I64(i) => Value::Int(i),
        ValueRef::U32(u) => Value::Uint(u64::from(u)),
        ValueRef::U64(u) => Value::Uint(u),
        ValueRef::F32(f) => Value::Double(f64::from(f)),
        ValueRef::F64(f) => Value::Double(f),
        ValueRef::String(s) => Value::String(Str::Ref(s)),
        ValueRef::Bytes(b) => Value::Bytes(Bin::Ref(b)),
        ValueRef::Message(ReflectCow::Borrowed(m)) => message(Msg::Ref(m)),
        ValueRef::Message(ReflectCow::Owned(m)) => message(Msg::Owned(Rc::new(*m))),
        ValueRef::List(l) => Value::List(List::Reflect(l)),
        ValueRef::Map(m) => Value::Map(Map::Reflect(m, ScalarType::String)),
    }
}

/// Deep-copies a value out of a temporary message.
fn owned<'a>(v: &Value<'_>) -> Value<'a> {
    match v {
        Value::Null => Value::Null,
        Value::Bool(b) => Value::Bool(*b),
        Value::Int(i) => Value::Int(*i),
        Value::Uint(u) => Value::Uint(*u),
        Value::Double(d) => Value::Double(*d),
        Value::String(s) => Value::String(Str::Rc(Rc::from(&**s))),
        Value::Bytes(b) => Value::Bytes(Bin::Rc(Rc::from(&**b))),
        Value::Duration(d) => Value::Duration(*d),
        Value::Timestamp(t) => Value::Timestamp(*t),
        Value::Type(t) => Value::Type(*t),
        Value::Message(Msg::Owned(m)) => Value::Message(Msg::Owned(Rc::clone(m))),
        Value::Message(m) => Value::Message(Msg::Owned(Rc::new(m.to_dynamic()))),
        Value::List(l) => {
            let mut items = Vec::with_capacity(l.len());
            for i in 0..l.len() {
                items.push(owned(&l.get(i).unwrap_or(Value::Null)));
            }
            Value::List(List::Owned(items.into()))
        }
        Value::Map(m) => {
            let mut entries = Vec::with_capacity(m.len());
            m.for_each(&mut |k, v| {
                entries.push((owned(&k), owned(&v)));
                true
            });
            Value::Map(Map::Owned(entries.into()))
        }
    }
}

/// Which well-known type a message is, if any.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wkt {
    Timestamp,
    Duration,
    Wrapper,
    Any,
    FieldMask,
    Struct,
    Value,
    ListValue,
}

pub fn wkt(md: &MessageDescriptor) -> Option<Wkt> {
    let name = md.full_name().strip_prefix("google.protobuf.")?;
    Some(match name {
        "Timestamp" => Wkt::Timestamp,
        "Duration" => Wkt::Duration,
        "BoolValue" | "Int32Value" | "Int64Value" | "UInt32Value" | "UInt64Value"
        | "FloatValue" | "DoubleValue" | "StringValue" | "BytesValue" => Wkt::Wrapper,
        "Any" => Wkt::Any,
        "FieldMask" => Wkt::FieldMask,
        "Struct" => Wkt::Struct,
        "Value" => Wkt::Value,
        "ListValue" => Wkt::ListValue,
        _ => return None,
    })
}

/// A message as CEL sees it: well-known types become their CEL values.
pub fn message(m: Msg<'_>) -> Value<'_> {
    let w = wkt(m.descriptor());
    message_as(m, w)
}

/// What reading a field yields, worked out from its descriptor once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    Value,
    /// A singular message field, and which well-known type it is.
    Message(Option<Wkt>),
}

impl Read {
    pub fn of(fd: &FieldDescriptor, pool: &DescriptorPool) -> Self {
        match fd.kind() {
            FieldKind::Singular(SingularKind::Message(idx)) => {
                Self::Message(wkt(pool.message(idx)))
            }
            _ => Self::Value,
        }
    }
}

/// [`message`], for a message whose well-known type is already known.
pub fn message_as(m: Msg<'_>, w: Option<Wkt>) -> Value<'_> {
    match w {
        Some(Wkt::Timestamp) => match seconds_nanos(&m) {
            Some((s, n)) => u32::try_from(n)
                .ok()
                .and_then(|n| DateTime::from_timestamp(s, n))
                .map_or(Value::Message(m), Value::Timestamp),
            None => Value::Message(m),
        },
        Some(Wkt::Duration) => match seconds_nanos(&m) {
            Some((s, n)) => TimeDelta::try_seconds(s)
                .and_then(|d| d.checked_add(&TimeDelta::nanoseconds(n)))
                .map_or(Value::Message(m), Value::Duration),
            None => Value::Message(m),
        },
        Some(Wkt::Wrapper | Wkt::Struct | Wkt::ListValue) => m.field(0),
        Some(Wkt::Value) => json_value(&m),
        _ => Value::Message(m),
    }
}

fn seconds_nanos(m: &Msg<'_>) -> Option<(i64, i64)> {
    let (Value::Int(s), Value::Int(n)) = (m.field(0), m.field(1)) else {
        return None;
    };
    Some((s, n))
}

fn json_value<'a>(m: &Msg<'a>) -> Value<'a> {
    let md = m.descriptor();
    for (i, fd) in md.fields().iter().enumerate() {
        if m.has(fd) {
            return match fd.name() {
                "null_value" => Value::Null,
                _ => m.field(i),
            };
        }
    }
    Value::Null
}

pub fn default_message<'a>(md: &'a MessageDescriptor, pool: &'a Arc<DescriptorPool>) -> Value<'a> {
    match wkt(md) {
        Some(Wkt::Timestamp) => Value::Timestamp(DateTime::UNIX_EPOCH),
        Some(Wkt::Duration) => Value::Duration(TimeDelta::zero()),
        Some(Wkt::Wrapper | Wkt::Value) => Value::Null,
        Some(Wkt::Struct) => Value::Map(Map::Owned(Rc::new([]))),
        Some(Wkt::ListValue) => Value::List(List::Owned(Rc::new([]))),
        _ => Value::Message(Msg::Default(md, pool)),
    }
}

fn default_field<'a>(fd: &'a FieldDescriptor, pool: &'a Arc<DescriptorPool>) -> Value<'a> {
    static EMPTY_LIST: [Const; 0] = [];
    static EMPTY_MAP: [(Const, Const); 0] = [];
    match fd.kind() {
        FieldKind::Singular(SingularKind::Scalar(s)) => default_scalar(s),
        FieldKind::Singular(SingularKind::Enum(_)) => Value::Int(0),
        FieldKind::Singular(SingularKind::Message(idx)) => default_message(pool.message(idx), pool),
        FieldKind::List(_) => Value::List(List::Const(&EMPTY_LIST)),
        FieldKind::Map { .. } => Value::Map(Map::Const(&EMPTY_MAP)),
    }
}

pub const fn default_scalar(s: ScalarType) -> Value<'static> {
    match s {
        ScalarType::Double | ScalarType::Float => Value::Double(0.0),
        ScalarType::Int64
        | ScalarType::Sfixed64
        | ScalarType::Sint64
        | ScalarType::Int32
        | ScalarType::Sfixed32
        | ScalarType::Sint32 => Value::Int(0),
        ScalarType::Uint64 | ScalarType::Fixed64 | ScalarType::Uint32 | ScalarType::Fixed32 => {
            Value::Uint(0)
        }
        ScalarType::Bool => Value::Bool(false),
        ScalarType::String => Value::String(Str::Ref("")),
        ScalarType::Bytes => Value::Bytes(Bin::Ref(&[])),
    }
}

impl<'a> List<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Reflect(l) => l.len(),
            Self::Owned(l) => l.len(),
            Self::Const(l) => l.len(),
        }
    }

    pub fn get(&self, i: usize) -> Option<Value<'a>> {
        match self {
            Self::Reflect(l) => l.get(i).map(from_ref),
            Self::Owned(l) => l.get(i).cloned(),
            Self::Const(l) => l.get(i).map(Value::from_const),
        }
    }
}

impl<'a> Map<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Reflect(m, _) => m.len(),
            Self::Owned(m) => m.len(),
            Self::Const(m) => m.len(),
        }
    }

    /// Visits every entry until `f` returns false.
    pub fn for_each(&self, f: &mut dyn FnMut(Value<'a>, Value<'a>) -> bool) {
        match self {
            Self::Reflect(m, _) => {
                let mut go = true;
                m.for_each(&mut |k, v| {
                    if go {
                        // SAFETY: `ReflectMap::for_each` hands out keys and
                        // values borrowed from the map, which lives for 'a;
                        // its signature only cannot say so.
                        let (k, v): (MapKeyRef<'a>, ValueRef<'a>) =
                            unsafe { std::mem::transmute((k, v)) };
                        go = f(map_key(k), from_ref(v));
                    }
                });
            }
            Self::Owned(m) => {
                for (k, v) in m.iter() {
                    if !f(k.clone(), v.clone()) {
                        break;
                    }
                }
            }
            Self::Const(m) => {
                for (k, v) in &**m {
                    if !f(Value::from_const(k), Value::from_const(v)) {
                        break;
                    }
                }
            }
        }
    }

    pub fn get(&self, key: &Value<'_>) -> Result<Option<Value<'a>>, Error> {
        match self {
            Self::Reflect(m, kt) => {
                let found = match key {
                    Value::String(s) => m.get_str(s),
                    Value::Bool(b) => m.get(&MapKey::Bool(*b)),
                    Value::Int(_) | Value::Uint(_) | Value::Double(_) => {
                        let Some(k) = int_key(key, *kt) else {
                            return Ok(None);
                        };
                        m.get(&k)
                    }
                    _ => return Err(Error::new("unsupported map key type")),
                };
                // SAFETY: as in `for_each`, the value borrows from the map.
                Ok(found.map(|v| {
                    from_ref(unsafe { std::mem::transmute::<ValueRef<'_>, ValueRef<'a>>(v) })
                }))
            }
            Self::Owned(_) | Self::Const(_) => {
                let mut out = None;
                self.for_each(&mut |k, v| {
                    if equals(&k, key) {
                        out = Some(v);
                        false
                    } else {
                        true
                    }
                });
                Ok(out)
            }
        }
    }
}

fn int_key(key: &Value<'_>, kt: ScalarType) -> Option<MapKey> {
    let (i, u) = match *key {
        Value::Int(i) => (Some(i), u64::try_from(i).ok()),
        Value::Uint(u) => (i64::try_from(u).ok(), Some(u)),
        Value::Double(d) if d.fract() == 0.0 => {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "integral and range-checked"
            )]
            let i = (-9.223_372_036_854_776e18..9.223_372_036_854_776e18)
                .contains(&d)
                .then_some(d as i64);
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "integral and range-checked"
            )]
            let u = (0.0..1.844_674_407_370_955_2e19)
                .contains(&d)
                .then_some(d as u64);
            (i, u)
        }
        _ => return None,
    };
    Some(match kt {
        ScalarType::Int32 | ScalarType::Sint32 | ScalarType::Sfixed32 => {
            MapKey::I32(i32::try_from(i?).ok()?)
        }
        ScalarType::Int64 | ScalarType::Sint64 | ScalarType::Sfixed64 => MapKey::I64(i?),
        ScalarType::Uint32 | ScalarType::Fixed32 => MapKey::U32(u32::try_from(u?).ok()?),
        ScalarType::Uint64 | ScalarType::Fixed64 => MapKey::U64(u?),
        _ => return None,
    })
}

pub fn map_key(k: MapKeyRef<'_>) -> Value<'_> {
    match k {
        MapKeyRef::Bool(b) => Value::Bool(b),
        MapKeyRef::I32(i) => Value::Int(i64::from(i)),
        MapKeyRef::I64(i) => Value::Int(i),
        MapKeyRef::U32(u) => Value::Uint(u64::from(u)),
        MapKeyRef::U64(u) => Value::Uint(u),
        MapKeyRef::String(s) => Value::String(Str::Ref(s)),
    }
}

impl<'a> Value<'a> {
    pub fn from_const(c: &'a Const) -> Self {
        match c {
            Const::Null => Self::Null,
            Const::Bool(b) => Self::Bool(*b),
            Const::Int(i) => Self::Int(*i),
            Const::Uint(u) => Self::Uint(*u),
            Const::Double(d) => Self::Double(*d),
            Const::String(s) => Self::String(Str::Ref(s)),
            Const::Bytes(b) => Self::Bytes(Bin::Ref(b)),
            Const::Duration(d) => Self::Duration(*d),
            Const::Timestamp(t) => Self::Timestamp(*t),
            Const::Message(m) => Self::Message(Msg::Ref(&**m)),
            Const::List(l) => Self::List(List::Const(l)),
            Const::Map(m) => Self::Map(Map::Const(m)),
            Const::Type(t) => Self::Type(*t),
        }
    }

    pub fn to_const(&self) -> Const {
        match self {
            Self::Null => Const::Null,
            Self::Bool(b) => Const::Bool(*b),
            Self::Int(i) => Const::Int(*i),
            Self::Uint(u) => Const::Uint(*u),
            Self::Double(d) => Const::Double(*d),
            Self::String(s) => Const::String((**s).into()),
            Self::Bytes(b) => Const::Bytes((**b).into()),
            Self::Duration(d) => Const::Duration(*d),
            Self::Timestamp(t) => Const::Timestamp(*t),
            Self::Message(m) => Const::Message(Arc::new(m.to_dynamic())),
            Self::List(l) => Const::List(
                (0..l.len())
                    .map(|i| l.get(i).map_or(Const::Null, |v| v.to_const()))
                    .collect(),
            ),
            Self::Map(m) => {
                let mut entries = Vec::with_capacity(m.len());
                m.for_each(&mut |k, v| {
                    entries.push((k.to_const(), v.to_const()));
                    true
                });
                Const::Map(entries.into())
            }
            Self::Type(t) => Const::Type(*t),
        }
    }

    pub const fn type_of(&self) -> Type {
        match self {
            Self::Null => Type::Null,
            Self::Bool(_) => Type::Bool,
            Self::Int(_) => Type::Int,
            Self::Uint(_) => Type::Uint,
            Self::Double(_) => Type::Double,
            Self::String(_) => Type::String,
            Self::Bytes(_) => Type::Bytes,
            Self::Duration(_) => Type::Duration,
            Self::Timestamp(_) => Type::Timestamp,
            Self::Message(_) => Type::Message,
            Self::List(_) => Type::List,
            Self::Map(_) => Type::Map,
            Self::Type(_) => Type::Type,
        }
    }

    pub fn str(s: String) -> Self {
        Self::String(Str::Rc(s.into()))
    }
}

/// CEL's heterogeneous equality: values of different types are unequal,
/// except numbers, which compare by value.
#[expect(clippy::many_single_char_names, reason = "pairs of operands")]
pub fn equals(a: &Value<'_>, b: &Value<'_>) -> bool {
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(x), Value::Bool(y)) => x == y,
        (Value::String(x), Value::String(y)) => **x == **y,
        (Value::Bytes(x), Value::Bytes(y)) => **x == **y,
        (Value::Duration(x), Value::Duration(y)) => x == y,
        (Value::Timestamp(x), Value::Timestamp(y)) => x == y,
        (Value::Type(x), Value::Type(y)) => x == y,
        (Value::List(x), Value::List(y)) => {
            x.len() == y.len()
                && (0..x.len()).all(|i| match (x.get(i), y.get(i)) {
                    (Some(p), Some(q)) => equals(&p, &q),
                    _ => false,
                })
        }
        (Value::Map(x), Value::Map(y)) => {
            if x.len() != y.len() {
                return false;
            }
            let mut eq = true;
            x.for_each(&mut |k, v| {
                eq = matches!(y.get(&k), Ok(Some(w)) if equals(&v, &w));
                eq
            });
            eq
        }
        (Value::Message(x), Value::Message(y)) => {
            x.same_type(y) && x.to_dynamic() == y.to_dynamic()
        }
        _ => compare_numbers(a, b) == Some(Ordering::Equal),
    }
}

/// Orders two numbers of any numeric types by value.
pub fn compare_numbers(a: &Value<'_>, b: &Value<'_>) -> Option<Ordering> {
    match (a, b) {
        (&Value::Int(x), &Value::Int(y)) => Some(x.cmp(&y)),
        (&Value::Uint(x), &Value::Uint(y)) => Some(x.cmp(&y)),
        (&Value::Double(x), &Value::Double(y)) => x.partial_cmp(&y),
        (&Value::Int(x), &Value::Uint(y)) => Some(i128::from(x).cmp(&i128::from(y))),
        (&Value::Uint(x), &Value::Int(y)) => Some(i128::from(x).cmp(&i128::from(y))),
        (&Value::Int(x), &Value::Double(y)) => compare_int_double(i128::from(x), y),
        (&Value::Uint(x), &Value::Double(y)) => compare_int_double(i128::from(x), y),
        (&Value::Double(x), &Value::Int(y)) => {
            compare_int_double(i128::from(y), x).map(Ordering::reverse)
        }
        (&Value::Double(x), &Value::Uint(y)) => {
            compare_int_double(i128::from(y), x).map(Ordering::reverse)
        }
        _ => None,
    }
}

fn compare_int_double(i: i128, d: f64) -> Option<Ordering> {
    if d.is_nan() {
        return None;
    }
    if d >= 1.9e19 {
        return Some(Ordering::Less);
    }
    if d <= -1.9e19 {
        return Some(Ordering::Greater);
    }
    let floor = d.floor();
    #[expect(clippy::cast_possible_truncation, reason = "in range")]
    let whole = floor as i128;
    match i.cmp(&whole) {
        Ordering::Equal if d > floor => Some(Ordering::Less),
        Ordering::Equal => Some(Ordering::Equal),
        o => Some(o),
    }
}

/// CEL ordering, for `<`, `<=`, `>` and `>=`.
pub fn compare(a: &Value<'_>, b: &Value<'_>) -> Result<Option<Ordering>, Error> {
    Ok(match (a, b) {
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        (Value::String(x), Value::String(y)) => Some((**x).cmp(&**y)),
        (Value::Bytes(x), Value::Bytes(y)) => Some((**x).cmp(&**y)),
        (Value::Duration(x), Value::Duration(y)) => Some(x.cmp(y)),
        (Value::Timestamp(x), Value::Timestamp(y)) => Some(x.cmp(y)),
        (
            Value::Int(_) | Value::Uint(_) | Value::Double(_),
            Value::Int(_) | Value::Uint(_) | Value::Double(_),
        ) => compare_numbers(a, b),
        _ => {
            return Err(Error::no_overload("_<_", &[a.type_of(), b.type_of()]));
        }
    })
}

impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Uint(u) => write!(f, "{u}u"),
            Self::Double(d) => write!(f, "{d:?}"),
            Self::String(s) => write!(f, "{:?}", &**s),
            Self::Bytes(b) => write!(f, "b{:?}", &**b),
            Self::Duration(d) => write!(f, "duration({d})"),
            Self::Timestamp(t) => write!(f, "timestamp({t})"),
            Self::Message(m) => write!(f, "{}{{..}}", m.descriptor().full_name()),
            Self::List(l) => f
                .debug_list()
                .entries((0..l.len()).filter_map(|i| l.get(i)))
                .finish(),
            Self::Map(m) => {
                let mut d = f.debug_map();
                m.for_each(&mut |k, v| {
                    d.entry(&k, &v);
                    true
                });
                d.finish()
            }
            Self::Type(t) => f.write_str(t.name()),
        }
    }
}
