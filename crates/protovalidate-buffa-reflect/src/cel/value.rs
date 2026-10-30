//! CEL values over encoded messages.
//!
//! A [`Value`] borrows from the encoding being validated, or from a rule's
//! constants, so reading a field, a string or a list costs no allocation.
//! Values an expression builds (concatenations, `map()` results) are
//! reference counted.

use std::{cmp::Ordering, fmt, rc::Rc, sync::Arc};

use buffa_descriptor::{
    DescriptorPool, FieldDescriptor, MessageDescriptor, MessageIndex, ScalarType,
    reflect::DynamicMessage,
};
use chrono::{DateTime, TimeDelta, Utc};

use super::Error;
use crate::{
    plan::Dispatch,
    wire::{self, Card, Found, Kind, Raw, Shape, Src},
};

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

/// A message: its encoding and its type.
#[derive(Clone)]
pub struct Msg<'a> {
    pub src: Src<'a>,
    pub index: MessageIndex,
    pub pool: &'a Arc<DescriptorPool>,
    /// Fields already found in the encoding, read without another pass.
    pub gathered: Option<&'a Gathered<'a>>,
}

/// The fields a walk found in one pass over a message, by slot.
pub struct Gathered<'a> {
    pub dispatch: &'a Dispatch,
    pub found: &'a [Found<'a>],
}

/// A list.
#[derive(Clone)]
pub enum List<'a> {
    /// A repeated field, read from its message's encoding.
    Field(Field<'a>),
    Owned(Rc<[Value<'a>]>),
    Const(&'a [Const]),
}

/// A map.
#[derive(Clone)]
pub enum Map<'a> {
    /// A map field, read from its message's encoding.
    Field(Field<'a>),
    Owned(Rc<[(Value<'a>, Value<'a>)]>),
    Const(&'a [(Const, Const)]),
}

/// A repeated or map field of an encoded message.
#[derive(Clone)]
pub struct Field<'a> {
    src: Src<'a>,
    number: u32,
    /// The kind of the items, or of the map's values.
    kind: Kind,
    card: Card,
    wkt: Option<Wkt>,
    pool: &'a Arc<DescriptorPool>,
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
    Message(Arc<ConstMsg>),
    List(Box<[Self]>),
    Map(Box<[(Self, Self)]>),
    Type(Type),
}

/// An encoded message kept in a plan.
#[derive(Debug)]
pub struct ConstMsg {
    pub bytes: Box<[u8]>,
    pub index: MessageIndex,
    pub pool: Arc<DescriptorPool>,
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

/// How to read a field, worked out from its descriptor once.
#[derive(Clone, Debug)]
pub struct Read {
    pub shape: Shape,
    /// The well-known type of a message field or its elements.
    pub wkt: Option<Wkt>,
}

impl Read {
    pub fn of(md: &MessageDescriptor, fd: &FieldDescriptor, pool: &DescriptorPool) -> Self {
        let shape = Shape::of(md, fd, pool);
        let wkt = match shape.kind {
            Kind::Message(m) => wkt(pool.message(m)),
            _ => None,
        };
        Self { shape, wkt }
    }
}

impl<'a> Msg<'a> {
    pub const fn new(src: Src<'a>, index: MessageIndex, pool: &'a Arc<DescriptorPool>) -> Self {
        Self {
            src,
            index,
            pool,
            gathered: None,
        }
    }

    fn gathered(&self, number: u32) -> Option<&'a Found<'a>> {
        let g = self.gathered?;
        g.dispatch.get(number).map(|s| &g.found[s])
    }

    pub fn descriptor(&self) -> &'a MessageDescriptor {
        self.pool.message(self.index)
    }

    /// Whether a field is set, as `has()` asks.
    pub fn has(&self, fd: &FieldDescriptor) -> bool {
        let read = Read::of(self.descriptor(), fd, self.pool);
        self.has_read(&read)
    }

    pub fn has_read(&self, read: &Read) -> bool {
        if let Some(found) = self.gathered(read.shape.number) {
            return present(found, read, &self.src, self.pool);
        }
        scan_has(&self.src, read, self.pool)
    }

    /// The field with the given index in the message's descriptor, read as
    /// CEL reads it: unset fields as their defaults, well-known types as
    /// their CEL values.
    pub fn field(&self, index: usize) -> Value<'a> {
        let md = self.descriptor();
        self.read(&Read::of(md, &md.fields()[index], self.pool))
    }

    /// Reads a field whose [`Read`] was worked out when compiling.
    pub fn read(&self, read: &Read) -> Value<'a> {
        let shape = &read.shape;
        let gathered = self.gathered(shape.number);
        if shape.card == Card::Singular {
            return match gathered {
                Some(found) => singular(found, &self.src, read, self.pool),
                None => {
                    let found = wire::singular(&self.src, shape, self.pool).unwrap_or_default();
                    singular(&found, &self.src, read, self.pool)
                }
            };
        }
        let field = Field {
            src: gathered.map_or_else(|| self.src.clone(), |f| self.src.within(&f.span)),
            number: shape.number,
            kind: shape.kind,
            card: shape.card,
            wkt: read.wkt,
            pool: self.pool,
        };
        match shape.card {
            Card::List => Value::List(List::Field(field)),
            _ => Value::Map(Map::Field(field)),
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

    fn same_type(&self, other: &Self) -> bool {
        self.descriptor().full_name() == other.descriptor().full_name()
    }

    /// The message decoded, for comparing messages.
    pub fn to_dynamic(&self) -> DynamicMessage {
        DynamicMessage::decode(Arc::clone(self.pool), self.index, &self.src.to_vec())
            .unwrap_or_else(|_| DynamicMessage::new(Arc::clone(self.pool), self.index))
    }
}

/// Whether a field is set, found by a pass over the message.
fn scan_has(src: &Src<'_>, read: &Read, pool: &Arc<DescriptorPool>) -> bool {
    let shape = &read.shape;
    match shape.card {
        Card::Singular => {
            wire::singular(src, shape, pool).is_ok_and(|found| present(&found, read, src, pool))
        }

        Card::List => {
            let mut any = false;
            let _ = wire::elements(src, shape.number, shape.kind, pool, &mut |_| {
                any = true;
                false
            });
            any
        }
        Card::Map(key) => {
            let mut any = false;
            let _ = wire::entries(src, shape.number, key, shape.kind, pool, &mut |_| {
                any = true;
                false
            });
            any
        }
    }
}

/// Whether a field is set: present on the wire, and, without explicit
/// presence, set to other than its zero value; a list or map, not empty.
pub fn present(found: &Found<'_>, read: &Read, src: &Src<'_>, pool: &Arc<DescriptorPool>) -> bool {
    match (read.shape.card, found.last) {
        (_, None) => false,
        (Card::Singular, Some(_)) if read.shape.explicit => true,
        // A closed enum drops the values it does not declare, which may be
        // all of them.
        (Card::List | Card::Map(_), Some(_)) => {
            !matches!(read.shape.kind, Kind::Enum(Some(_)))
                || scan_has(&src.within(&found.span), read, pool)
        }
        (Card::Singular, Some(raw)) => match read.shape.kind {
            Kind::Scalar(s) => !is_zero_scalar(&scalar(raw, s)),
            Kind::Enum(_) => !is_zero_scalar(&scalar(raw, ScalarType::Int32)),
            Kind::Message(_) => true,
        },
    }
}

fn is_zero_scalar(v: &Value<'_>) -> bool {
    match v {
        Value::Bool(b) => !b,
        Value::Int(i) => *i == 0,
        Value::Uint(u) => *u == 0,
        Value::Double(d) => *d == 0.0,
        Value::String(s) => s.is_empty(),
        Value::Bytes(b) => b.is_empty(),
        _ => false,
    }
}

/// A singular field's value: its last occurrence, its occurrences merged,
/// or its default.
pub fn singular<'a>(
    found: &Found<'a>,
    parent: &Src<'a>,
    read: &Read,
    pool: &'a Arc<DescriptorPool>,
) -> Value<'a> {
    match (read.shape.kind, found.last) {
        (Kind::Message(m), Some(_)) => message_as(
            Msg::new(found.message(parent, read.shape.number), m, pool),
            read.wkt,
        ),
        (Kind::Message(_), None) if matches!(read.wkt, Some(Wkt::Wrapper | Wkt::Value)) => {
            Value::Null
        }
        (Kind::Message(m), None) => message_as(Msg::new(Src::EMPTY, m, pool), read.wkt),
        (kind, Some(raw)) => element(raw, kind, None, pool),
        (Kind::Scalar(s), None) => default_scalar(s),
        (Kind::Enum(_), None) => Value::Int(0),
    }
}

/// One occurrence's value: a scalar, or one message (not merged).
#[expect(clippy::cast_possible_truncation, reason = "the wire's truncations")]
#[expect(clippy::cast_possible_wrap, reason = "the wire's reinterpretations")]
pub fn element<'a>(
    raw: Raw<'a>,
    kind: Kind,
    wkt: Option<Wkt>,
    pool: &'a Arc<DescriptorPool>,
) -> Value<'a> {
    match (kind, raw) {
        (Kind::Scalar(s), raw) => scalar(raw, s),
        (Kind::Enum(_), Raw::Varint(v)) => Value::Int(i64::from(v as i32)),
        (Kind::Message(m), Raw::Len(b) | Raw::Group(b)) => {
            message_as(Msg::new(Src::Bytes(b), m, pool), wkt)
        }
        _ => Value::Null,
    }
}

/// A scalar occurrence's value.
#[expect(clippy::cast_possible_truncation, reason = "the wire's truncations")]
#[expect(clippy::cast_possible_wrap, reason = "the wire's reinterpretations")]
pub fn scalar(raw: Raw<'_>, s: ScalarType) -> Value<'_> {
    match (s, raw) {
        (ScalarType::Int32, Raw::Varint(v)) => Value::Int(i64::from(v as i32)),
        (ScalarType::Int64, Raw::Varint(v)) => Value::Int(v as i64),
        (ScalarType::Uint32, Raw::Varint(v)) => Value::Uint(u64::from(v as u32)),
        (ScalarType::Uint64, Raw::Varint(v)) | (ScalarType::Fixed64, Raw::I64(v)) => Value::Uint(v),
        (ScalarType::Sint32, Raw::Varint(v)) => {
            let v = v as u32;
            Value::Int(i64::from((v >> 1) as i32 ^ -((v & 1) as i32)))
        }
        (ScalarType::Sint64, Raw::Varint(v)) => Value::Int((v >> 1) as i64 ^ -((v & 1) as i64)),
        (ScalarType::Bool, Raw::Varint(v)) => Value::Bool(v != 0),
        (ScalarType::Sfixed64, Raw::I64(v)) => Value::Int(v as i64),
        (ScalarType::Double, Raw::I64(v)) => Value::Double(f64::from_bits(v)),
        (ScalarType::Fixed32, Raw::I32(v)) => Value::Uint(u64::from(v)),
        (ScalarType::Sfixed32, Raw::I32(v)) => Value::Int(i64::from(v as i32)),
        (ScalarType::Float, Raw::I32(v)) => Value::Double(f64::from(f32::from_bits(v))),
        (ScalarType::String, Raw::Len(b)) => match std::str::from_utf8(b) {
            Ok(s) => Value::String(Str::Ref(s)),
            // Not a valid encoding, which decoding rejects; read leniently.
            Err(_) => Value::String(Str::Rc(String::from_utf8_lossy(b).into())),
        },
        (ScalarType::Bytes, Raw::Len(b)) => Value::Bytes(Bin::Ref(b)),
        (s, _) => default_scalar(s),
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

/// A `Timestamp`'s or `Duration`'s fields: `int64 seconds = 1`, `int32 nanos
/// = 2`.
#[expect(clippy::cast_possible_truncation, reason = "the wire's truncations")]
#[expect(clippy::cast_possible_wrap, reason = "the wire's reinterpretations")]
fn seconds_nanos(m: &Msg<'_>) -> Option<(i64, i64)> {
    let (mut s, mut n) = (0, 0);
    m.src
        .visit(&mut |number, raw| {
            match (number, raw) {
                (1, Raw::Varint(v)) => s = v as i64,
                (2, Raw::Varint(v)) => n = i64::from(v as i32),
                _ => {}
            }
            Ok::<(), wire::Malformed>(())
        })
        .ok()?;
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

impl<'a> Field<'a> {
    fn each(&self, f: &mut dyn FnMut(Value<'a>) -> bool) {
        let _ = wire::elements(&self.src, self.number, self.kind, self.pool, &mut |raw| {
            f(element(raw, self.kind, self.wkt, self.pool))
        });
    }

    /// Visits each entry whose key no later entry repeats: the entries a
    /// decoder keeps.
    fn entries(&self, f: &mut dyn FnMut(Value<'a>, Value<'a>) -> bool) {
        const SMALL: usize = 16;
        let Card::Map(key) = self.card else {
            return;
        };
        let key_of = |e: &wire::Entry<'a>| e.key.map_or(default_scalar(key), |k| scalar(k, key));
        let value_read = Read {
            shape: Shape::entry(2, self.kind),
            wkt: self.wkt,
        };
        let value_of = |e: &wire::Entry<'a>| singular(&e.value, &e.src, &value_read, self.pool);
        let (number, kind) = (self.number, self.kind);
        // Few entries are checked for repeated keys pairwise, on the stack.
        let mut small = [const { None }; SMALL];
        let mut n = 0;
        let _ = wire::entries(&self.src, number, key, kind, self.pool, &mut |e| {
            if n < SMALL {
                small[n] = Some((key_of(&e), e));
            }
            n += 1;
            n <= SMALL
        });
        if n <= SMALL {
            let small = &small[..n];
            for (i, (k, e)) in small.iter().flatten().enumerate() {
                if small[i + 1..]
                    .iter()
                    .flatten()
                    .any(|(later, _)| equals(k, later))
                {
                    continue;
                }
                if !f(k.clone(), value_of(e)) {
                    break;
                }
            }
            return;
        }
        let mut all = Vec::with_capacity(n);
        let _ = wire::entries(&self.src, number, key, kind, self.pool, &mut |e| {
            all.push((key_of(&e), value_of(&e)));
            true
        });
        // Stable, so the last of equal keys sorts last.
        all.sort_by(|a, b| {
            compare(&a.0, &b.0)
                .ok()
                .flatten()
                .unwrap_or(Ordering::Equal)
        });
        for (i, (k, v)) in all.iter().enumerate() {
            if all.get(i + 1).is_some_and(|next| equals(k, &next.0)) {
                continue;
            }
            if !f(k.clone(), v.clone()) {
                break;
            }
        }
    }
}

impl<'a> List<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Field(field) => {
                let mut n = 0;
                field.each(&mut |_| {
                    n += 1;
                    true
                });
                n
            }
            Self::Owned(l) => l.len(),
            Self::Const(l) => l.len(),
        }
    }

    pub fn get(&self, i: usize) -> Option<Value<'a>> {
        match self {
            Self::Field(field) => {
                let mut at = 0;
                let mut out = None;
                field.each(&mut |item| {
                    if at == i {
                        out = Some(item);
                        return false;
                    }
                    at += 1;
                    true
                });
                out
            }
            Self::Owned(l) => l.get(i).cloned(),
            Self::Const(l) => l.get(i).map(Value::from_const),
        }
    }

    pub fn items(&self) -> Vec<Value<'a>> {
        let mut out = Vec::new();
        self.for_each(&mut |v| {
            out.push(v);
            true
        });
        out
    }

    /// Visits every item until `f` returns false.
    pub fn for_each(&self, f: &mut dyn FnMut(Value<'a>) -> bool) {
        match self {
            Self::Field(field) => field.each(f),
            Self::Owned(l) => {
                for item in l.iter() {
                    if !f(item.clone()) {
                        break;
                    }
                }
            }
            Self::Const(l) => {
                for item in &**l {
                    if !f(Value::from_const(item)) {
                        break;
                    }
                }
            }
        }
    }
}

impl<'a> Map<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Field(_) => {
                let mut n = 0;
                self.for_each(&mut |_, _| {
                    n += 1;
                    true
                });
                n
            }
            Self::Owned(m) => m.len(),
            Self::Const(m) => m.len(),
        }
    }

    /// Visits every entry until `f` returns false.
    pub fn for_each(&self, f: &mut dyn FnMut(Value<'a>, Value<'a>) -> bool) {
        match self {
            Self::Field(field) => field.entries(f),
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
        if !matches!(
            key,
            Value::String(_) | Value::Bool(_) | Value::Int(_) | Value::Uint(_) | Value::Double(_)
        ) {
            return Err(Error::new("unsupported map key type"));
        }
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
            Const::Message(m) => Self::Message(Msg::new(Src::Bytes(&m.bytes), m.index, &m.pool)),
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
            Self::Message(m) => Const::Message(Arc::new(ConstMsg {
                bytes: m.src.to_vec().into(),
                index: m.index,
                pool: Arc::clone(m.pool),
            })),
            Self::List(l) => {
                let mut items = Vec::new();
                l.for_each(&mut |v| {
                    items.push(v.to_const());
                    true
                });
                Const::List(items.into())
            }
            Self::Map(m) => {
                let mut entries = Vec::new();
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
            let mut ys = Vec::new();
            y.for_each(&mut |v| {
                ys.push(v);
                true
            });
            let mut i = 0;
            let mut eq = true;
            x.for_each(&mut |v| {
                eq = ys.get(i).is_some_and(|w| equals(&v, w));
                i += 1;
                eq
            });
            eq && i == ys.len()
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
            Self::List(l) => {
                let mut d = f.debug_list();
                l.for_each(&mut |v| {
                    d.entry(&v);
                    true
                });
                d.finish()
            }
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
