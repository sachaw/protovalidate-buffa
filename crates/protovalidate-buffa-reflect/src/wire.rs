//! Reading a message's fields straight from its encoding.
//!
//! The rules here are the parser's: a field may appear any number of times
//! and in any order; the last occurrence of a scalar wins, occurrences of a
//! message merge, setting a oneof member clears the others, an occurrence
//! whose wire type does not fit the field is an unknown field, and so is an
//! unknown value of a closed enum. Reading a field applies them, so a value
//! read here is the value a decoder would produce.

use std::{ops::Range, sync::Arc};

use buffa::editions::{EnumType, FieldPresence};
use buffa_descriptor::{
    DescriptorPool, EnumIndex, FieldDescriptor, FieldKind, MessageDescriptor, MessageIndex,
    ScalarType, SingularKind,
};

/// Nesting deeper than this is refused, as the decoder refuses it.
pub const DEPTH: u32 = 100;

/// The encoding is not a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed;

/// One occurrence's value, as the wire carries it.
#[derive(Clone, Copy)]
pub enum Raw<'a> {
    Varint(u64),
    I64(u64),
    I32(u32),
    Len(&'a [u8]),
    /// A group's contents, between its start and end tags.
    Group(&'a [u8]),
}

#[inline(always)]
fn varint(buf: &mut &[u8]) -> Result<u64, Malformed> {
    if let Some((&b, rest)) = buf.split_first()
        && b < 0x80
    {
        *buf = rest;
        return Ok(u64::from(b));
    }
    long_varint(buf)
}

#[inline(never)]
fn long_varint(buf: &mut &[u8]) -> Result<u64, Malformed> {
    let mut v = 0u64;
    for (i, &b) in buf.iter().take(10).enumerate() {
        v |= u64::from(b & 0x7f) << (7 * i);
        if b < 0x80 {
            *buf = &buf[i + 1..];
            return Ok(v);
        }
    }
    Err(Malformed)
}

fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], Malformed> {
    if buf.len() < n {
        return Err(Malformed);
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Ok(head)
}

/// Reads one field: its number and value. A group is read to its end tag.
// Inlined into each loop, so the field is not returned through memory.
#[inline(always)]
fn field<'a>(buf: &mut &'a [u8], depth: u32) -> Result<(u32, Raw<'a>), Malformed> {
    let tag = varint(buf)?;
    let number = u32::try_from(tag >> 3).map_err(|_| Malformed)?;
    if number == 0 {
        return Err(Malformed);
    }
    let raw = match tag & 7 {
        0 => Raw::Varint(varint(buf)?),
        1 => Raw::I64(u64::from_le_bytes(
            take(buf, 8)?.try_into().map_err(|_| Malformed)?,
        )),
        2 => {
            let n = usize::try_from(varint(buf)?).map_err(|_| Malformed)?;
            Raw::Len(take(buf, n)?)
        }
        3 => Raw::Group(group(buf, number, depth)?),
        5 => Raw::I32(u32::from_le_bytes(
            take(buf, 4)?.try_into().map_err(|_| Malformed)?,
        )),
        _ => return Err(Malformed),
    };
    Ok((number, raw))
}

fn group<'a>(buf: &mut &'a [u8], number: u32, depth: u32) -> Result<&'a [u8], Malformed> {
    if depth >= DEPTH {
        return Err(Malformed);
    }
    let start = *buf;
    loop {
        let before = *buf;
        let tag = varint(&mut { before })?;
        if tag & 7 == 4 {
            varint(buf)?;
            if tag >> 3 != u64::from(number) {
                return Err(Malformed);
            }
            let len = start.len() - before.len();
            return Ok(&start[..len]);
        }
        field(buf, depth + 1)?;
    }
}

impl Raw<'_> {
    /// The wire type, as a bit of [`Shape::wires`].
    #[inline]
    pub const fn wire(&self) -> u8 {
        1 << match self {
            Self::Varint(_) => 0,
            Self::I64(_) => 1,
            Self::Len(_) => 2,
            Self::Group(_) => 3,
            Self::I32(_) => 5,
        }
    }
}

/// The encoding of one message: a slice, or the occurrences of a message
/// field, which merge as their concatenation does.
#[derive(Clone)]
pub enum Src<'a> {
    Bytes(&'a [u8]),
    Merged(Arc<Merged<'a>>),
}

pub struct Merged<'a> {
    parent: Src<'a>,
    number: u32,
    /// Occurrences before a sibling oneof member cleared the field.
    skip: u32,
}

impl<'a> Src<'a> {
    pub const EMPTY: Self = Self::Bytes(&[]);

    /// Visits every field, in order.
    #[inline]
    pub fn visit<E: From<Malformed>>(
        &self,
        f: &mut impl FnMut(u32, Raw<'a>) -> Result<(), E>,
    ) -> Result<(), E> {
        self.visit_at(&mut |n, raw, _| f(n, raw))
    }

    /// [`visit`](Self::visit), with where each field sits in the
    /// [`base`](Self::base) bytes.
    #[inline]
    pub fn visit_at<E: From<Malformed>>(
        &self,
        f: &mut impl FnMut(u32, Raw<'a>, Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        match self {
            Self::Bytes(b) => {
                let mut buf = *b;
                while !buf.is_empty() {
                    let start = b.len() - buf.len();
                    let (n, raw) = field(&mut buf, 0)?;
                    f(n, raw, start..b.len() - buf.len())?;
                }
                Ok(())
            }
            Self::Merged(m) => m.visit_at(f),
        }
    }

    /// The bytes every field of the message is part of.
    pub fn base(&self) -> &'a [u8] {
        match self {
            Self::Bytes(b) => b,
            Self::Merged(m) => m.parent.base(),
        }
    }

    /// The part of the message from `span`'s start to its end, which holds
    /// every occurrence of a field when `span` covers its first and last.
    pub fn within(&self, span: (u32, u32)) -> Self {
        match self {
            Self::Bytes(b) => Self::Bytes(b.get(span.0 as usize..span.1 as usize).unwrap_or(b)),
            Self::Merged(_) => self.clone(),
        }
    }

    /// The bytes of the message, copied out when it is merged.
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Self::Bytes(b) => b.to_vec(),
            Self::Merged(m) => {
                let mut out = Vec::new();
                let _ = m.chunks(&mut |c| {
                    out.extend_from_slice(c);
                    Ok::<(), Malformed>(())
                });
                out
            }
        }
    }
}

impl<'a> Merged<'a> {
    fn chunks<E: From<Malformed>>(
        &self,
        f: &mut dyn FnMut(&'a [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut seen = 0;
        self.parent.visit(&mut |n, raw| {
            if n != self.number {
                return Ok(());
            }
            let (Raw::Len(chunk) | Raw::Group(chunk)) = raw else {
                return Ok(());
            };
            seen += 1;
            if seen > self.skip { f(chunk) } else { Ok(()) }
        })
    }

    fn visit_at<E: From<Malformed>>(
        &self,
        f: &mut dyn FnMut(u32, Raw<'a>, Range<usize>) -> Result<(), E>,
    ) -> Result<(), E> {
        let mut seen = 0;
        self.parent.visit_at(&mut |n, raw, at| {
            if n != self.number {
                return Ok(());
            }
            let Some(chunk) = payload(raw, &at, n) else {
                return Ok(());
            };
            seen += 1;
            if seen <= self.skip {
                return Ok(());
            }
            let (Raw::Len(bytes) | Raw::Group(bytes)) = raw else {
                return Ok(());
            };
            Src::Bytes(bytes).visit_at(&mut |n, raw, inner| {
                f(n, raw, chunk.start + inner.start..chunk.start + inner.end)
            })
        })
    }
}

/// What a field holds, for reading it.
#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Scalar(ScalarType),
    /// An enum; closed ones drop values they do not declare.
    Enum(Option<EnumIndex>),
    Message(MessageIndex),
}

impl Kind {
    pub fn of(kind: SingularKind, fd: Option<&FieldDescriptor>, pool: &DescriptorPool) -> Self {
        match kind {
            SingularKind::Scalar(s) => Self::Scalar(s),
            SingularKind::Message(m) => Self::Message(m),
            SingularKind::Enum(e) => {
                let ty = fd
                    .and_then(FieldDescriptor::enum_type)
                    .unwrap_or_else(|| pool.enumeration(e).enum_type());
                Self::Enum((ty == EnumType::Closed).then_some(e))
            }
        }
    }

    /// Whether an occurrence is this kind's value, rather than an unknown
    /// field.
    #[inline]
    pub fn accepts(self, raw: Raw<'_>, pool: &DescriptorPool) -> bool {
        match (self, raw) {
            (Self::Message(_), Raw::Len(_) | Raw::Group(_)) => true,
            (Self::Enum(None), Raw::Varint(_)) => true,
            (Self::Enum(Some(e)), Raw::Varint(v)) => known(pool, e, v),
            (Self::Scalar(s), raw) => matches!(
                (wire(s), raw),
                (0, Raw::Varint(_)) | (1, Raw::I64(_)) | (2, Raw::Len(_)) | (5, Raw::I32(_))
            ),
            _ => false,
        }
    }

    pub const fn packable(self) -> bool {
        !matches!(
            self,
            Self::Message(_) | Self::Scalar(ScalarType::String | ScalarType::Bytes)
        )
    }
}

#[expect(clippy::cast_possible_truncation, reason = "an enum is an int32")]
fn known(pool: &DescriptorPool, e: EnumIndex, v: u64) -> bool {
    pool.enumeration(e).value(v as i32).is_some()
}

const fn wire(s: ScalarType) -> u8 {
    match s {
        ScalarType::Double | ScalarType::Fixed64 | ScalarType::Sfixed64 => 1,
        ScalarType::String | ScalarType::Bytes => 2,
        ScalarType::Float | ScalarType::Fixed32 | ScalarType::Sfixed32 => 5,
        _ => 0,
    }
}

/// A field, as reading it needs: its number, kind, cardinality and presence,
/// and the other members of its oneof.
#[derive(Clone, Debug)]
pub struct Shape {
    pub number: u32,
    pub kind: Kind,
    pub card: Card,
    /// Unset reads as absent, not as a zero that was set: explicit presence.
    pub explicit: bool,
    pub siblings: Box<[(u32, Kind)]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Card {
    Singular,
    List,
    /// A map, with its key's scalar type.
    Map(ScalarType),
}

impl Shape {
    pub fn of(md: &MessageDescriptor, fd: &FieldDescriptor, pool: &DescriptorPool) -> Self {
        let (kind, card) = match fd.kind() {
            FieldKind::Singular(k) => (Kind::of(k, Some(fd), pool), Card::Singular),
            FieldKind::List(k) => (Kind::of(k, Some(fd), pool), Card::List),
            FieldKind::Map { key, value } => (Kind::of(value, Some(fd), pool), Card::Map(key)),
        };
        let siblings = fd
            .oneof_index()
            .map(|o| {
                md.oneofs()[usize::from(o)]
                    .field_indices()
                    .iter()
                    .map(|&i| &md.fields()[usize::from(i)])
                    .filter(|f| f.number() != fd.number())
                    .filter_map(|f| match f.kind() {
                        FieldKind::Singular(k) => Some((f.number(), Kind::of(k, Some(f), pool))),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            number: fd.number(),
            kind,
            card,
            explicit: fd.presence() != FieldPresence::Implicit
                || fd.oneof_index().is_some()
                || matches!(kind, Kind::Message(_)) && card == Card::Singular,
            siblings,
        }
    }

    /// Whether an occurrence is one of this field's, rather than an unknown
    /// field.
    #[inline]
    pub fn accepts(&self, raw: Raw<'_>, pool: &DescriptorPool) -> bool {
        match self.card {
            Card::Singular => self.kind.accepts(raw, pool),
            Card::List => {
                matches!(raw, Raw::Len(_)) && self.kind.packable() || self.kind.accepts(raw, pool)
            }
            Card::Map(_) => matches!(raw, Raw::Len(_)),
        }
    }

    /// The wire types an occurrence of the field may have, a bit each as
    /// [`Raw::wire`] gives them.
    pub const fn wires(&self) -> u8 {
        let element = match self.kind {
            Kind::Message(_) => 1 << 2 | 1 << 3,
            Kind::Enum(_) => 1,
            Kind::Scalar(s) => 1 << wire(s),
        };
        match self.card {
            Card::Singular => element,
            Card::List if self.kind.packable() => element | 1 << 2,
            Card::List => element,
            Card::Map(_) => 1 << 2,
        }
    }

    /// A map entry's key or value.
    pub fn entry(number: u32, kind: Kind) -> Self {
        Self {
            number,
            kind,
            card: Card::Singular,
            explicit: false,
            siblings: Box::new([]),
        }
    }
}

/// Where a length-delimited or group occurrence's contents sit, given where
/// the whole field does.
#[inline]
fn payload(raw: Raw<'_>, at: &Range<usize>, number: u32) -> Option<Range<usize>> {
    match raw {
        Raw::Len(b) => Some(at.end - b.len()..at.end),
        Raw::Group(b) => {
            let end = at.end - varint_len(u64::from(number) << 3);
            Some(end - b.len()..end)
        }
        _ => None,
    }
}

const fn varint_len(v: u64) -> usize {
    (64 - (v | 1).leading_zeros() as usize).div_ceil(7)
}

/// An occurrence's value, without the bytes it borrows: a length-delimited
/// one is an offset and a length into its message's [`Src::base`].
#[derive(Clone, Copy, Debug)]
pub enum At {
    Varint(u64),
    I64(u64),
    I32(u32),
    Len(u32, u32),
    Group(u32, u32),
}

impl At {
    #[inline]
    fn of(raw: Raw<'_>, at: &Range<usize>, number: u32) -> Self {
        let span = |r: Range<usize>| {
            (
                u32::try_from(r.start).unwrap_or(u32::MAX),
                u32::try_from(r.len()).unwrap_or(0),
            )
        };
        match raw {
            Raw::Varint(v) => Self::Varint(v),
            Raw::I64(v) => Self::I64(v),
            Raw::I32(v) => Self::I32(v),
            Raw::Len(_) => {
                let (s, l) = span(payload(raw, at, number).unwrap_or(0..0));
                Self::Len(s, l)
            }
            Raw::Group(_) => {
                let (s, l) = span(payload(raw, at, number).unwrap_or(0..0));
                Self::Group(s, l)
            }
        }
    }

    #[inline]
    pub fn raw(self, base: &[u8]) -> Raw<'_> {
        let slice = |s: u32, l: u32| base.get(s as usize..(s + l) as usize).unwrap_or(&[]);
        match self {
            Self::Varint(v) => Raw::Varint(v),
            Self::I64(v) => Raw::I64(v),
            Self::I32(v) => Raw::I32(v),
            Self::Len(s, l) => Raw::Len(slice(s, l)),
            Self::Group(s, l) => Raw::Group(slice(s, l)),
        }
    }
}

/// A field's occurrences that count: the last one, how many there are since
/// a sibling last cleared the field, and where they sit in their message's
/// [`Src::base`].
#[derive(Clone, Copy, Debug)]
pub struct Found {
    pub last: Option<At>,
    pub count: u32,
    pub total: u32,
    /// From the first occurrence's start to the last one's end.
    pub span: (u32, u32),
}

impl Default for Found {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl Found {
    pub const EMPTY: Self = Self {
        last: None,
        count: 0,
        total: 0,
        span: (0, 0),
    };

    /// Takes the occurrence of field `number` found at `at`.
    #[inline(always)]
    pub fn take(&mut self, raw: Raw<'_>, at: Range<usize>, number: u32) {
        let (start, end) = (
            u32::try_from(at.start).unwrap_or(u32::MAX),
            u32::try_from(at.end).unwrap_or(u32::MAX),
        );
        if self.count == 0 {
            self.span.0 = start;
        }
        self.span.1 = end;
        self.last = Some(At::of(raw, &at, number));
        self.count += 1;
        self.total += 1;
    }

    /// A sibling oneof member was set.
    #[inline]
    pub fn clear(&mut self) {
        self.last = None;
        self.count = 0;
    }

    /// The last occurrence, from the message it was found in.
    #[inline]
    pub fn last<'a>(&self, src: &Src<'a>) -> Option<Raw<'a>> {
        self.last.map(|at| at.raw(src.base()))
    }

    /// The field's message, merged from its occurrences.
    pub fn message<'a>(&self, parent: &Src<'a>, number: u32) -> Src<'a> {
        match self.last(parent) {
            Some(Raw::Len(b) | Raw::Group(b)) if self.count == 1 => Src::Bytes(b),
            Some(_) => Src::Merged(Arc::new(Merged {
                parent: parent.clone(),
                number,
                skip: self.total - self.count,
            })),
            None => Src::EMPTY,
        }
    }
}

/// Reads a singular field.
pub fn singular(src: &Src<'_>, shape: &Shape, pool: &DescriptorPool) -> Result<Found, Malformed> {
    let mut found = Found::EMPTY;
    src.visit_at(&mut |n, raw, at| {
        if n == shape.number {
            if shape.kind.accepts(raw, pool) {
                found.take(raw, at, n);
            }
        } else if let Some((_, k)) = shape.siblings.iter().find(|(s, _)| *s == n)
            && k.accepts(raw, pool)
        {
            found.clear();
        }
        Ok::<(), Malformed>(())
    })?;
    Ok(found)
}

/// Visits a repeated field's elements, packed or not, until `f` returns
/// false.
pub fn elements<'a>(
    src: &Src<'a>,
    number: u32,
    kind: Kind,
    pool: &DescriptorPool,
    f: &mut dyn FnMut(Raw<'a>) -> bool,
) -> Result<(), Malformed> {
    #[derive(Debug)]
    enum Stop {
        Done,
        Malformed,
    }
    impl From<Malformed> for Stop {
        fn from(_: Malformed) -> Self {
            Self::Malformed
        }
    }
    let result = src.visit(&mut |n, raw| {
        if n != number {
            return Ok(());
        }
        match raw {
            Raw::Len(mut packed) if kind.packable() => {
                let Kind::Scalar(s) = kind else {
                    return each_packed(&mut packed, 0, kind, pool, f);
                };
                each_packed(&mut packed, wire(s), kind, pool, f)
            }
            raw if kind.accepts(raw, pool) => {
                if f(raw) {
                    Ok(())
                } else {
                    Err(Stop::Done)
                }
            }
            _ => Ok(()),
        }
    });
    fn each_packed<'a>(
        packed: &mut &'a [u8],
        wire: u8,
        kind: Kind,
        pool: &DescriptorPool,
        f: &mut dyn FnMut(Raw<'a>) -> bool,
    ) -> Result<(), Stop> {
        while !packed.is_empty() {
            let raw = match wire {
                1 => Raw::I64(u64::from_le_bytes(
                    take(packed, 8)?.try_into().map_err(|_| Malformed)?,
                )),
                5 => Raw::I32(u32::from_le_bytes(
                    take(packed, 4)?.try_into().map_err(|_| Malformed)?,
                )),
                _ => Raw::Varint(varint(packed)?),
            };
            if kind.accepts(raw, pool) && !f(raw) {
                return Err(Stop::Done);
            }
        }
        Ok(())
    }
    match result {
        Ok(()) | Err(Stop::Done) => Ok(()),
        Err(Stop::Malformed) => Err(Malformed),
    }
}

/// A map entry: its key and value as the decoder reads them.
pub struct Entry<'a> {
    pub key: Option<Raw<'a>>,
    pub value: Found,
    pub src: Src<'a>,
}

/// Visits a map's entries in order, duplicates included, until `f` returns
/// false.
pub fn entries<'a>(
    src: &Src<'a>,
    number: u32,
    key: ScalarType,
    value: Kind,
    pool: &DescriptorPool,
    f: &mut dyn FnMut(Entry<'a>) -> bool,
) -> Result<(), Malformed> {
    let key = Kind::Scalar(key);
    let mut stop = false;
    src.visit(&mut |n, raw| {
        let (true, false, Raw::Len(entry)) = (n == number, stop, raw) else {
            return Ok(());
        };
        let src = Src::Bytes(entry);
        let mut k = None;
        let mut v = Found::EMPTY;
        // A closed enum value the enum does not declare drops the entry.
        let mut dropped = false;
        src.visit_at(&mut |n, raw, at| {
            match n {
                1 if key.accepts(raw, pool) => k = Some(raw),
                2 => match value {
                    Kind::Enum(Some(_)) if matches!(raw, Raw::Varint(_)) => {
                        dropped = !value.accepts(raw, pool);
                        if !dropped {
                            v.take(raw, at, n);
                        }
                    }
                    _ if value.accepts(raw, pool) => v.take(raw, at, n),
                    _ => {}
                },
                _ => {}
            }
            Ok::<(), Malformed>(())
        })?;
        if !dropped {
            stop = !f(Entry {
                key: k,
                value: v,
                src,
            });
        }
        Ok::<(), Malformed>(())
    })
}
