//! Native checks compiled to closures over typed reads.
//!
//! A predicate whose operands are `this`, paths of singular fields from it
//! or `now`, of types known when compiling, reads its operands straight from
//! the encoding and tests them without building CEL values where it can.
//! Each test is derived from the [`Pred`], and so from the rule's CEL; a
//! value of another type than expected (a `dyn` field) makes it decline, and
//! the predicate runs instead.

use std::cmp::Ordering;

use buffa_descriptor::{MessageIndex, ScalarType};
use chrono::{DateTime, TimeDelta, Utc};
use regex::Regex;
use regex_automata::{
    Input,
    dfa::{
        Automaton,
        dense::{self, DFA},
    },
};

use super::{
    Clock, Ty,
    compile::{Func, Op},
    eval::char_count,
    functions,
    pred::{Base, Conv, Operand, Pred},
    value::{Bin, Const, Msg, Prim, Read, Str, Value, Wkt, equals, utf8},
};
use crate::wire::{Card, Kind};

/// What a test reads: `this` as a scalar read off the wire, or as a CEL
/// value.
#[derive(Clone, Copy)]
pub enum Arg<'v, 'a> {
    Prim(Prim<'a>),
    Value(&'v Value<'a>),
}

/// A compiled test of `this`: `None` when the value is not of the type it
/// was compiled for.
pub type Test = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<bool> + Send + Sync>;

type Get<T> = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<T> + Send + Sync>;
type GetStr = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<Str<'a>> + Send + Sync>;
type GetBytes = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<Bin<'a>> + Send + Sync>;
type GetPrim = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<Prim<'a>> + Send + Sync>;
type GetValue = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<Value<'a>> + Send + Sync>;
type GetMsg = Box<dyn for<'v, 'a> Fn(Arg<'v, 'a>, &Clock) -> Option<Msg<'a>> + Send + Sync>;

/// What an operand holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Of {
    Int,
    Uint,
    Double,
    Bool,
    Str,
    Bytes,
    Duration,
    Timestamp,
    List,
    Map,
}

#[expect(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    reason = "an arm per predicate, over its operands"
)]
pub fn compile(p: &Pred, this: &Ty) -> Option<Test> {
    Some(match p {
        Pred::Compare(x, op, c) => {
            let op = *op;
            match (of(x, this)?, c) {
                (Of::Int, &Const::Int(k)) => ordered(int(x)?, op, k),
                (Of::Uint, &Const::Uint(k)) => ordered(uint(x)?, op, k),
                (Of::Double, &Const::Double(k)) => ordered(double(x)?, op, k),
                (Of::Bool, &Const::Bool(k)) => ordered(boolean(x)?, op, k),
                (Of::Duration, &Const::Duration(k)) => ordered(duration(x)?, op, k),
                (Of::Timestamp, &Const::Timestamp(k)) => ordered(timestamp(x)?, op, k),
                (Of::Str, Const::String(k)) => {
                    let (get, k) = (string(x)?, k.clone());
                    Box::new(move |v, c| Some(decide(op, Some((*get(v, c)?).cmp(&*k)))))
                }
                (Of::Bytes, Const::Bytes(k)) => {
                    let (get, k) = (bytes(x)?, k.clone());
                    Box::new(move |v, c| Some(decide(op, Some((*get(v, c)?).cmp(&*k)))))
                }
                (Of::List | Of::Map, k @ (Const::List(_) | Const::Map(_)))
                    if matches!(op, Op::Eq | Op::Ne) =>
                {
                    let (get, k) = (value(x)?, k.clone());
                    Box::new(move |v, c| {
                        Some(equals(&get(v, c)?, &Value::from_const(&k)) == (op == Op::Eq))
                    })
                }
                _ => return None,
            }
        }
        Pred::Compare2(x, op, y) => {
            let op = *op;
            if of(x, this)? != of(y, this)? {
                return None;
            }
            match of(x, this)? {
                Of::Int => ordered2(int(x)?, op, int(y)?),
                Of::Uint => ordered2(uint(x)?, op, uint(y)?),
                Of::Double => ordered2(double(x)?, op, double(y)?),
                Of::Bool => ordered2(boolean(x)?, op, boolean(y)?),
                Of::Duration => ordered2(duration(x)?, op, duration(y)?),
                Of::Timestamp => ordered2(timestamp(x)?, op, timestamp(y)?),
                Of::Str => {
                    let (a, b) = (string(x)?, string(y)?);
                    Box::new(move |v, c| Some(decide(op, Some((*a(v, c)?).cmp(&*b(v, c)?)))))
                }
                Of::Bytes => {
                    let (a, b) = (bytes(x)?, bytes(y)?);
                    Box::new(move |v, c| Some(decide(op, Some((*a(v, c)?).cmp(&*b(v, c)?)))))
                }
                Of::List | Of::Map => return None,
            }
        }
        Pred::Size(x, op, c) => {
            let op = *op;
            let n: Get<i64> = match of(x, this)? {
                Of::Str => {
                    let get = string(x)?;
                    Box::new(move |v, c| Some(char_count(&get(v, c)?)))
                }
                Of::Bytes => {
                    let get = bytes(x)?;
                    Box::new(move |v, c| Some(i64::try_from(get(v, c)?.len()).unwrap_or(i64::MAX)))
                }
                Of::List | Of::Map => {
                    let get = value(x)?;
                    Box::new(move |v, c| {
                        let n = match get(v, c)? {
                            Value::List(l) => l.len(),
                            Value::Map(m) => m.len(),
                            _ => return None,
                        };
                        Some(i64::try_from(n).unwrap_or(i64::MAX))
                    })
                }
                _ => return None,
            };
            match *c {
                Const::Int(k) => ordered(n, op, k),
                Const::Uint(k) => Box::new(move |v, c| {
                    let n = u64::try_from(n(v, c)?).ok()?;
                    Some(decide(op, Some(n.cmp(&k))))
                }),
                _ => return None,
            }
        }
        Pred::Match(x, re) => {
            if of(x, this)? != Of::Str {
                return None;
            }
            let (get, re) = (string(x)?, Pattern::new(re));
            Box::new(move |v, c| Some(re.is_match(&get(v, c)?)))
        }
        Pred::In(x, items) => match of(x, this)? {
            Of::Int => within(int(x)?, items, |c| match *c {
                Const::Int(i) => Some(i),
                _ => None,
            })?,
            Of::Uint => within(uint(x)?, items, |c| match *c {
                Const::Uint(u) => Some(u),
                _ => None,
            })?,
            Of::Double => within(double(x)?, items, |c| match *c {
                Const::Double(d) => Some(d),
                _ => None,
            })?,
            Of::Duration => within(duration(x)?, items, |c| match *c {
                Const::Duration(d) => Some(d),
                _ => None,
            })?,
            Of::Timestamp => within(timestamp(x)?, items, |c| match *c {
                Const::Timestamp(t) => Some(t),
                _ => None,
            })?,
            Of::Str => {
                let get = string(x)?;
                let items = all(items, |c| match c {
                    Const::String(s) => Some(s.clone()),
                    _ => None,
                })?;
                Box::new(move |v, c| {
                    let s = get(v, c)?;
                    Some(items.iter().any(|i| **i == *s))
                })
            }
            Of::Bytes => {
                let get = bytes(x)?;
                let items = all(items, |c| match c {
                    Const::Bytes(b) => Some(b.clone()),
                    _ => None,
                })?;
                Box::new(move |v, c| {
                    let b = get(v, c)?;
                    Some(items.iter().any(|i| **i == *b))
                })
            }
            Of::Bool | Of::List | Of::Map => return None,
        },
        Pred::Has(x, read) => {
            if x.base != Base::This || x.conv != Conv::None {
                return None;
            }
            let get = message(&x.path)?;
            let read = (**read).clone();
            Box::new(move |v, c| Some(get(v, c)?.has_read(&read)))
        }
        Pred::Text(x, test) => {
            if of(x, this)? != Of::Str {
                return None;
            }
            let (get, test) = (string(x)?, *test);
            Box::new(move |v, c| Some(test(&get(v, c)?)))
        }
        Pred::Number(x, test) => {
            if of(x, this)? != Of::Double {
                return None;
            }
            let (get, test) = (double(x)?, *test);
            Box::new(move |v, c| Some(test(get(v, c)?)))
        }
        Pred::Call(f, x, consts) => match (of(x, this)?, f, &**consts) {
            (Of::Str, Func::StartsWith | Func::EndsWith | Func::Contains, [Const::String(k)]) => {
                let (get, k, f) = (string(x)?, k.clone(), f.clone());
                Box::new(move |v, c| {
                    let s = get(v, c)?;
                    Some(match f {
                        Func::StartsWith => s.starts_with(&*k),
                        Func::EndsWith => s.ends_with(&*k),
                        _ => s.contains(&*k),
                    })
                })
            }
            (Of::Bytes, Func::StartsWith | Func::EndsWith | Func::Contains, [Const::Bytes(k)]) => {
                let (get, k, f) = (bytes(x)?, k.clone(), f.clone());
                Box::new(move |v, c| {
                    let b = get(v, c)?;
                    Some(match f {
                        Func::StartsWith => b.starts_with(&k),
                        Func::EndsWith => b.ends_with(&k),
                        _ => k.is_empty() || b.windows(k.len()).any(|w| *w == *k),
                    })
                })
            }
            // Functions of a string and constants, and `unique()` of a
            // list: the library's own, on the values read.
            (Of::Str, Func::IsIp | Func::IsIpPrefix | Func::IsHostAndPort, _)
                if x.conv == Conv::None && consts.len() <= 2 =>
            {
                library(value(x)?, f, consts)
            }
            (Of::List, Func::Unique, []) => library(value(x)?, f, consts),
            _ => return None,
        },
        Pred::Each(x, all, body) => {
            if of(x, this)? != Of::List {
                return None;
            }
            let body = compile(body, &item(x, this)?)?;
            let (get, all) = (value(x)?, *all);
            Box::new(move |v, c| {
                let Value::List(items) = get(v, c)? else {
                    return None;
                };
                let mut out = Some(all);
                items.for_each(&mut |item| match body(Arg::Value(&item), c) {
                    Some(b) if b != all => {
                        out = Some(!all);
                        false
                    }
                    Some(_) => true,
                    None => {
                        out = None;
                        false
                    }
                });
                out
            })
        }
        Pred::Not(p) => {
            let p = compile(p, this)?;
            Box::new(move |v, c| p(v, c).map(|b| !b))
        }
        Pred::And(ps) => {
            let (a, b) = (compile(&ps.0, this)?, compile(&ps.1, this)?);
            Box::new(move |v, c| Some(a(v, c)? && b(v, c)?))
        }
        Pred::Or(ps) => {
            let (a, b) = (compile(&ps.0, this)?, compile(&ps.1, this)?);
            Box::new(move |v, c| Some(a(v, c)? || b(v, c)?))
        }
    })
}

/// A library function of the operand and constants that answers a bool.
fn library(get: GetValue, f: &Func, consts: &[Const]) -> Test {
    let (f, consts): (Func, Box<[Const]>) = (f.clone(), consts.into());
    Box::new(move |v, c| {
        let mut args = [const { Value::Null }; 3];
        args[0] = get(v, c)?;
        for (slot, k) in args[1..].iter_mut().zip(consts.iter()) {
            *slot = Value::from_const(k);
        }
        match functions::call(&f, &args[..=consts.len()]) {
            Ok(Value::Bool(b)) => Some(b),
            _ => None,
        }
    })
}

/// `x <op> k`, for an operand of an ordered type.
fn ordered<T: PartialOrd + Send + Sync + 'static>(get: Get<T>, op: Op, k: T) -> Test {
    Box::new(move |v, c| Some(decide(op, get(v, c)?.partial_cmp(&k))))
}

/// `x <op> y`, for operands of one ordered type.
fn ordered2<T: PartialOrd + 'static>(a: Get<T>, op: Op, b: Get<T>) -> Test {
    Box::new(move |v, c| Some(decide(op, a(v, c)?.partial_cmp(&b(v, c)?))))
}

/// `x in [..]`, for a list of constants of the operand's type.
fn within<T: PartialEq + Send + Sync + 'static>(
    get: Get<T>,
    items: &[Const],
    f: impl Fn(&Const) -> Option<T>,
) -> Option<Test> {
    let items = all(items, f)?;
    Some(Box::new(move |v, c| Some(items.contains(&get(v, c)?))))
}

/// A regular expression, as a DFA built ahead when it is small enough:
/// matching then takes no cache, which a `Regex` takes from a pool per call.
struct Pattern {
    dfa: Option<DFA<Vec<u32>>>,
    re: Box<Regex>,
}

impl Pattern {
    fn new(re: &Regex) -> Self {
        const LIMIT: usize = 1 << 20;
        let dfa = dense::Builder::new()
            .configure(
                dense::Config::new()
                    .dfa_size_limit(Some(LIMIT))
                    .determinize_size_limit(Some(LIMIT)),
            )
            .build(re.as_str())
            .ok();
        Self {
            dfa,
            re: Box::new(re.clone()),
        }
    }

    fn is_match(&self, s: &str) -> bool {
        // A DFA may give up on a haystack (a Unicode word boundary past
        // ASCII); the regex then decides.
        self.dfa
            .as_ref()
            .and_then(|dfa| dfa.try_search_fwd(&Input::new(s).earliest(true)).ok())
            .map_or_else(|| self.re.is_match(s), |m| m.is_some())
    }
}

/// A comparison's outcome, as CEL decides it: unordered values (NaN) are
/// only unequal.
#[inline]
const fn decide(op: Op, order: Option<Ordering>) -> bool {
    match (op, order) {
        (Op::Ne, Some(o)) => !matches!(o, Ordering::Equal),
        (Op::Eq, Some(Ordering::Equal))
        | (Op::Ne, None)
        | (Op::Lt, Some(Ordering::Less))
        | (Op::Le, Some(Ordering::Less | Ordering::Equal))
        | (Op::Gt, Some(Ordering::Greater))
        | (Op::Ge, Some(Ordering::Greater | Ordering::Equal)) => true,
        _ => false,
    }
}

fn all<T>(items: &[Const], f: impl Fn(&Const) -> Option<T>) -> Option<Box<[T]>> {
    items.iter().map(f).collect()
}

/// What an operand holds, after its conversion.
fn of(x: &Operand, this: &Ty) -> Option<Of> {
    let held = match (x.base, x.path.last()) {
        (Base::Now(_), _) => Of::Timestamp,
        (Base::This, None) => match this {
            Ty::Int => Of::Int,
            Ty::Uint => Of::Uint,
            Ty::Double => Of::Double,
            Ty::Bool => Of::Bool,
            Ty::String => Of::Str,
            Ty::Bytes => Of::Bytes,
            Ty::Duration => Of::Duration,
            Ty::Timestamp => Of::Timestamp,
            Ty::List(_) => Of::List,
            Ty::Map(..) => Of::Map,
            _ => return None,
        },
        (Base::This, Some(read)) => match (read.shape.card, read.shape.kind, read.wkt) {
            (Card::List, ..) => Of::List,
            (Card::Map(_), ..) => Of::Map,
            (_, Kind::Message(_), Some(Wkt::Duration)) => Of::Duration,
            (_, Kind::Message(_), Some(Wkt::Timestamp)) => Of::Timestamp,
            _ => match Ty::of_scalar(scalar(read)?) {
                Ty::Int => Of::Int,
                Ty::Uint => Of::Uint,
                Ty::Double => Of::Double,
                Ty::Bool => Of::Bool,
                Ty::String => Of::Str,
                _ => Of::Bytes,
            },
        },
    };
    match (x.conv, held) {
        (Conv::None, held) => Some(held),
        (Conv::Bytes, Of::Str | Of::Bytes) => Some(Of::Bytes),
        (Conv::String, Of::Str | Of::Bytes) => Some(Of::Str),
        _ => None,
    }
}

/// The type of a list operand's items.
fn item(x: &Operand, this: &Ty) -> Option<Ty> {
    match (x.base, x.path.last()) {
        (Base::This, None) => match this {
            Ty::List(t) => Some((**t).clone()),
            _ => None,
        },
        (Base::This, Some(read)) => Some(match (read.shape.kind, read.wkt) {
            (Kind::Scalar(s), _) => Ty::of_scalar(s),
            (Kind::Enum(_), _) => Ty::Int,
            (Kind::Message(_), Some(Wkt::Duration)) => Ty::Duration,
            (Kind::Message(_), Some(Wkt::Timestamp)) => Ty::Timestamp,
            (Kind::Message(m), None) => Ty::Message(m),
            _ => Ty::Dyn,
        }),
        (Base::Now(_), _) => None,
    }
}

/// A singular scalar field's type; an enum reads as an int32.
const fn scalar(read: &Read) -> Option<ScalarType> {
    match (read.shape.card, read.shape.kind) {
        (Card::Singular, Kind::Scalar(s)) => Some(s),
        (Card::Singular, Kind::Enum(_)) => Some(ScalarType::Int32),
        _ => None,
    }
}

/// Reads a message: `this`, or a path of singular message fields from it.
fn message(path: &[Read]) -> Option<GetMsg> {
    let path: Box<[(Read, MessageIndex)]> = path
        .iter()
        .map(|r| match (r.shape.card, r.shape.kind, r.wkt) {
            (Card::Singular, Kind::Message(m), None) => Some((r.clone(), m)),
            _ => None,
        })
        .collect::<Option<_>>()?;
    Some(Box::new(move |v, _| {
        let Arg::Value(Value::Message(m)) = v else {
            return None;
        };
        let Some(((first, index), rest)) = path.split_first() else {
            return Some(m.clone());
        };
        let mut at = m.child(first, *index);
        for (read, index) in rest {
            at = at.child(read, *index);
        }
        Some(at)
    }))
}

/// Reads an operand's value, before its conversion, as a CEL value.
fn value(x: &Operand) -> Option<GetValue> {
    if let Base::Now(d) = x.base {
        return Some(Box::new(move |_, c| {
            c.now().checked_add_signed(d).map(Value::Timestamp)
        }));
    }
    let Some((last, path)) = x.path.split_last() else {
        return Some(Box::new(|v, _| match v {
            Arg::Prim(p) => Some(p.value()),
            Arg::Value(v) => Some(v.clone()),
        }));
    };
    let last = last.clone();
    let get = message(path)?;
    Some(Box::new(move |v, c| Some(get(v, c)?.read(&last))))
}

/// Reads an operand's scalar, `this` or a field of a message, as `T`.
fn read<T: 'static>(
    x: &Operand,
    conv: impl Fn(Prim<'_>) -> Option<T> + Copy + Send + Sync + 'static,
) -> Option<Get<T>> {
    if x.base != Base::This || x.conv != Conv::None {
        return None;
    }
    let Some((last, path)) = x.path.split_last() else {
        return Some(Box::new(move |v, _| conv(this_prim(v)?)));
    };
    let s = scalar(last)?;
    let last = last.clone();
    if path.is_empty() {
        return Some(Box::new(move |v, _| match v {
            Arg::Value(Value::Message(m)) => conv(m.prim(&last, s)),
            _ => None,
        }));
    }
    let get = message(path)?;
    Some(Box::new(move |v, c| conv(get(v, c)?.prim(&last, s))))
}

const fn this_prim<'a>(v: Arg<'_, 'a>) -> Option<Prim<'a>> {
    let v = match v {
        Arg::Prim(p) => return Some(p),
        Arg::Value(v) => v,
    };
    match v {
        Value::Int(i) => Some(Prim::Int(*i)),
        Value::Uint(u) => Some(Prim::Uint(*u)),
        Value::Double(d) => Some(Prim::Double(*d)),
        Value::Bool(b) => Some(Prim::Bool(*b)),
        Value::String(Str::Ref(s)) => Some(Prim::Str(s.as_bytes())),
        Value::Bytes(Bin::Ref(b)) => Some(Prim::Bytes(b)),
        _ => None,
    }
}

fn int(x: &Operand) -> Option<Get<i64>> {
    read(x, |p| match p {
        Prim::Int(i) => Some(i),
        _ => None,
    })
}

fn uint(x: &Operand) -> Option<Get<u64>> {
    read(x, |p| match p {
        Prim::Uint(u) => Some(u),
        _ => None,
    })
}

fn double(x: &Operand) -> Option<Get<f64>> {
    read(x, |p| match p {
        Prim::Double(d) => Some(d),
        _ => None,
    })
}

fn boolean(x: &Operand) -> Option<Get<bool>> {
    read(x, |p| match p {
        Prim::Bool(b) => Some(b),
        _ => None,
    })
}

fn duration(x: &Operand) -> Option<Get<TimeDelta>> {
    let get = value(x)?;
    Some(Box::new(move |v, c| match get(v, c)? {
        Value::Duration(d) => Some(d),
        _ => None,
    }))
}

fn timestamp(x: &Operand) -> Option<Get<DateTime<Utc>>> {
    let get = value(x)?;
    Some(Box::new(move |v, c| match get(v, c)? {
        Value::Timestamp(t) => Some(t),
        _ => None,
    }))
}

/// Reads an operand's string. `string(b)` of bytes that are not UTF-8 is an
/// error the predicate reports, so the test declines.
fn string(x: &Operand) -> Option<GetStr> {
    let get = text_or_bytes(x)?;
    Some(Box::new(move |v, c| match get(v, c)? {
        Prim::Str(b) => Some(utf8(b)),
        Prim::Bytes(b) => std::str::from_utf8(b).ok().map(Str::Ref),
        _ => None,
    }))
}

/// Reads an operand's bytes; `bytes(s)` of a string is its UTF-8.
fn bytes(x: &Operand) -> Option<GetBytes> {
    let get = text_or_bytes(x)?;
    Some(Box::new(move |v, c| match get(v, c)? {
        Prim::Str(b) | Prim::Bytes(b) => Some(Bin::Ref(b)),
        _ => None,
    }))
}

/// Reads a string or bytes operand's bytes, whichever conversion it has.
fn text_or_bytes(x: &Operand) -> Option<GetPrim> {
    if x.base != Base::This {
        return None;
    }
    let Some((last, path)) = x.path.split_last() else {
        return Some(Box::new(|v, _| match v {
            Arg::Prim(p) => Some(p),
            Arg::Value(Value::String(Str::Ref(s))) => Some(Prim::Str(s.as_bytes())),
            Arg::Value(Value::Bytes(Bin::Ref(b))) => Some(Prim::Bytes(b)),
            Arg::Value(_) => None,
        }));
    };
    let s = scalar(last)?;
    let last = last.clone();
    let get = message(path)?;
    Some(Box::new(move |v, c| Some(get(v, c)?.prim(&last, s))))
}
