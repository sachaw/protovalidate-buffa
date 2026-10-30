//! Native checks compiled to closures over typed reads.
//!
//! A predicate whose operands are `this` or paths of singular fields from
//! it, of scalar types known when compiling, reads those scalars straight
//! from the encoding and tests them without building CEL values. Each test
//! is derived from the [`Pred`], and so from the rule's CEL; a value of
//! another type than expected (a `dyn` field) makes it decline, and the
//! predicate runs instead.

use std::cmp::Ordering;

use buffa_descriptor::{MessageIndex, ScalarType};
use regex::Regex;

use super::{
    Ty,
    compile::{Func, Op},
    eval::char_count,
    pred::{Operand, Pred},
    value::{Bin, Const, Msg, Prim, Read, Str, Value, utf8},
};
use crate::wire::{Card, Kind};

/// A compiled test of `this`: `None` when the value is not of the type it
/// was compiled for.
pub type Test = Box<dyn for<'a> Fn(&Value<'a>) -> Option<bool> + Send + Sync>;

type Get<T> = Box<dyn for<'a> Fn(&Value<'a>) -> Option<T> + Send + Sync>;
type GetStr = Box<dyn for<'a> Fn(&Value<'a>) -> Option<Str<'a>> + Send + Sync>;
type GetBytes = Box<dyn for<'a> Fn(&Value<'a>) -> Option<&'a [u8]> + Send + Sync>;

/// What an operand holds, when it is a scalar.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Of {
    Int,
    Uint,
    Double,
    Bool,
    Str,
    Bytes,
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
                (Of::Int, &Const::Int(k)) => {
                    let get = int(x)?;
                    Box::new(move |v| Some(decide(op, Some(get(v)?.cmp(&k)))))
                }
                (Of::Uint, &Const::Uint(k)) => {
                    let get = uint(x)?;
                    Box::new(move |v| Some(decide(op, Some(get(v)?.cmp(&k)))))
                }
                (Of::Double, &Const::Double(k)) => {
                    let get = double(x)?;
                    Box::new(move |v| Some(decide(op, get(v)?.partial_cmp(&k))))
                }
                (Of::Bool, &Const::Bool(k)) => {
                    let get = boolean(x)?;
                    Box::new(move |v| Some(decide(op, Some(get(v)?.cmp(&k)))))
                }
                (Of::Str, Const::String(k)) => {
                    let (get, k) = (string(x)?, k.clone());
                    Box::new(move |v| Some(decide(op, Some((*get(v)?).cmp(&*k)))))
                }
                (Of::Bytes, Const::Bytes(k)) => {
                    let (get, k) = (bytes(x)?, k.clone());
                    Box::new(move |v| Some(decide(op, Some((*get(v)?).cmp(&*k)))))
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
                Of::Int => {
                    let (a, b) = (int(x)?, int(y)?);
                    Box::new(move |v| Some(decide(op, Some(a(v)?.cmp(&b(v)?)))))
                }
                Of::Uint => {
                    let (a, b) = (uint(x)?, uint(y)?);
                    Box::new(move |v| Some(decide(op, Some(a(v)?.cmp(&b(v)?)))))
                }
                Of::Double => {
                    let (a, b) = (double(x)?, double(y)?);
                    Box::new(move |v| Some(decide(op, a(v)?.partial_cmp(&b(v)?))))
                }
                Of::Bool => {
                    let (a, b) = (boolean(x)?, boolean(y)?);
                    Box::new(move |v| Some(decide(op, Some(a(v)?.cmp(&b(v)?)))))
                }
                Of::Str => {
                    let (a, b) = (string(x)?, string(y)?);
                    Box::new(move |v| Some(decide(op, Some((*a(v)?).cmp(&*b(v)?)))))
                }
                Of::Bytes => {
                    let (a, b) = (bytes(x)?, bytes(y)?);
                    Box::new(move |v| Some(decide(op, Some(a(v)?.cmp(b(v)?)))))
                }
            }
        }
        Pred::Size(x, op, c) => {
            let op = *op;
            let n: Get<i64> = match of(x, this)? {
                Of::Str => {
                    let get = string(x)?;
                    Box::new(move |v| Some(char_count(&get(v)?)))
                }
                Of::Bytes => {
                    let get = bytes(x)?;
                    Box::new(move |v| Some(i64::try_from(get(v)?.len()).unwrap_or(i64::MAX)))
                }
                _ => return None,
            };
            match *c {
                Const::Int(k) => Box::new(move |v| Some(decide(op, Some(n(v)?.cmp(&k))))),
                Const::Uint(k) => Box::new(move |v| {
                    let n = u64::try_from(n(v)?).ok()?;
                    Some(decide(op, Some(n.cmp(&k))))
                }),
                _ => return None,
            }
        }
        Pred::Match(x, re) => {
            if of(x, this)? != Of::Str {
                return None;
            }
            let (get, re): (_, Box<Regex>) = (string(x)?, re.clone());
            Box::new(move |v| Some(re.is_match(&get(v)?)))
        }
        Pred::In(x, items) => match of(x, this)? {
            Of::Int => {
                let get = int(x)?;
                let items = all(items, |c| match *c {
                    Const::Int(i) => Some(i),
                    _ => None,
                })?;
                Box::new(move |v| Some(items.contains(&get(v)?)))
            }
            Of::Uint => {
                let get = uint(x)?;
                let items = all(items, |c| match *c {
                    Const::Uint(u) => Some(u),
                    _ => None,
                })?;
                Box::new(move |v| Some(items.contains(&get(v)?)))
            }
            Of::Double => {
                let get = double(x)?;
                let items = all(items, |c| match *c {
                    Const::Double(d) => Some(d),
                    _ => None,
                })?;
                Box::new(move |v| Some(items.contains(&get(v)?)))
            }
            Of::Str => {
                let get = string(x)?;
                let items = all(items, |c| match c {
                    Const::String(s) => Some(s.clone()),
                    _ => None,
                })?;
                Box::new(move |v| {
                    let s = get(v)?;
                    Some(items.iter().any(|i| **i == *s))
                })
            }
            Of::Bytes => {
                let get = bytes(x)?;
                let items = all(items, |c| match c {
                    Const::Bytes(b) => Some(b.clone()),
                    _ => None,
                })?;
                Box::new(move |v| {
                    let b = get(v)?;
                    Some(items.iter().any(|i| **i == *b))
                })
            }
            Of::Bool => return None,
        },
        Pred::Has(x, read) => {
            let get = message(&x.0)?;
            let read = (**read).clone();
            Box::new(move |v| Some(get(v)?.has_read(&read)))
        }
        Pred::Text(x, test) => {
            if of(x, this)? != Of::Str {
                return None;
            }
            let (get, test) = (string(x)?, *test);
            Box::new(move |v| Some(test(&get(v)?)))
        }
        Pred::Number(x, test) => {
            if of(x, this)? != Of::Double {
                return None;
            }
            let (get, test) = (double(x)?, *test);
            Box::new(move |v| Some(test(get(v)?)))
        }
        Pred::Call(f, x, consts) => {
            let ty = of(x, this)?;
            let [c] = &**consts else { return None };
            match (ty, f, c) {
                (Of::Str, Func::StartsWith | Func::EndsWith | Func::Contains, Const::String(k)) => {
                    let (get, k, f) = (string(x)?, k.clone(), f.clone());
                    Box::new(move |v| {
                        let s = get(v)?;
                        Some(match f {
                            Func::StartsWith => s.starts_with(&*k),
                            Func::EndsWith => s.ends_with(&*k),
                            _ => s.contains(&*k),
                        })
                    })
                }
                (
                    Of::Bytes,
                    Func::StartsWith | Func::EndsWith | Func::Contains,
                    Const::Bytes(k),
                ) => {
                    let (get, k, f) = (bytes(x)?, k.clone(), f.clone());
                    Box::new(move |v| {
                        let b = get(v)?;
                        Some(match f {
                            Func::StartsWith => b.starts_with(&k),
                            Func::EndsWith => b.ends_with(&k),
                            _ => k.is_empty() || b.windows(k.len()).any(|w| *w == *k),
                        })
                    })
                }
                _ => return None,
            }
        }
        Pred::Not(p) => {
            let p = compile(p, this)?;
            Box::new(move |v| p(v).map(|b| !b))
        }
        Pred::And(ps) => {
            let (a, b) = (compile(&ps.0, this)?, compile(&ps.1, this)?);
            Box::new(move |v| Some(a(v)? && b(v)?))
        }
        Pred::Or(ps) => {
            let (a, b) = (compile(&ps.0, this)?, compile(&ps.1, this)?);
            Box::new(move |v| Some(a(v)? || b(v)?))
        }
    })
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

/// The scalar an operand holds.
fn of(x: &Operand, this: &Ty) -> Option<Of> {
    let ty = match x.0.last() {
        None => this.clone(),
        Some(read) => Ty::of_scalar(scalar(read)?),
    };
    Some(match ty {
        Ty::Int => Of::Int,
        Ty::Uint => Of::Uint,
        Ty::Double => Of::Double,
        Ty::Bool => Of::Bool,
        Ty::String => Of::Str,
        Ty::Bytes => Of::Bytes,
        _ => return None,
    })
}

/// A singular scalar field's type; an enum reads as an int32.
const fn scalar(read: &Read) -> Option<ScalarType> {
    match (read.shape.card, read.shape.kind) {
        (Card::Singular, Kind::Scalar(s)) => Some(s),
        (Card::Singular, Kind::Enum(_)) => Some(ScalarType::Int32),
        _ => None,
    }
}

type GetMsg = Box<dyn for<'a> Fn(&Value<'a>) -> Option<Msg<'a>> + Send + Sync>;

/// Reads a message: `this`, or a path of singular message fields from it.
fn message(path: &[Read]) -> Option<GetMsg> {
    let path: Box<[(Read, MessageIndex)]> = path
        .iter()
        .map(|r| match (r.shape.card, r.shape.kind, r.wkt) {
            (Card::Singular, Kind::Message(m), None) => Some((r.clone(), m)),
            _ => None,
        })
        .collect::<Option<_>>()?;
    Some(Box::new(move |v| {
        let Value::Message(m) = v else { return None };
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

/// Reads an operand's scalar, `this` or a field of a message, as `T`.
fn read<T: 'static>(
    x: &Operand,
    conv: impl Fn(Prim<'_>) -> Option<T> + Copy + Send + Sync + 'static,
) -> Option<Get<T>> {
    let Some((last, path)) = x.0.split_last() else {
        return Some(Box::new(move |v| conv(this_prim(v)?)));
    };
    let s = scalar(last)?;
    let last = last.clone();
    if path.is_empty() {
        return Some(Box::new(move |v| match v {
            Value::Message(m) => conv(m.prim(&last, s)),
            _ => None,
        }));
    }
    let get = message(path)?;
    Some(Box::new(move |v| conv(get(v)?.prim(&last, s))))
}

const fn this_prim<'a>(v: &Value<'a>) -> Option<Prim<'a>> {
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

/// Reads an operand's string: its bytes, which are UTF-8 in a valid
/// encoding.
fn string(x: &Operand) -> Option<GetStr> {
    let Some((last, path)) = x.0.split_last() else {
        return Some(Box::new(|v| match v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        }));
    };
    let s = scalar(last)?;
    if s != ScalarType::String {
        return None;
    }
    let last = last.clone();
    let get = message(path)?;
    Some(Box::new(move |v| match get(v)?.prim(&last, s) {
        Prim::Str(b) => Some(utf8(b)),
        _ => None,
    }))
}

fn bytes(x: &Operand) -> Option<GetBytes> {
    let Some((last, path)) = x.0.split_last() else {
        return Some(Box::new(|v| match v {
            Value::Bytes(Bin::Ref(b)) => Some(b),
            _ => None,
        }));
    };
    let s = scalar(last)?;
    let last = last.clone();
    let get = message(path)?;
    Some(Box::new(move |v| match get(v)?.prim(&last, s) {
        Prim::Bytes(b) => Some(b),
        _ => None,
    }))
}
