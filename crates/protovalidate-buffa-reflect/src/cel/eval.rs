//! Evaluating a [`Node`] tree.

use std::rc::Rc;

use super::{
    Clock, Error,
    compile::{Fold, FoldKind, Func, Node, Op},
    functions,
    value::{Const, List, Map, Msg, Value, compare, equals},
};

pub const LOCALS: usize = 8;

struct Frame<'a, 'c, 'l> {
    this: &'l Value<'a>,
    clock: Option<&'c Clock>,
    /// Comprehension variables; empty for an expression without any.
    locals: &'l mut [Value<'a>],
}

/// Evaluates `node`, which binds `locals` comprehension variables.
pub fn run<'a>(
    node: &'a Node,
    locals: usize,
    this: &Value<'a>,
    clock: &Clock,
) -> Result<Value<'a>, Error> {
    if locals == 0 {
        let mut frame = Frame {
            this,
            clock: Some(clock),
            locals: &mut [],
        };
        return eval(node, &mut frame);
    }
    with_locals(node, this, clock)
}

#[inline(never)]
fn with_locals<'a>(node: &'a Node, this: &Value<'a>, clock: &Clock) -> Result<Value<'a>, Error> {
    let mut locals = [const { Value::Null }; LOCALS];
    let mut frame = Frame {
        this,
        clock: Some(clock),
        locals: &mut locals,
    };
    eval(node, &mut frame)
}

/// Evaluates a node that reads no input, for folding.
pub fn constant(node: &Node) -> Result<Value<'_>, Error> {
    let mut locals = [const { Value::Null }; LOCALS];
    let mut frame = Frame {
        this: &Value::Null,
        clock: None,
        locals: &mut locals,
    };
    eval(node, &mut frame)
}

fn boolean(v: &Value<'_>, function: &str) -> Result<bool, Error> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(Error::no_overload(function, &[other.type_of()])),
    }
}

fn message<'v, 'a>(v: &'v Value<'a>) -> Result<&'v Msg<'a>, Error> {
    match v {
        Value::Message(m) => Ok(m),
        other => Err(Error::new(format!(
            "type '{}' does not support field selection",
            other.type_of().name()
        ))),
    }
}

#[expect(clippy::many_single_char_names, reason = "an evaluator's operands")]
fn eval<'a>(node: &'a Node, f: &mut Frame<'a, '_, '_>) -> Result<Value<'a>, Error> {
    Ok(match node {
        Node::Const(c) => Value::from_const(c),
        Node::This => f.this.clone(),
        Node::Now => Value::Timestamp(
            f.clock
                .ok_or_else(|| Error::new("`now` is not constant"))?
                .now(),
        ),
        Node::Local(s) => f.locals[usize::from(*s)].clone(),
        Node::Field(x, read) => message(&*operand(x, f)?)?.read(read),
        Node::Has(x, read) => Value::Bool(message(&eval(x, f)?)?.has_read(read)),
        Node::Get(x, name) => select(&eval(x, f)?, name)?,
        Node::HasName(x, name) => match eval(x, f)? {
            Value::Message(m) => Value::Bool(
                m.has_by_name(name)
                    .ok_or_else(|| Error::new(format!("no such field '{name}'")))?,
            ),
            Value::Map(m) => Value::Bool(
                m.get(&Value::String(super::value::Str::Ref(name)))?
                    .is_some(),
            ),
            other => {
                return Err(Error::new(format!(
                    "invalid type for field selection: {}",
                    other.type_of().name()
                )));
            }
        },
        Node::Not(x) => Value::Bool(!boolean(&eval(x, f)?, "!_")?),
        Node::Neg(x) => functions::negate(&eval(x, f)?)?,
        Node::And(xs) => logic(true, &xs[0], &xs[1], f)?,
        Node::Or(xs) => logic(false, &xs[0], &xs[1], f)?,
        Node::Cond(xs) => {
            if boolean(&eval(&xs[0], f)?, "_?_:_")? {
                eval(&xs[1], f)?
            } else {
                eval(&xs[2], f)?
            }
        }
        Node::Op(op, xs) => {
            let a = eval(&xs[0], f)?;
            let b = eval(&xs[1], f)?;
            binary(*op, &a, &b)?
        }
        Node::List(xs) => list(xs, f)?,
        Node::Map(es) => map(es, f)?,
        Node::Call(func, xs) => call(func, xs, f)?,
        Node::Fold(fold) => comprehension(fold, f)?,
        Node::CompareThis(op, c) => compare_const(*op, f.this, c)?,
        Node::Compare(op, x) => compare_const(*op, &*operand(&x.0, f)?, &x.1)?,
        Node::Choose(x) => {
            if boolean(&eval(&x.0, f)?, "_?_:_")? {
                Value::from_const(&x.1)
            } else {
                Value::from_const(&x.2)
            }
        }
        Node::Call1(func, x) => {
            let v = operand(x, f)?;
            match (func, &*v) {
                (Func::Size, Value::String(s)) => Value::Int(char_count(s)),
                _ => call1(func, &v)?,
            }
        }
        Node::Match(x, re) => match &*operand(x, f)? {
            Value::String(s) => Value::Bool(re.is_match(s)),
            other => return Err(Error::no_overload("matches", &[other.type_of()])),
        },
        Node::Size(x, unsigned) => {
            let n = match &*operand(x, f)? {
                Value::String(s) => char_count(s),
                other => match call1(&Func::Size, other)? {
                    Value::Int(n) => n,
                    _ => unreachable!("size() is an int"),
                },
            };
            if *unsigned {
                Value::Uint(u64::try_from(n).map_err(|_| Error::new("uint out of range"))?)
            } else {
                Value::Int(n)
            }
        }
    })
}

/// An operand: `this` is borrowed rather than visited and cloned.
#[inline]
fn operand<'a, 'f>(
    x: &'a Node,
    f: &'f mut Frame<'a, '_, '_>,
) -> Result<std::borrow::Cow<'f, Value<'a>>, Error> {
    if matches!(x, Node::This) {
        Ok(std::borrow::Cow::Borrowed(f.this))
    } else {
        eval(x, f).map(std::borrow::Cow::Owned)
    }
}

#[inline(never)]
fn call1<'a>(func: &Func, v: &Value<'a>) -> Result<Value<'a>, Error> {
    functions::call(func, std::slice::from_ref(v))
}

pub fn char_count(s: &str) -> i64 {
    // ASCII strings, the common case, count their bytes.
    let n = if s.is_ascii() {
        s.len()
    } else {
        s.chars().count()
    };
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// A comparison against a constant: same-typed scalars directly, anything
/// else through the general operator.
#[inline]
pub fn compare_const<'a>(op: Op, v: &Value<'a>, c: &'a Const) -> Result<Value<'a>, Error> {
    compare_const_bool(op, v, c).map(Value::Bool)
}

#[inline]
pub fn compare_const_bool(op: Op, v: &Value<'_>, c: &Const) -> Result<bool, Error> {
    use std::cmp::Ordering as O;
    let order = match (v, c) {
        (Value::Int(x), Const::Int(y)) => Some(x.cmp(y)),
        (Value::Uint(x), Const::Uint(y)) => Some(x.cmp(y)),
        (Value::Double(x), Const::Double(y)) => x.partial_cmp(y),
        (Value::String(x), Const::String(y)) => Some((**x).cmp(&**y)),
        (Value::Bytes(x), Const::Bytes(y)) => Some((**x).cmp(&**y)),
        (Value::Bool(x), Const::Bool(y)) => Some(x.cmp(y)),
        (Value::Duration(x), Const::Duration(y)) => Some(x.cmp(y)),
        (Value::Timestamp(x), Const::Timestamp(y)) => Some(x.cmp(y)),
        _ => {
            return match binary(op, v, &Value::from_const(c))? {
                Value::Bool(b) => Ok(b),
                _ => unreachable!("comparisons are bools"),
            };
        }
    };
    Ok(match (op, order) {
        (Op::Eq, o) => o == Some(O::Equal),
        (Op::Ne, o) => o != Some(O::Equal),
        (_, None) => false,
        (Op::Lt, Some(o)) => o == O::Less,
        (Op::Le, Some(o)) => o != O::Greater,
        (Op::Gt, Some(o)) => o == O::Greater,
        (_, Some(o)) => o != O::Less,
    })
}

// The rarer nodes are kept out of `eval`, so its frame, entered once per
// node, stays small.

#[inline(never)]
fn list<'a>(xs: &'a [Node], f: &mut Frame<'a, '_, '_>) -> Result<Value<'a>, Error> {
    let mut items = Vec::with_capacity(xs.len());
    for x in xs {
        items.push(eval(x, f)?);
    }
    Ok(Value::List(List::Owned(items.into())))
}

#[inline(never)]
fn map<'a>(es: &'a [(Node, Node)], f: &mut Frame<'a, '_, '_>) -> Result<Value<'a>, Error> {
    let mut entries: Vec<(Value<'a>, Value<'a>)> = Vec::with_capacity(es.len());
    for (k, v) in es {
        let k = eval(k, f)?;
        if !matches!(
            k,
            Value::Bool(_) | Value::Int(_) | Value::Uint(_) | Value::String(_)
        ) {
            return Err(Error::new("unsupported map key type"));
        }
        if entries.iter().any(|(e, _)| equals(e, &k)) {
            return Err(Error::new("duplicate map key"));
        }
        entries.push((k, eval(v, f)?));
    }
    Ok(Value::Map(Map::Owned(entries.into())))
}

#[inline(never)]
fn call<'a>(
    func: &'a super::compile::Func,
    xs: &'a [Node],
    f: &mut Frame<'a, '_, '_>,
) -> Result<Value<'a>, Error> {
    let mut args = [const { Value::Null }; 4];
    let n = xs.len().min(4);
    for (slot, x) in args.iter_mut().zip(xs.iter()) {
        *slot = eval(x, f)?;
    }
    functions::call(func, &args[..n])
}

pub fn select<'a>(v: &Value<'a>, name: &str) -> Result<Value<'a>, Error> {
    match v {
        Value::Message(m) => m
            .field_by_name(name)
            .ok_or_else(|| Error::new(format!("no such field '{name}'"))),
        Value::Map(m) => m
            .get(&Value::String(super::value::Str::Ref(name)))?
            .ok_or_else(|| Error::new(format!("no such key: {name}"))),
        other => Err(Error::new(format!(
            "type '{}' does not support field selection",
            other.type_of().name()
        ))),
    }
}

/// `&&` and `||`, commutative over errors as CEL specifies: an error on one
/// side yields to a deciding value on the other.
fn logic<'a>(
    and: bool,
    a: &'a Node,
    b: &'a Node,
    f: &mut Frame<'a, '_, '_>,
) -> Result<Value<'a>, Error> {
    let name = if and { "_&&_" } else { "_||_" };
    let decides = !and;
    let first = eval(a, f).and_then(|v| boolean(&v, name));
    if first == Ok(decides) {
        return Ok(Value::Bool(decides));
    }
    let second = eval(b, f).and_then(|v| boolean(&v, name));
    match (first, second) {
        (_, Ok(x)) if x == decides => Ok(Value::Bool(decides)),
        (Err(e), _) | (Ok(_), Err(e)) => Err(e),
        (Ok(_), Ok(x)) => Ok(Value::Bool(x)),
    }
}

/// Orders two values of the same scalar type, the common case, without the
/// general comparison's dispatch. `Err` for any other pair; `Ok(None)` for
/// NaN.
#[inline]
fn same_type_order(a: &Value<'_>, b: &Value<'_>) -> Result<Option<std::cmp::Ordering>, ()> {
    Ok(match (a, b) {
        (Value::Int(x), Value::Int(y)) => Some(x.cmp(y)),
        (Value::Uint(x), Value::Uint(y)) => Some(x.cmp(y)),
        (Value::Double(x), Value::Double(y)) => x.partial_cmp(y),
        (Value::String(x), Value::String(y)) => Some((**x).cmp(&**y)),
        (Value::Bytes(x), Value::Bytes(y)) => Some((**x).cmp(&**y)),
        (Value::Bool(x), Value::Bool(y)) => Some(x.cmp(y)),
        (Value::Duration(x), Value::Duration(y)) => Some(x.cmp(y)),
        (Value::Timestamp(x), Value::Timestamp(y)) => Some(x.cmp(y)),
        _ => return Err(()),
    })
}

#[inline]
pub fn binary<'a>(op: Op, a: &Value<'a>, b: &Value<'a>) -> Result<Value<'a>, Error> {
    use std::cmp::Ordering as O;
    if matches!(op, Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge)
        && let Ok(order) = same_type_order(a, b)
    {
        return Ok(Value::Bool(match (op, order) {
            (Op::Eq, o) => o == Some(O::Equal),
            (Op::Ne, o) => o != Some(O::Equal),
            (_, None) => false,
            (Op::Lt, Some(o)) => o == O::Less,
            (Op::Le, Some(o)) => o != O::Greater,
            (Op::Gt, Some(o)) => o == O::Greater,
            (_, Some(o)) => o != O::Less,
        }));
    }
    binary_slow(op, a, b)
}

#[inline(never)]
fn binary_slow<'a>(op: Op, a: &Value<'a>, b: &Value<'a>) -> Result<Value<'a>, Error> {
    use std::cmp::Ordering as O;
    Ok(match op {
        Op::Eq => Value::Bool(equals(a, b)),
        Op::Ne => Value::Bool(!equals(a, b)),
        Op::Lt => Value::Bool(lt(a, b, "_<_", |o| o == O::Less)?),
        Op::Le => Value::Bool(lt(a, b, "_<=_", |o| o != O::Greater)?),
        Op::Gt => Value::Bool(lt(a, b, "_>_", |o| o == O::Greater)?),
        Op::Ge => Value::Bool(lt(a, b, "_>=_", |o| o != O::Less)?),
        Op::In => Value::Bool(contains(b, a)?),
        Op::Index => index(a, b)?,
        Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Rem => functions::arithmetic(op, a, b)?,
    })
}

/// A comparison. NaN compares false against everything.
fn lt(
    a: &Value<'_>,
    b: &Value<'_>,
    name: &str,
    test: impl Fn(std::cmp::Ordering) -> bool,
) -> Result<bool, Error> {
    match compare(a, b) {
        Ok(Some(o)) => Ok(test(o)),
        Ok(None) => Ok(false),
        Err(_) => Err(Error::no_overload(name, &[a.type_of(), b.type_of()])),
    }
}

fn contains(container: &Value<'_>, item: &Value<'_>) -> Result<bool, Error> {
    match container {
        Value::List(l) => Ok((0..l.len()).any(|i| l.get(i).is_some_and(|v| equals(&v, item)))),
        Value::Map(m) => Ok(m.get(item).unwrap_or(None).is_some()),
        other => Err(Error::no_overload(
            "@in",
            &[item.type_of(), other.type_of()],
        )),
    }
}

fn index<'a>(container: &Value<'a>, key: &Value<'a>) -> Result<Value<'a>, Error> {
    match (container, key) {
        (Value::List(l), Value::Int(_) | Value::Uint(_) | Value::Double(_)) => {
            let i = match *key {
                Value::Int(i) => i,
                Value::Uint(u) => i64::try_from(u).unwrap_or(i64::MAX),
                Value::Double(d) if d.fract() == 0.0 && d.abs() < 9e18 => {
                    #[expect(clippy::cast_possible_truncation, reason = "integral and in range")]
                    let i = d as i64;
                    i
                }
                _ => return Err(Error::new("invalid list index")),
            };
            usize::try_from(i)
                .ok()
                .and_then(|i| l.get(i))
                .ok_or_else(|| Error::new(format!("index out of bounds: {i}")))
        }
        (Value::Map(m), k) => m
            .get(k)?
            .ok_or_else(|| Error::new(format!("no such key: {k:?}"))),
        (c, k) => Err(Error::no_overload("_[_]", &[c.type_of(), k.type_of()])),
    }
}

/// Visits a range's elements (a list's items, a map's keys) until `f`
/// returns false.
fn each<'a>(range: &Value<'a>, f: &mut dyn FnMut(Value<'a>) -> bool) -> Result<(), Error> {
    match range {
        Value::List(l) => {
            l.for_each(f);
            Ok(())
        }
        Value::Map(m) => {
            m.for_each(&mut |k, _| f(k));
            Ok(())
        }
        other => Err(Error::new(format!(
            "expression of type '{}' cannot be the range of a comprehension",
            other.type_of().name()
        ))),
    }
}

#[inline(never)]
fn comprehension<'a>(fold: &'a Fold, f: &mut Frame<'a, '_, '_>) -> Result<Value<'a>, Error> {
    let range = eval(&fold.range, f)?;
    let var = usize::from(fold.var);
    let mut error: Option<Error> = None;
    match fold.kind {
        FoldKind::All | FoldKind::Exists => {
            let deciding = fold.kind == FoldKind::Exists;
            let predicate = fold.test.as_ref().expect("all and exists have a predicate");
            let mut decided = false;
            each(&range, &mut |item| {
                f.locals[var] = item;
                match eval(predicate, f).and_then(|v| boolean(&v, "predicate")) {
                    Ok(b) if b == deciding => {
                        decided = true;
                        false
                    }
                    Ok(_) => true,
                    Err(e) => {
                        error.get_or_insert(e);
                        true
                    }
                }
            })?;
            if decided {
                return Ok(Value::Bool(deciding));
            }
            error.map_or(Ok(Value::Bool(!deciding)), Err)
        }
        FoldKind::ExistsOne => {
            let test = fold.test.as_ref().expect("exists_one has a predicate");
            let mut count = 0usize;
            each(&range, &mut |item| {
                f.locals[var] = item;
                match eval(test, f).and_then(|v| boolean(&v, "predicate")) {
                    Ok(b) => {
                        count += usize::from(b);
                        true
                    }
                    Err(e) => {
                        error = Some(e);
                        false
                    }
                }
            })?;
            error.map_or(Ok(Value::Bool(count == 1)), Err)
        }
        FoldKind::Map => {
            let transform = fold.transform.as_ref().expect("map has a transform");
            let mut out = Vec::new();
            each(&range, &mut |item| {
                f.locals[var] = item;
                let keep = fold
                    .test
                    .as_ref()
                    .map_or(Ok(true), |t| eval(t, f).and_then(|v| boolean(&v, "filter")));
                match keep.and_then(|k| {
                    if k {
                        eval(transform, f).map(Some)
                    } else {
                        Ok(None)
                    }
                }) {
                    Ok(Some(v)) => {
                        out.push(v);
                        true
                    }
                    Ok(None) => true,
                    Err(e) => {
                        error = Some(e);
                        false
                    }
                }
            })?;
            error.map_or_else(|| Ok(Value::List(List::Owned(Rc::from(out)))), Err)
        }
    }
}
