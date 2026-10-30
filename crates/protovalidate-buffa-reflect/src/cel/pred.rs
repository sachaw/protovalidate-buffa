//! Rules that fold to a test of `this` and its fields, as standard rules and
//! most message rules do, run as native checks: a predicate evaluated to a
//! `bool` without the general tree's values.
//!
//! The predicate is derived from the folded expression, so it means exactly
//! what the rule's CEL means; any shape not listed here stays a [`Node`].

use chrono::TimeDelta;
use regex::Regex;

use super::{
    Clock, Error,
    compile::{FoldKind, Func, Node, Op},
    eval, functions, typed,
    value::{Const, Read, Value, equals},
};

pub enum Pred {
    /// `x <op> c`.
    Compare(Operand, Op, Const),
    /// `x <op> y`.
    Compare2(Operand, Op, Operand),
    /// `size(x) <op> c`.
    Size(Operand, Op, Const),
    Match(Operand, Box<Regex>),
    /// `x in [..]`.
    In(Operand, Box<[Const]>),
    /// `has(x.f)`.
    Has(Operand, Box<Read>),
    /// A test of a string `x`, such as `x.isEmail()`.
    Text(Operand, fn(&str) -> bool),
    /// A test of a double `x`, such as `x.isNan()`.
    Number(Operand, fn(f64) -> bool),
    /// A function of `x` and further arguments.
    Call(Func, Operand, Box<[Param]>),
    /// `x.all(e, p)` (true) or `x.exists(e, p)` (false) over a list's items
    /// or a map's keys, `p` a predicate of the item; or over a map's values,
    /// when `p` reads `x[e]` alone.
    Each(Operand, bool, Over, Box<Self>),
    /// `c ? a : b`.
    Cond(Box<(Self, Self, Self)>),
    Not(Box<Self>),
    And(Box<(Self, Self)>),
    Or(Box<(Self, Self)>),
}

/// What a comprehension visits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Over {
    /// A list's items, or a map's keys.
    Items,
    /// A map's values.
    Values,
}

/// An argument of a function after its subject.
#[derive(Clone)]
pub enum Param {
    Const(Const),
    Operand(Operand),
}

/// `this`, or a path of fields from it, then a field selected by name, a
/// conversion and arithmetic with a constant, each when there is one.
#[derive(Clone)]
pub struct Operand {
    pub base: Base,
    /// Fields read from `this`.
    pub path: Box<[Read]>,
    /// A field of a `dyn` value, selected by name when it runs.
    pub name: Option<Box<str>>,
    pub conv: Conv,
    /// `x <op> y` for arithmetic `op`.
    pub arith: Option<(Op, Box<Param>)>,
}

/// Where an operand starts.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Base {
    This,
    /// `now`, plus a duration.
    Now(TimeDelta),
}

/// What stands for `this` in a comprehension's body.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Item {
    /// Nothing: the predicate is of `this` itself.
    None,
    /// The comprehension variable, the item or key.
    Key(u8),
    /// `this[var]`, the map value at the key.
    Value(u8),
}

/// A conversion applied to an operand's value.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Conv {
    None,
    /// `bytes(x)`.
    Bytes,
    /// `string(x)`.
    String,
    /// `int(x)`.
    Int,
}

/// A rule as a native check: it fails when `pred` is `fails_when`, with the
/// given message, if any.
pub struct Check {
    pub pred: Pred,
    /// The predicate compiled for the types it reads, when they are known.
    pub typed: Option<typed::Test>,
    /// Whether `typed` reads `this` alone.
    pub scalar: bool,
    pub fails_when: bool,
    pub message: Option<Box<str>>,
    /// The expression of a failure's message, when it is not a constant.
    pub explain: Option<Node>,
}

/// Whether a node could be a message: anything but a bool.
const fn is_text(n: &Node) -> bool {
    !matches!(n, Node::Const(Const::Bool(_)))
}

impl Check {
    pub fn from_node(node: &Node) -> Option<Self> {
        match node {
            Node::Choose(x) => match (&x.1, &x.2) {
                (Const::String(m), Const::String(e)) if e.is_empty() => Some(Self {
                    pred: Pred::from_node(&x.0)?,
                    typed: None,
                    scalar: false,
                    fails_when: true,
                    message: Some(m.clone()),
                    explain: None,
                }),
                (Const::String(e), Const::String(m)) if e.is_empty() => Some(Self {
                    pred: Pred::from_node(&x.0)?,
                    typed: None,
                    scalar: false,
                    fails_when: false,
                    message: Some(m.clone()),
                    explain: None,
                }),
                _ => None,
            },
            // `p ? message : ''` and `p ? '' : message`, the message built
            // from the value: the test is native, the message is evaluated
            // only for a failure.
            Node::Cond(xs) => {
                let empty = |n: &Node| matches!(n, Node::Const(Const::String(s)) if s.is_empty());
                let (fails_when, explain) = match (empty(&xs[1]), empty(&xs[2])) {
                    (false, true) if is_text(&xs[1]) => (true, &xs[1]),
                    (true, false) if is_text(&xs[2]) => (false, &xs[2]),
                    _ => {
                        return Some(Self {
                            pred: Pred::from_node(node)?,
                            typed: None,
                            scalar: false,
                            fails_when: false,
                            message: None,
                            explain: None,
                        });
                    }
                };
                Some(Self {
                    pred: Pred::from_node(&xs[0])?,
                    typed: None,
                    scalar: false,
                    fails_when,
                    message: None,
                    explain: Some(explain.clone()),
                })
            }
            n => Some(Self {
                pred: Pred::from_node(n)?,
                typed: None,
                scalar: false,
                fails_when: false,
                message: None,
                explain: None,
            }),
        }
    }
}

impl Operand {
    fn this() -> Self {
        Self {
            base: Base::This,
            path: Box::default(),
            name: None,
            conv: Conv::None,
            arith: None,
        }
    }

    /// Whether the operand is `this` as it is.
    pub fn is_this(&self) -> bool {
        self.base == Base::This
            && self.path.is_empty()
            && self.name.is_none()
            && self.conv == Conv::None
            && self.arith.is_none()
    }

    fn within(node: &Node, item: Item) -> Option<Self> {
        let (arith, node) = match node {
            Node::Op(op @ (Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Rem), xs)
                if !matches!(xs[0], Node::Now) =>
            {
                let y = match &xs[1] {
                    Node::Const(c) => Param::Const(c.clone()),
                    y => Param::Operand(Self::within(y, item)?),
                };
                (Some((*op, Box::new(y))), &xs[0])
            }
            x => (None, x),
        };
        let (conv, node) = match node {
            Node::Call1(Func::ToBytes, x) => (Conv::Bytes, &**x),
            Node::Call1(Func::ToString, x) => (Conv::String, &**x),
            Node::Call1(Func::ToInt, x) => (Conv::Int, &**x),
            x => (Conv::None, x),
        };
        let (name, node) = match node {
            Node::Get(x, name) => (Some(name.clone()), &**x),
            x => (None, x),
        };
        let now = |d: TimeDelta| {
            Some(Self {
                base: Base::Now(d),
                path: Box::new([]),
                name: None,
                conv,
                arith: arith.clone(),
            })
        };
        match node {
            Node::Now => return now(TimeDelta::zero()),
            Node::Op(op @ (Op::Add | Op::Sub), xs) if matches!(xs[0], Node::Now) => {
                return match (&xs[1], op) {
                    (Node::Const(Const::Duration(d)), Op::Add) => now(*d),
                    (Node::Const(Const::Duration(d)), _) => now(-*d),
                    _ => None,
                };
            }
            _ => {}
        }
        let mut path = Vec::new();
        let mut at = node;
        loop {
            match (at, item) {
                (Node::This, Item::None) => break,
                (Node::Local(v), Item::Key(i)) if *v == i => break,
                (Node::Op(Op::Index, xs), Item::Value(i))
                    if matches!(xs[0], Node::This) && matches!(xs[1], Node::Local(v) if v == i) =>
                {
                    break;
                }
                (Node::Field(x, read), _) => {
                    path.push((**read).clone());
                    at = x;
                }
                _ => return None,
            }
        }
        path.reverse();
        Some(Self {
            base: Base::This,
            path: path.into(),
            name,
            conv,
            arith,
        })
    }

    fn reads(&self, f: &mut dyn FnMut(u32)) {
        if let Some(first) = self.path.first() {
            f(first.shape.number);
        }
        if let Some((_, y)) = &self.arith
            && let Param::Operand(y) = &**y
        {
            y.reads(f);
        }
    }

    /// The operand's value.
    fn value<'a>(&'a self, this: &Value<'a>, clock: &Clock) -> Result<Value<'a>, Error> {
        self.with(this, clock, |v| Ok(v.clone()))
    }

    /// Calls `f` with the operand's value. `this` itself is passed as is,
    /// not moved through a return value.
    #[inline]
    fn with<'a, R>(
        &'a self,
        this: &Value<'a>,
        clock: &Clock,
        f: impl FnOnce(&Value<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        if self.is_this() {
            return f(this);
        }
        let mut v = match self.base {
            Base::This => match self.path.split_first() {
                None => this.clone(),
                Some((first, rest)) => {
                    let mut v = field(this, first)?;
                    for read in rest {
                        v = field(&v, read)?;
                    }
                    v
                }
            },
            Base::Now(d) => Value::Timestamp(
                clock
                    .now()
                    .checked_add_signed(d)
                    .ok_or_else(|| Error::new("timestamp overflow"))?,
            ),
        };
        if let Some(name) = &self.name {
            v = eval::select(&v, name)?;
        }
        v = match self.conv {
            Conv::None => v,
            Conv::Bytes => functions::call(&Func::ToBytes, std::slice::from_ref(&v))?,
            Conv::String => functions::call(&Func::ToString, std::slice::from_ref(&v))?,
            Conv::Int => functions::call(&Func::ToInt, std::slice::from_ref(&v))?,
        };
        if let Some((op, y)) = &self.arith {
            v = match &**y {
                Param::Const(c) => functions::arithmetic(*op, &v, &Value::from_const(c))?,
                Param::Operand(y) => functions::arithmetic(*op, &v, &y.value(this, clock)?)?,
            };
        }
        f(&v)
    }
}

fn field<'a>(v: &Value<'a>, read: &'a Read) -> Result<Value<'a>, Error> {
    match v {
        Value::Message(m) => Ok(m.read(read)),
        other => Err(Error::new(format!(
            "type '{}' does not support field selection",
            other.type_of().name()
        ))),
    }
}

impl Pred {
    fn from_node(node: &Node) -> Option<Self> {
        Self::within(node, Item::None)
    }

    /// A predicate of `this`, or, in a comprehension's body, of its item,
    /// which then stands for `this`.
    fn within(node: &Node, item: Item) -> Option<Self> {
        Some(match node {
            Node::CompareThis(op, c) if item == Item::None => {
                Self::Compare(Operand::this(), *op, (**c).clone())
            }
            Node::Compare(op, x) => match &x.0 {
                Node::Size(s, _) | Node::Call1(Func::Size, s) => {
                    Self::Size(Operand::within(s, item)?, *op, x.1.clone())
                }
                operand => Self::Compare(Operand::within(operand, item)?, *op, x.1.clone()),
            },
            Node::Op(op @ (Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge), xs) => {
                Self::Compare2(
                    Operand::within(&xs[0], item)?,
                    *op,
                    Operand::within(&xs[1], item)?,
                )
            }
            Node::Match(s, re) => Self::Match(Operand::within(s, item)?, re.clone()),
            Node::Op(Op::In, xs) => match &xs[1] {
                Node::Const(Const::List(items)) => {
                    Self::In(Operand::within(&xs[0], item)?, items.clone())
                }
                _ => return None,
            },
            Node::Has(x, read) => Self::Has(Operand::within(x, item)?, read.clone()),
            Node::Call1(f, s) if pure(f) => {
                let x = Operand::within(s, item)?;
                match (text(f), number(f)) {
                    (Some(t), _) => Self::Text(x, t),
                    (_, Some(n)) => Self::Number(x, n),
                    _ => Self::Call(f.clone(), x, Box::new([])),
                }
            }
            Node::Call(f, args) if pure(f) => {
                let (subject, rest) = args.split_first()?;
                let params = rest
                    .iter()
                    .map(|a| match a {
                        Node::Const(c) => Some(Param::Const(c.clone())),
                        a => Operand::within(a, item).map(Param::Operand),
                    })
                    .collect::<Option<_>>()?;
                Self::Call(f.clone(), Operand::within(subject, item)?, params)
            }
            Node::Fold(fold) if item == Item::None => {
                let all = match fold.kind {
                    FoldKind::All => true,
                    FoldKind::Exists => false,
                    _ => return None,
                };
                let range = Operand::within(&fold.range, Item::None)?;
                let test = fold.test.as_ref()?;
                match Self::within(test, Item::Key(fold.var)) {
                    Some(body) => Self::Each(range, all, Over::Items, Box::new(body)),
                    None if range.is_this() => {
                        let body = Self::within(test, Item::Value(fold.var))?;
                        Self::Each(range, all, Over::Values, Box::new(body))
                    }
                    None => return None,
                }
            }
            Node::Cond(xs) => Self::Cond(Box::new((
                Self::within(&xs[0], item)?,
                Self::within(&xs[1], item)?,
                Self::within(&xs[2], item)?,
            ))),
            Node::Not(x) => Self::Not(Box::new(Self::within(x, item)?)),
            Node::And(xs) => Self::And(Box::new((
                Self::within(&xs[0], item)?,
                Self::within(&xs[1], item)?,
            ))),
            Node::Or(xs) => Self::Or(Box::new((
                Self::within(&xs[0], item)?,
                Self::within(&xs[1], item)?,
            ))),
            _ => return None,
        })
    }

    /// Whether the predicate reads `this` alone, so a scalar off the wire
    /// can stand in for it.
    pub fn this_only(&self) -> bool {
        match self {
            Self::Compare(x, ..)
            | Self::Size(x, ..)
            | Self::Match(x, _)
            | Self::In(x, _)
            | Self::Text(x, _)
            | Self::Number(x, _)
            | Self::Call(_, x, _) => x.path.is_empty() && x.name.is_none(),
            Self::Compare2(x, _, y) => {
                x.path.is_empty() && y.path.is_empty() && x.name.is_none() && y.name.is_none()
            }
            Self::Cond(ps) => ps.0.this_only() && ps.1.this_only() && ps.2.this_only(),
            Self::Has(..) | Self::Each(..) => false,
            Self::Not(p) => p.this_only(),
            Self::And(ps) | Self::Or(ps) => ps.0.this_only() && ps.1.this_only(),
        }
    }

    /// Calls `f` with the number of each field of `this` the predicate reads.
    pub fn reads(&self, f: &mut dyn FnMut(u32)) {
        match self {
            Self::Compare(x, ..)
            | Self::Size(x, ..)
            | Self::Match(x, _)
            | Self::In(x, _)
            | Self::Text(x, _)
            | Self::Number(x, _)
            | Self::Each(x, ..) => x.reads(f),
            Self::Call(_, x, params) => {
                x.reads(f);
                for p in &**params {
                    if let Param::Operand(y) = p {
                        y.reads(f);
                    }
                }
            }
            Self::Cond(ps) => {
                ps.0.reads(f);
                ps.1.reads(f);
                ps.2.reads(f);
            }
            Self::Compare2(x, _, y) => {
                x.reads(f);
                y.reads(f);
            }
            Self::Has(x, read) => match x.path.first() {
                Some(first) => f(first.shape.number),
                None => f(read.shape.number),
            },
            Self::Not(p) => p.reads(f),
            Self::And(ps) | Self::Or(ps) => {
                ps.0.reads(f);
                ps.1.reads(f);
            }
        }
    }

    #[expect(clippy::too_many_lines, reason = "an arm per predicate")]
    pub fn eval<'a>(&'a self, this: &Value<'a>, clock: &Clock) -> Result<bool, Error> {
        match self {
            Self::Compare(x, op, c) => x.with(this, clock, |v| eval::compare_const_bool(*op, v, c)),
            Self::Compare2(x, op, y) => x.with(this, clock, |a| {
                y.with(this, clock, |b| match eval::binary(*op, a, b)? {
                    Value::Bool(b) => Ok(b),
                    _ => unreachable!("comparisons are bools"),
                })
            }),
            Self::Size(x, op, c) => x.with(this, clock, |v| {
                let n = match v {
                    Value::String(s) => eval::char_count(s),
                    other => match functions::call(&Func::Size, std::slice::from_ref(other))? {
                        Value::Int(n) => n,
                        _ => unreachable!("size() is an int"),
                    },
                };
                let n = match c {
                    Const::Uint(_) => {
                        Value::Uint(u64::try_from(n).map_err(|_| Error::new("uint out of range"))?)
                    }
                    _ => Value::Int(n),
                };
                eval::compare_const_bool(*op, &n, c)
            }),
            Self::Match(x, re) => x.with(this, clock, |v| match v {
                Value::String(s) => Ok(re.is_match(s)),
                other => Err(Error::no_overload("matches", &[other.type_of()])),
            }),
            Self::In(x, items) => x.with(this, clock, |v| {
                Ok(items.iter().any(|c| equals(v, &Value::from_const(c))))
            }),
            Self::Has(x, read) => x.with(this, clock, |v| match v {
                Value::Message(m) => Ok(m.has_read(read)),
                other => Err(Error::new(format!(
                    "type '{}' does not support field selection",
                    other.type_of().name()
                ))),
            }),
            Self::Text(x, test) => x.with(this, clock, |v| match v {
                Value::String(s) => Ok(test(s)),
                other => Err(Error::no_overload("string function", &[other.type_of()])),
            }),
            Self::Number(x, test) => x.with(this, clock, |v| match v {
                Value::Double(d) => Ok(test(*d)),
                other => Err(Error::no_overload("double function", &[other.type_of()])),
            }),
            Self::Call(f, x, params) => {
                let mut args = [const { Value::Null }; 4];
                args[0] = x.with(this, clock, |v| Ok(v.clone()))?;
                for (slot, p) in args[1..].iter_mut().zip(params.iter()) {
                    *slot = match p {
                        Param::Const(c) => Value::from_const(c),
                        Param::Operand(y) => y.with(this, clock, |v| Ok(v.clone()))?,
                    };
                }
                match functions::call(f, &args[..=params.len()])? {
                    Value::Bool(b) => Ok(b),
                    other => Err(Error::new(format!(
                        "expected a bool, got {}",
                        other.type_of().name()
                    ))),
                }
            }
            Self::Cond(ps) => {
                if ps.0.eval(this, clock)? {
                    ps.1.eval(this, clock)
                } else {
                    ps.2.eval(this, clock)
                }
            }
            Self::Each(x, all, over, body) => x.with(this, clock, |range| {
                // As CEL's comprehensions: a deciding item absorbs others'
                // errors.
                let mut error = None;
                let mut decided = false;
                let mut visit = |item: Value<'_>| match body.eval(&item, clock) {
                    Ok(b) if b != *all => {
                        decided = true;
                        false
                    }
                    Ok(_) => true,
                    Err(e) => {
                        error.get_or_insert(e);
                        true
                    }
                };
                match range {
                    Value::List(items) => items.for_each(&mut visit),
                    Value::Map(entries) if *over == Over::Values => {
                        entries.for_each(&mut |_, v| visit(v));
                    }
                    Value::Map(entries) => entries.for_each(&mut |k, _| visit(k)),
                    other => {
                        return Err(Error::new(format!(
                            "expression of type '{}' cannot be the range of a comprehension",
                            other.type_of().name()
                        )));
                    }
                }
                if decided {
                    return Ok(!*all);
                }
                error.map_or(Ok(*all), Err)
            }),
            Self::Not(p) => p.eval(this, clock).map(|b| !b),
            Self::And(ps) => logic(false, &ps.0, &ps.1, this, clock),
            Self::Or(ps) => logic(true, &ps.0, &ps.1, this, clock),
        }
    }
}

/// `&&` (deciding on false) and `||` (deciding on true): a deciding side
/// absorbs the other's error, as CEL specifies.
fn logic<'a>(
    decides: bool,
    a: &'a Pred,
    b: &'a Pred,
    this: &Value<'a>,
    clock: &Clock,
) -> Result<bool, Error> {
    let first = a.eval(this, clock);
    if first == Ok(decides) {
        return Ok(decides);
    }
    match (first, b.eval(this, clock)) {
        (_, Ok(x)) if x == decides => Ok(decides),
        (Err(e), _) | (_, Err(e)) => Err(e),
        (Ok(_), Ok(x)) => Ok(x),
    }
}

/// The one-argument string functions, as native tests.
fn text(f: &Func) -> Option<fn(&str) -> bool> {
    use protovalidate_buffa::rules::string as rules;
    Some(match f {
        Func::IsEmail => rules::is_email,
        Func::IsHostname => rules::is_hostname,
        Func::IsUri => rules::is_uri,
        Func::IsUriRef => rules::is_uri_ref,
        Func::IsIp => rules::is_ip,
        Func::IsIpPrefix => rules::is_ip_with_prefixlen,
        _ => return None,
    })
}

/// The one-argument double functions, as native tests.
fn number(f: &Func) -> Option<fn(f64) -> bool> {
    Some(match f {
        Func::IsNan => f64::is_nan,
        Func::IsInf => f64::is_infinite,
        _ => return None,
    })
}

/// Functions of their arguments alone, which a native check may call.
const fn pure(f: &Func) -> bool {
    matches!(
        f,
        Func::StartsWith
            | Func::EndsWith
            | Func::Contains
            | Func::IsEmail
            | Func::IsHostname
            | Func::IsIp
            | Func::IsIpPrefix
            | Func::IsUri
            | Func::IsUriRef
            | Func::IsHostAndPort
            | Func::IsNan
            | Func::IsInf
            | Func::Unique
    )
}
