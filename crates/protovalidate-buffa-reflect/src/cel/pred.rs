//! Rules that fold to a test of `this` and its fields, as standard rules and
//! most message rules do, run as native checks: a predicate evaluated to a
//! `bool` without the general tree's values.
//!
//! The predicate is derived from the folded expression, so it means exactly
//! what the rule's CEL means; any shape not listed here stays a [`Node`].

use regex::Regex;

use super::{
    Error,
    compile::{Func, Node, Op},
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
    /// A function of `x` and constants.
    Call(Func, Operand, Box<[Const]>),
    Not(Box<Self>),
    And(Box<(Self, Self)>),
    Or(Box<(Self, Self)>),
}

/// `this`, or a path of fields from it.
pub struct Operand(pub Box<[Read]>);

/// A rule as a native check: it fails when `pred` is `fails_when`, with the
/// given message, if any.
pub struct Check {
    pub pred: Pred,
    /// The predicate compiled for the types it reads, when they are known.
    pub typed: Option<typed::Test>,
    pub fails_when: bool,
    pub message: Option<Box<str>>,
}

impl Check {
    pub fn from_node(node: &Node) -> Option<Self> {
        match node {
            Node::Choose(x) => match (&x.1, &x.2) {
                (Const::String(m), Const::String(e)) if e.is_empty() => Some(Self {
                    pred: Pred::from_node(&x.0)?,
                    typed: None,
                    fails_when: true,
                    message: Some(m.clone()),
                }),
                (Const::String(e), Const::String(m)) if e.is_empty() => Some(Self {
                    pred: Pred::from_node(&x.0)?,
                    typed: None,
                    fails_when: false,
                    message: Some(m.clone()),
                }),
                _ => None,
            },
            n => Some(Self {
                pred: Pred::from_node(n)?,
                typed: None,
                fails_when: false,
                message: None,
            }),
        }
    }
}

impl Operand {
    fn from_node(node: &Node) -> Option<Self> {
        let mut path = Vec::new();
        let mut at = node;
        loop {
            match at {
                Node::This => break,
                Node::Field(x, read) => {
                    path.push((**read).clone());
                    at = x;
                }
                _ => return None,
            }
        }
        path.reverse();
        Some(Self(path.into()))
    }

    fn reads(&self, f: &mut dyn FnMut(u32)) {
        if let Some(first) = self.0.first() {
            f(first.shape.number);
        }
    }

    /// Calls `f` with the operand's value. `this` itself is passed as is,
    /// not moved through a return value.
    #[inline]
    fn with<'a, R>(
        &'a self,
        this: &Value<'a>,
        f: impl FnOnce(&Value<'a>) -> Result<R, Error>,
    ) -> Result<R, Error> {
        let Some((first, rest)) = self.0.split_first() else {
            return f(this);
        };
        let mut v = field(this, first)?;
        for read in rest {
            v = field(&v, read)?;
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

fn consts(nodes: &[Node]) -> Option<Box<[Const]>> {
    nodes
        .iter()
        .map(|a| match a {
            Node::Const(c) => Some(c.clone()),
            _ => None,
        })
        .collect()
}

impl Pred {
    fn from_node(node: &Node) -> Option<Self> {
        Some(match node {
            Node::CompareThis(op, c) => Self::Compare(Operand(Box::new([])), *op, (**c).clone()),
            Node::Compare(op, x) => match &x.0 {
                Node::Size(s, _) | Node::Call1(Func::Size, s) => {
                    Self::Size(Operand::from_node(s)?, *op, x.1.clone())
                }
                operand => Self::Compare(Operand::from_node(operand)?, *op, x.1.clone()),
            },
            Node::Op(op @ (Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge), xs) => {
                Self::Compare2(
                    Operand::from_node(&xs[0])?,
                    *op,
                    Operand::from_node(&xs[1])?,
                )
            }
            Node::Match(s, re) => Self::Match(Operand::from_node(s)?, re.clone()),
            Node::Op(Op::In, xs) => match &xs[1] {
                Node::Const(Const::List(items)) => {
                    Self::In(Operand::from_node(&xs[0])?, items.clone())
                }
                _ => return None,
            },
            Node::Has(x, read) => Self::Has(Operand::from_node(x)?, read.clone()),
            Node::Call1(f, s) if pure(f) => {
                let x = Operand::from_node(s)?;
                match (text(f), number(f)) {
                    (Some(t), _) => Self::Text(x, t),
                    (_, Some(n)) => Self::Number(x, n),
                    _ => Self::Call(f.clone(), x, Box::new([])),
                }
            }
            Node::Call(f, args) if pure(f) => {
                let (subject, rest) = args.split_first()?;
                Self::Call(f.clone(), Operand::from_node(subject)?, consts(rest)?)
            }
            Node::Not(x) => Self::Not(Box::new(Self::from_node(x)?)),
            Node::And(xs) => Self::And(Box::new((
                Self::from_node(&xs[0])?,
                Self::from_node(&xs[1])?,
            ))),
            Node::Or(xs) => Self::Or(Box::new((
                Self::from_node(&xs[0])?,
                Self::from_node(&xs[1])?,
            ))),
            _ => return None,
        })
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
            | Self::Call(_, x, _) => x.reads(f),
            Self::Compare2(x, _, y) => {
                x.reads(f);
                y.reads(f);
            }
            Self::Has(x, read) => match x.0.first() {
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

    pub fn eval<'a>(&'a self, this: &Value<'a>) -> Result<bool, Error> {
        match self {
            Self::Compare(x, op, c) => x.with(this, |v| eval::compare_const_bool(*op, v, c)),
            Self::Compare2(x, op, y) => x.with(this, |a| {
                y.with(this, |b| match eval::binary(*op, a, b)? {
                    Value::Bool(b) => Ok(b),
                    _ => unreachable!("comparisons are bools"),
                })
            }),
            Self::Size(x, op, c) => x.with(this, |v| {
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
            Self::Match(x, re) => x.with(this, |v| match v {
                Value::String(s) => Ok(re.is_match(s)),
                other => Err(Error::no_overload("matches", &[other.type_of()])),
            }),
            Self::In(x, items) => x.with(this, |v| {
                Ok(items.iter().any(|c| equals(v, &Value::from_const(c))))
            }),
            Self::Has(x, read) => x.with(this, |v| match v {
                Value::Message(m) => Ok(m.has_read(read)),
                other => Err(Error::new(format!(
                    "type '{}' does not support field selection",
                    other.type_of().name()
                ))),
            }),
            Self::Text(x, test) => x.with(this, |v| match v {
                Value::String(s) => Ok(test(s)),
                other => Err(Error::no_overload("string function", &[other.type_of()])),
            }),
            Self::Number(x, test) => x.with(this, |v| match v {
                Value::Double(d) => Ok(test(*d)),
                other => Err(Error::no_overload("double function", &[other.type_of()])),
            }),
            Self::Call(f, x, consts) => {
                let mut args = [const { Value::Null }; 4];
                args[0] = x.with(this, |v| Ok(v.clone()))?;
                for (slot, c) in args[1..].iter_mut().zip(consts.iter()) {
                    *slot = Value::from_const(c);
                }
                match functions::call(f, &args[..=consts.len()])? {
                    Value::Bool(b) => Ok(b),
                    other => Err(Error::new(format!(
                        "expected a bool, got {}",
                        other.type_of().name()
                    ))),
                }
            }
            Self::Not(p) => p.eval(this).map(|b| !b),
            Self::And(ps) => logic(false, &ps.0, &ps.1, this),
            Self::Or(ps) => logic(true, &ps.0, &ps.1, this),
        }
    }
}

/// `&&` (deciding on false) and `||` (deciding on true): a deciding side
/// absorbs the other's error, as CEL specifies.
fn logic<'a>(decides: bool, a: &'a Pred, b: &'a Pred, this: &Value<'a>) -> Result<bool, Error> {
    let first = a.eval(this);
    if first == Ok(decides) {
        return Ok(decides);
    }
    match (first, b.eval(this)) {
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
