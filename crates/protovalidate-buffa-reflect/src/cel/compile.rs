//! Lowering a parsed expression to a [`Node`] tree.

use std::sync::Arc;

use buffa_descriptor::DescriptorPool;
use cel::common::ast::{
    CallExpr, ComprehensionExpr, EntryExpr, Expr, IdedExpr, LiteralValue, operators as op,
};
use regex::Regex;

use super::{
    Bindings, eval,
    types::Ty,
    value::{Const, Read, Type},
};

/// A compiled expression.
pub enum Node {
    Const(Const),
    This,
    Now,
    Local(u8),
    /// A field of a message whose type is known, by index.
    Field(Box<Self>, u32, Read),
    /// `has()` of a field of a message whose type is known, by index.
    Has(Box<Self>, u32),
    /// A field, or a map entry, by name, resolved when it runs.
    Get(Box<Self>, Box<str>),
    HasName(Box<Self>, Box<str>),
    Not(Box<Self>),
    Neg(Box<Self>),
    And(Box<[Self; 2]>),
    Or(Box<[Self; 2]>),
    Cond(Box<[Self; 3]>),
    Op(Op, Box<[Self; 2]>),
    List(Box<[Self]>),
    Map(Box<[(Self, Self)]>),
    Call(Func, Box<[Self]>),
    Fold(Box<Fold>),
    // Fused forms of the shapes standard rules fold to, each evaluated in one
    // visit rather than one per node.
    /// A comparison of `this` against a constant.
    CompareThis(Op, Box<Const>),
    /// A comparison against a constant.
    Compare(Op, Box<(Self, Const)>),
    /// `cond ? a : b` where both branches are constants.
    Choose(Box<(Self, Const, Const)>),
    /// A function of one argument.
    Call1(Func, Box<Self>),
    /// `matches()` against a pattern compiled once.
    Match(Box<Self>, Box<Regex>),
    /// `int(size(x))` or, when true, `uint(size(x))`.
    Size(Box<Self>, bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Index,
}

/// A comprehension, one of the macros.
pub struct Fold {
    pub kind: FoldKind,
    pub range: Node,
    pub var: u8,
    /// The predicate of `all`, `exists` and `exists_one`; the filter of
    /// `map` and `filter`.
    pub test: Option<Node>,
    /// The transform of `map`; `None` for `filter`.
    pub transform: Option<Node>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FoldKind {
    All,
    Exists,
    ExistsOne,
    Map,
}

/// The functions the tree evaluates itself. Receivers are the first argument.
#[derive(Clone, Debug)]
pub enum Func {
    Size,
    StartsWith,
    EndsWith,
    Contains,
    /// A pattern known when compiling is compiled once.
    Matches(Option<Box<Regex>>),
    IsEmail,
    IsHostname,
    IsIp,
    IsIpPrefix,
    IsUri,
    IsUriRef,
    IsHostAndPort,
    IsNan,
    IsInf,
    Unique,
    GetField,
    ToInt,
    ToUint,
    ToDouble,
    ToString,
    ToBytes,
    ToBool,
    ToDuration,
    ToTimestamp,
    TypeOf,
    Format,
    CharAt,
    IndexOf,
    LastIndexOf,
    LowerAscii,
    UpperAscii,
    Replace,
    Split,
    Substring,
    Trim,
    Join,
    Reverse,
    Time(Time),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Time {
    FullYear,
    Month,
    DayOfYear,
    DayOfMonth,
    Date,
    DayOfWeek,
    Hours,
    Minutes,
    Seconds,
    Milliseconds,
}

/// Why an expression was not lowered.
pub enum Refusal {
    /// The expression is wrong: protovalidate's compilation error.
    Error(String),
    /// The tree cannot express it; the interpreter will run it.
    Unsupported,
}

type Result<T> = std::result::Result<T, Refusal>;

#[expect(clippy::cast_possible_truncation, reason = "a small constant")]
const MAX_LOCALS: u8 = eval::LOCALS as u8;

/// Lowers `e`. `Ok(None)` when the expression folds to a pass.
pub fn compile(e: &IdedExpr, bindings: &Bindings<'_>) -> Result<Option<(Node, usize)>> {
    let mut cx = Compiler {
        pool: bindings.pool,
        bindings,
        locals: Vec::new(),
        next: 0,
        used: 0,
    };
    let (node, ty) = cx.expr(e)?;
    if !matches!(ty, Ty::Bool | Ty::String | Ty::Dyn) {
        return Err(Refusal::Error(format!(
            "expression outputs {}, wanted bool or string",
            ty.name(cx.pool)
        )));
    }
    Ok(match node {
        Node::Const(Const::Bool(true)) => None,
        Node::Const(Const::String(s)) if s.is_empty() => None,
        node => Some((node, usize::from(cx.used))),
    })
}

struct Compiler<'b> {
    pool: &'b Arc<DescriptorPool>,
    bindings: &'b Bindings<'b>,
    locals: Vec<(String, Ty, u8)>,
    next: u8,
    /// The most comprehension variables bound at once.
    used: u8,
}

fn error<T>(message: impl Into<String>) -> Result<T> {
    Err(Refusal::Error(message.into()))
}

impl Compiler<'_> {
    fn expr(&mut self, e: &IdedExpr) -> Result<(Node, Ty)> {
        match &e.expr {
            Expr::Literal(l) => Ok(literal(l)),
            Expr::Ident(name) => self.ident(name),
            Expr::Select(s) => {
                if !s.test
                    && let Some(name) = qualified(e)
                    && let Some(t) = type_name(&name)
                {
                    return Ok((Node::Const(Const::Type(t)), Ty::Type));
                }
                let (operand, ty) = self.expr(&s.operand)?;
                self.select(operand, &ty, &s.field, s.test)
            }
            Expr::Call(c) => self.call(c),
            Expr::List(l) => {
                if !l.optional_indices.is_empty() {
                    return Err(Refusal::Unsupported);
                }
                let mut items = Vec::with_capacity(l.elements.len());
                let mut elem = None;
                for x in &l.elements {
                    let (n, t) = self.expr(x)?;
                    elem = Some(match elem {
                        None => t,
                        Some(prev) if prev == t => prev,
                        Some(_) => Ty::Dyn,
                    });
                    items.push(n);
                }
                Ok(fold(
                    Node::List(items.into()),
                    Ty::List(Box::new(elem.unwrap_or(Ty::Dyn))),
                ))
            }
            Expr::Map(m) => {
                let mut entries = Vec::with_capacity(m.entries.len());
                for entry in &m.entries {
                    let EntryExpr::MapEntry(entry) = &entry.expr else {
                        return Err(Refusal::Unsupported);
                    };
                    if entry.optional {
                        return Err(Refusal::Unsupported);
                    }
                    let (k, _) = self.expr(&entry.key)?;
                    let (v, _) = self.expr(&entry.value)?;
                    entries.push((k, v));
                }
                Ok(fold(
                    Node::Map(entries.into()),
                    Ty::Map(Box::new(Ty::Dyn), Box::new(Ty::Dyn)),
                ))
            }
            Expr::Comprehension(c) => self.comprehension(c),
            Expr::Struct(_) | Expr::Unspecified => Err(Refusal::Unsupported),
        }
    }

    fn ident(&self, name: &str) -> Result<(Node, Ty)> {
        if let Some((_, ty, slot)) = self.locals.iter().rev().find(|(n, ..)| n == name) {
            return Ok((Node::Local(*slot), ty.clone()));
        }
        match name {
            "this" => return Ok((Node::This, self.bindings.this.clone())),
            "now" => return Ok((Node::Now, Ty::Timestamp)),
            _ => {}
        }
        if let Some((_, c)) = self.bindings.consts.iter().find(|(n, _)| *n == name) {
            return Ok((Node::Const(c.clone()), Ty::of_const(c, self.pool)));
        }
        if let Some(t) = type_name(name) {
            return Ok((Node::Const(Const::Type(t)), Ty::Type));
        }
        error(format!("undeclared reference to '{name}'"))
    }

    fn select(&self, operand: Node, ty: &Ty, field: &str, test: bool) -> Result<(Node, Ty)> {
        match ty {
            Ty::Message(idx) => {
                let md = self.pool.message(*idx);
                let Some(index) = md.fields().iter().position(|f| f.name() == field) else {
                    return error(format!("undefined field '{field}' on {}", md.full_name()));
                };
                let fd = &md.fields()[index];
                let index = u32::try_from(index).map_err(|_| Refusal::Unsupported)?;
                Ok(if test {
                    fold(Node::Has(Box::new(operand), index), Ty::Bool)
                } else {
                    fold(
                        Node::Field(Box::new(operand), index, Read::of(fd, self.pool)),
                        Ty::of_field(fd, self.pool),
                    )
                })
            }
            Ty::Map(_, v) => {
                let v = (**v).clone();
                Ok(if test {
                    fold(Node::HasName(Box::new(operand), field.into()), Ty::Bool)
                } else {
                    fold(Node::Get(Box::new(operand), field.into()), v)
                })
            }
            Ty::Dyn => Ok(if test {
                fold(Node::HasName(Box::new(operand), field.into()), Ty::Bool)
            } else {
                fold(Node::Get(Box::new(operand), field.into()), Ty::Dyn)
            }),
            other => error(format!(
                "type '{}' does not support field selection",
                other.name(self.pool)
            )),
        }
    }

    fn call(&mut self, c: &CallExpr) -> Result<(Node, Ty)> {
        let name = c.func_name.as_str();
        match (name, c.target.is_some(), c.args.len()) {
            (op::LOGICAL_AND | op::LOGICAL_OR, false, 2) => {
                let (a, at) = self.expr(&c.args[0])?;
                let (b, bt) = self.expr(&c.args[1])?;
                self.expect(name, &[at, bt], &[Ty::Bool, Ty::Bool])?;
                let and = name == op::LOGICAL_AND;
                Ok((logic(and, a, b), Ty::Bool))
            }
            (op::LOGICAL_NOT, false, 1) => {
                let (a, at) = self.expr(&c.args[0])?;
                self.expect(name, &[at], &[Ty::Bool])?;
                Ok(fold(Node::Not(Box::new(a)), Ty::Bool))
            }
            (op::NOT_STRICTLY_FALSE, false, 1) => Err(Refusal::Unsupported),
            (op::NEGATE, false, 1) => {
                let (a, at) = self.expr(&c.args[0])?;
                if !matches!(at, Ty::Int | Ty::Double | Ty::Dyn | Ty::Duration) {
                    return self.no_overload(name, &[at]);
                }
                Ok(fold(Node::Neg(Box::new(a)), at))
            }
            (op::CONDITIONAL, false, 3) => {
                let (p, pt) = self.expr(&c.args[0])?;
                self.expect(name, &[pt], &[Ty::Bool])?;
                let (t, tt) = self.expr(&c.args[1])?;
                let (f, ft) = self.expr(&c.args[2])?;
                let ty = if tt == ft { tt } else { Ty::Dyn };
                Ok(match p {
                    Node::Const(Const::Bool(true)) => (t, ty),
                    Node::Const(Const::Bool(false)) => (f, ty),
                    p => match (t, f) {
                        (Node::Const(t), Node::Const(f)) => match p {
                            Node::Not(p) => fold(Node::Choose(Box::new((*p, f, t))), ty),
                            p => fold(Node::Choose(Box::new((p, t, f))), ty),
                        },
                        (t, f) => fold(Node::Cond(Box::new([p, t, f])), ty),
                    },
                })
            }
            (
                op::ADD
                | op::SUBSTRACT
                | op::MULTIPLY
                | op::DIVIDE
                | op::MODULO
                | op::EQUALS
                | op::NOT_EQUALS
                | op::LESS
                | op::LESS_EQUALS
                | op::GREATER
                | op::GREATER_EQUALS
                | op::IN
                | op::INDEX,
                false,
                2,
            ) => {
                let (a, at) = self.expr(&c.args[0])?;
                let (b, bt) = self.expr(&c.args[1])?;
                let o = binary_op(name);
                let ty = self.binary_type(name, o, &at, &bt)?;
                Ok(fold(binary(o, a, b), ty))
            }
            ("dyn", false, 1) => {
                let (a, _) = self.expr(&c.args[0])?;
                Ok((a, Ty::Dyn))
            }
            _ => self.function(c),
        }
    }

    fn function(&mut self, c: &CallExpr) -> Result<(Node, Ty)> {
        let member = c.target.is_some();
        let Some(func) = function(&c.func_name, member) else {
            return Err(Refusal::Unsupported);
        };
        let mut args: Vec<Node> = Vec::with_capacity(c.args.len() + 1);
        let mut tys = Vec::with_capacity(c.args.len() + 1);
        for x in c.target.iter().map(|t| &**t).chain(&c.args) {
            let (n, t) = self.expr(x)?;
            args.push(n);
            tys.push(t);
        }
        let ty = self.signature(&func, &c.func_name, &tys)?;
        let func = match func {
            Func::Matches(None) => match &args[1] {
                Node::Const(Const::String(p)) => {
                    let re = Regex::new(p).map_err(|e| {
                        Refusal::Error(format!("invalid regular expression `{p}`: {e}"))
                    })?;
                    Func::Matches(Some(Box::new(re)))
                }
                _ => Func::Matches(None),
            },
            f => f,
        };
        let node = match (func, args.len()) {
            (Func::Matches(Some(re)), 2) => {
                args.truncate(1);
                Node::Match(Box::new(args.pop().expect("a subject")), re)
            }
            (f @ (Func::ToInt | Func::ToUint), 1) => match args.pop().expect("one argument") {
                Node::Call1(Func::Size, x) => Node::Size(x, matches!(f, Func::ToUint)),
                x => Node::Call1(f, Box::new(x)),
            },
            (f, 1) => Node::Call1(f, Box::new(args.pop().expect("one argument"))),
            (f, _) => Node::Call(f, args.into()),
        };
        Ok(fold(node, ty))
    }

    fn expect(&self, name: &str, got: &[Ty], want: &[Ty]) -> Result<()> {
        if got.iter().zip(want).all(|(g, w)| g.admits(w)) {
            Ok(())
        } else {
            self.no_overload::<()>(name, got)
        }
    }

    fn no_overload<T>(&self, name: &str, args: &[Ty]) -> Result<T> {
        let args: Vec<_> = args.iter().map(|t| t.name(self.pool)).collect();
        error(format!(
            "found no matching overload for '{name}' applied to '({})'",
            args.join(", ")
        ))
    }

    #[expect(clippy::many_single_char_names, reason = "a table of operand types")]
    fn binary_type(&self, name: &str, o: Op, a: &Ty, b: &Ty) -> Result<Ty> {
        use Ty as T;
        let either_dyn = a.is_dyn() || b.is_dyn();
        Ok(match o {
            Op::Eq | Op::Ne => T::Bool,
            Op::Lt | Op::Le | Op::Gt | Op::Ge => {
                let ok = either_dyn
                    || (a.is_number() && b.is_number())
                    || (a == b
                        && matches!(
                            a,
                            T::Bool | T::String | T::Bytes | T::Duration | T::Timestamp
                        ));
                if !ok {
                    return self.no_overload(name, &[a.clone(), b.clone()]);
                }
                T::Bool
            }
            Op::In => match b {
                T::List(_) | T::Map(..) | T::Dyn => T::Bool,
                _ => return self.no_overload(name, &[a.clone(), b.clone()]),
            },
            Op::Index => match (a, b) {
                (T::List(e), T::Int | T::Uint | T::Dyn) => (**e).clone(),
                (T::Map(_, v), _) => (**v).clone(),
                (T::Dyn, _) => T::Dyn,
                _ => return self.no_overload(name, &[a.clone(), b.clone()]),
            },
            Op::Add => match (a, b) {
                (T::Dyn, t) | (t, T::Dyn) => match t {
                    T::Duration => T::Dyn,
                    t => t.clone(),
                },
                (T::Int, T::Int) => T::Int,
                (T::Uint, T::Uint) => T::Uint,
                (T::Double, T::Double) => T::Double,
                (T::String, T::String) => T::String,
                (T::Bytes, T::Bytes) => T::Bytes,
                (T::List(x), T::List(y)) => {
                    T::List(Box::new(if x == y { (**x).clone() } else { T::Dyn }))
                }
                (T::Duration, T::Duration) => T::Duration,
                (T::Timestamp, T::Duration) | (T::Duration, T::Timestamp) => T::Timestamp,
                _ => return self.no_overload(name, &[a.clone(), b.clone()]),
            },
            Op::Sub => match (a, b) {
                (T::Dyn, _) | (_, T::Dyn) => T::Dyn,
                (T::Int, T::Int) => T::Int,
                (T::Uint, T::Uint) => T::Uint,
                (T::Double, T::Double) => T::Double,
                (T::Duration, T::Duration) | (T::Timestamp, T::Timestamp) => T::Duration,
                (T::Timestamp, T::Duration) => T::Timestamp,
                _ => return self.no_overload(name, &[a.clone(), b.clone()]),
            },
            Op::Mul | Op::Div => match (a, b) {
                (T::Dyn, t) | (t, T::Dyn) if t.is_number() => t.clone(),
                (T::Int, T::Int) => T::Int,
                (T::Uint, T::Uint) => T::Uint,
                (T::Double, T::Double) => T::Double,
                _ => return self.no_overload(name, &[a.clone(), b.clone()]),
            },
            Op::Rem => match (a, b) {
                (T::Dyn, t) | (t, T::Dyn) if matches!(t, T::Int | T::Uint | T::Dyn) => t.clone(),
                (T::Int, T::Int) => T::Int,
                (T::Uint, T::Uint) => T::Uint,
                _ => return self.no_overload(name, &[a.clone(), b.clone()]),
            },
        })
    }

    /// Checks a call's arguments against the function's overloads.
    #[expect(clippy::too_many_lines, reason = "one arm per function's overloads")]
    fn signature(&self, func: &Func, name: &str, args: &[Ty]) -> Result<Ty> {
        use Ty as T;
        let fits = |want: &[&[T]]| {
            want.iter().any(|w| {
                w.len() == args.len() && args.iter().zip(w.iter()).all(|(a, w)| a.admits(w))
            })
        };
        let string = || T::List(Box::new(T::String));
        let (ok, out) = match func {
            Func::Size => (
                args.len() == 1
                    && matches!(
                        args[0],
                        T::String | T::Bytes | T::List(_) | T::Map(..) | T::Dyn
                    ),
                T::Int,
            ),
            Func::StartsWith | Func::EndsWith | Func::Contains => (
                fits(&[&[T::String, T::String], &[T::Bytes, T::Bytes]]),
                T::Bool,
            ),
            Func::Matches(_) => (fits(&[&[T::String, T::String]]), T::Bool),
            Func::IsEmail | Func::IsHostname | Func::IsUri | Func::IsUriRef => {
                (fits(&[&[T::String]]), T::Bool)
            }
            Func::IsIp => (fits(&[&[T::String], &[T::String, T::Int]]), T::Bool),
            Func::IsIpPrefix => (
                fits(&[
                    &[T::String],
                    &[T::String, T::Int],
                    &[T::String, T::Bool],
                    &[T::String, T::Int, T::Bool],
                ]),
                T::Bool,
            ),
            Func::IsHostAndPort => (fits(&[&[T::String, T::Bool]]), T::Bool),
            Func::IsNan => (fits(&[&[T::Double]]), T::Bool),
            Func::IsInf => (fits(&[&[T::Double], &[T::Double, T::Int]]), T::Bool),
            Func::Unique => (
                args.len() == 1
                    && match &args[0] {
                        T::List(e) => matches!(
                            **e,
                            T::Bool | T::Int | T::Uint | T::Double | T::String | T::Bytes | T::Dyn
                        ),
                        T::Dyn => true,
                        _ => false,
                    },
                T::Bool,
            ),
            Func::GetField => (fits(&[&[T::Dyn, T::String]]), T::Dyn),
            Func::ToInt => (
                fits(&[
                    &[T::Int],
                    &[T::Uint],
                    &[T::Double],
                    &[T::String],
                    &[T::Timestamp],
                    &[T::Duration],
                ]),
                T::Int,
            ),
            Func::ToUint => (
                fits(&[&[T::Int], &[T::Uint], &[T::Double], &[T::String]]),
                T::Uint,
            ),
            Func::ToDouble => (
                fits(&[&[T::Int], &[T::Uint], &[T::Double], &[T::String]]),
                T::Double,
            ),
            Func::ToString => (args.len() == 1, T::String),
            Func::ToBytes => (fits(&[&[T::String], &[T::Bytes]]), T::Bytes),
            Func::ToBool => (fits(&[&[T::Bool], &[T::String]]), T::Bool),
            Func::ToDuration => (fits(&[&[T::String], &[T::Duration]]), T::Duration),
            Func::ToTimestamp => (
                fits(&[&[T::String], &[T::Timestamp], &[T::Int]]),
                T::Timestamp,
            ),
            Func::TypeOf => (args.len() == 1, T::Type),
            Func::Format => (fits(&[&[T::String, T::List(Box::new(T::Dyn))]]), T::String),
            Func::CharAt => (fits(&[&[T::String, T::Int]]), T::String),
            Func::IndexOf | Func::LastIndexOf => (
                fits(&[&[T::String, T::String], &[T::String, T::String, T::Int]]),
                T::Int,
            ),
            Func::LowerAscii | Func::UpperAscii | Func::Trim | Func::Reverse => {
                (fits(&[&[T::String]]), T::String)
            }
            Func::Replace => (
                fits(&[
                    &[T::String, T::String, T::String],
                    &[T::String, T::String, T::String, T::Int],
                ]),
                T::String,
            ),
            Func::Split => (
                fits(&[&[T::String, T::String], &[T::String, T::String, T::Int]]),
                string(),
            ),
            Func::Substring => (
                fits(&[&[T::String, T::Int], &[T::String, T::Int, T::Int]]),
                T::String,
            ),
            Func::Join => (fits(&[&[string()], &[string(), T::String]]), T::String),
            Func::Time(t) => {
                let ok = if *t == Time::Milliseconds
                    || matches!(t, Time::Hours | Time::Minutes | Time::Seconds)
                {
                    fits(&[&[T::Timestamp], &[T::Timestamp, T::String], &[T::Duration]])
                } else {
                    fits(&[&[T::Timestamp], &[T::Timestamp, T::String]])
                };
                (ok, T::Int)
            }
        };
        if ok {
            Ok(out)
        } else {
            self.no_overload(name, args)
        }
    }

    fn comprehension(&mut self, c: &ComprehensionExpr) -> Result<(Node, Ty)> {
        if c.iter_var2.is_some() {
            return Err(Refusal::Unsupported);
        }
        let shape = macro_shape(c).ok_or(Refusal::Unsupported)?;
        let (range, range_ty) = self.expr(&c.iter_range)?;
        let var_ty = match &range_ty {
            Ty::List(e) => (**e).clone(),
            Ty::Map(k, _) => (**k).clone(),
            Ty::Dyn => Ty::Dyn,
            other => {
                return error(format!(
                    "expression of type '{}' cannot be the range of a comprehension",
                    other.name(self.pool)
                ));
            }
        };
        if self.next >= MAX_LOCALS {
            return Err(Refusal::Unsupported);
        }
        let var = self.next;
        self.next += 1;
        self.used = self.used.max(self.next);
        self.locals.push((c.iter_var.clone(), var_ty, var));
        let result = self.comprehension_body(&shape);
        self.locals.pop();
        self.next -= 1;
        let (kind, test, transform, ty) = result?;
        let comprehension = Fold {
            kind,
            range,
            var,
            test,
            transform,
        };
        Ok(fold(Node::Fold(Box::new(comprehension)), ty))
    }

    fn comprehension_body(
        &mut self,
        shape: &Shape<'_>,
    ) -> Result<(FoldKind, Option<Node>, Option<Node>, Ty)> {
        Ok(match *shape {
            Shape::All(p) | Shape::Exists(p) | Shape::ExistsOne(p) => {
                let (test, ty) = self.expr(p)?;
                self.expect("predicate", &[ty], &[Ty::Bool])?;
                let kind = match shape {
                    Shape::All(_) => FoldKind::All,
                    Shape::Exists(_) => FoldKind::Exists,
                    _ => FoldKind::ExistsOne,
                };
                (kind, Some(test), None, Ty::Bool)
            }
            Shape::Map { filter, transform } => {
                let test = match filter {
                    Some(f) => {
                        let (n, ty) = self.expr(f)?;
                        self.expect("filter", &[ty], &[Ty::Bool])?;
                        Some(n)
                    }
                    None => None,
                };
                let (transform, ty) = self.expr(transform)?;
                (FoldKind::Map, test, Some(transform), Ty::List(Box::new(ty)))
            }
        })
    }
}

/// Replaces a node whose inputs are all known with its value.
fn fold(node: Node, ty: Ty) -> (Node, Ty) {
    if !closed(&node, 0) {
        return (node, ty);
    }
    match eval::constant(&node) {
        Ok(v) => (Node::Const(v.to_const()), ty),
        Err(_) => (node, ty),
    }
}

/// A binary operation; a comparison against a constant is fused.
fn binary(o: Op, a: Node, b: Node) -> Node {
    if !matches!(o, Op::Eq | Op::Ne | Op::Lt | Op::Le | Op::Gt | Op::Ge) {
        return Node::Op(o, Box::new([a, b]));
    }
    match (a, b) {
        (a @ Node::Const(_), b @ Node::Const(_)) => Node::Op(o, Box::new([a, b])),
        (Node::This, Node::Const(c)) => Node::CompareThis(o, Box::new(c)),
        (Node::Const(c), Node::This) => Node::CompareThis(flip(o), Box::new(c)),
        (a, Node::Const(c)) => Node::Compare(o, Box::new((a, c))),
        (Node::Const(c), b) => Node::Compare(flip(o), Box::new((b, c))),
        pair => Node::Op(o, Box::new(pair.into())),
    }
}

/// The comparison with its operands swapped.
const fn flip(o: Op) -> Op {
    match o {
        Op::Lt => Op::Gt,
        Op::Le => Op::Ge,
        Op::Gt => Op::Lt,
        Op::Ge => Op::Le,
        o => o,
    }
}

fn logic(and: bool, a: Node, b: Node) -> Node {
    let absorbing = !and;
    match (a, b) {
        (Node::Const(Const::Bool(x)), _) | (_, Node::Const(Const::Bool(x))) if x == absorbing => {
            Node::Const(Const::Bool(absorbing))
        }
        (Node::Const(Const::Bool(_)), n) | (n, Node::Const(Const::Bool(_))) => n,
        pair if and => Node::And(Box::new(pair.into())),
        pair => Node::Or(Box::new(pair.into())),
    }
}

/// Whether a node reads nothing but constants and the locals in `bound`.
fn closed(n: &Node, bound: u16) -> bool {
    match n {
        Node::Const(_) => true,
        Node::This | Node::Now | Node::CompareThis(..) => false,
        Node::Local(s) => bound & (1 << s) != 0,
        Node::Field(x, ..)
        | Node::Has(x, _)
        | Node::Get(x, _)
        | Node::HasName(x, _)
        | Node::Not(x)
        | Node::Neg(x)
        | Node::Call1(_, x)
        | Node::Match(x, _)
        | Node::Size(x, _) => closed(x, bound),
        Node::And(xs) | Node::Or(xs) | Node::Op(_, xs) => xs.iter().all(|x| closed(x, bound)),
        Node::Cond(xs) => xs.iter().all(|x| closed(x, bound)),
        Node::List(xs) | Node::Call(_, xs) => xs.iter().all(|x| closed(x, bound)),
        Node::Map(es) => es.iter().all(|(k, v)| closed(k, bound) && closed(v, bound)),
        Node::Compare(_, x) => closed(&x.0, bound),
        Node::Choose(x) => closed(&x.0, bound),
        Node::Fold(f) => {
            let inner = bound | (1 << f.var);
            closed(&f.range, bound)
                && f.test.as_ref().is_none_or(|t| closed(t, inner))
                && f.transform.as_ref().is_none_or(|t| closed(t, inner))
        }
    }
}

enum Shape<'e> {
    All(&'e IdedExpr),
    Exists(&'e IdedExpr),
    ExistsOne(&'e IdedExpr),
    Map {
        filter: Option<&'e IdedExpr>,
        transform: &'e IdedExpr,
    },
}

/// A call without a receiver.
const fn call(e: &IdedExpr) -> Option<&CallExpr> {
    match &e.expr {
        Expr::Call(call) if call.target.is_none() => Some(call),
        _ => None,
    }
}

/// Recognizes the comprehensions `cel`'s macros expand to.
fn macro_shape(c: &ComprehensionExpr) -> Option<Shape<'_>> {
    let accu = c.accu_var.as_str();
    let is_accu = |e: &IdedExpr| matches!(&e.expr, Expr::Ident(n) if n == accu);
    let lit_bool = |e: &IdedExpr| match &e.expr {
        Expr::Literal(LiteralValue::Boolean(b)) => Some(bool::from(*b)),
        _ => None,
    };
    let step = call(&c.loop_step)?;
    match (&c.accu_init.expr, step.func_name.as_str()) {
        (Expr::Literal(LiteralValue::Boolean(b)), op::LOGICAL_AND)
            if bool::from(*b) && is_accu(&c.result) && is_accu(&step.args[0]) =>
        {
            Some(Shape::All(&step.args[1]))
        }
        (Expr::Literal(LiteralValue::Boolean(b)), op::LOGICAL_OR)
            if !bool::from(*b) && is_accu(&c.result) && is_accu(&step.args[0]) =>
        {
            Some(Shape::Exists(&step.args[1]))
        }
        (Expr::Literal(LiteralValue::Int(_)), op::CONDITIONAL)
            if lit_bool(&c.loop_cond) == Some(true) =>
        {
            Some(Shape::ExistsOne(&step.args[0]))
        }
        (Expr::List(l), op::ADD) if l.elements.is_empty() && is_accu(&step.args[0]) => {
            let Expr::List(item) = &step.args[1].expr else {
                return None;
            };
            Some(Shape::Map {
                filter: None,
                transform: item.elements.first()?,
            })
        }
        (Expr::List(l), op::CONDITIONAL) if l.elements.is_empty() && is_accu(&step.args[2]) => {
            let add = call(&step.args[1])?;
            if add.func_name != op::ADD || !is_accu(&add.args[0]) {
                return None;
            }
            let Expr::List(item) = &add.args[1].expr else {
                return None;
            };
            Some(Shape::Map {
                filter: Some(&step.args[0]),
                transform: item.elements.first()?,
            })
        }
        _ => None,
    }
}

fn literal(l: &LiteralValue) -> (Node, Ty) {
    let (c, t) = match l {
        LiteralValue::Boolean(b) => (Const::Bool(bool::from(*b)), Ty::Bool),
        LiteralValue::Int(i) => (Const::Int(*i.inner()), Ty::Int),
        LiteralValue::UInt(u) => (Const::Uint(u64::from(*u)), Ty::Uint),
        LiteralValue::Double(d) => (Const::Double(*d.inner()), Ty::Double),
        LiteralValue::String(s) => (Const::String(s.inner().into()), Ty::String),
        LiteralValue::Bytes(b) => (Const::Bytes(b.inner().into()), Ty::Bytes),
        LiteralValue::Null => (Const::Null, Ty::Null),
    };
    (Node::Const(c), t)
}

fn qualified(e: &IdedExpr) -> Option<String> {
    match &e.expr {
        Expr::Ident(n) => Some(n.clone()),
        Expr::Select(s) if !s.test => Some(format!("{}.{}", qualified(&s.operand)?, s.field)),
        _ => None,
    }
}

fn type_name(name: &str) -> Option<Type> {
    Some(match name {
        "bool" => Type::Bool,
        "int" => Type::Int,
        "uint" => Type::Uint,
        "double" => Type::Double,
        "string" => Type::String,
        "bytes" => Type::Bytes,
        "list" => Type::List,
        "map" => Type::Map,
        "null_type" => Type::Null,
        "type" => Type::Type,
        "google.protobuf.Duration" => Type::Duration,
        "google.protobuf.Timestamp" => Type::Timestamp,
        _ => return None,
    })
}

fn binary_op(name: &str) -> Op {
    match name {
        op::ADD => Op::Add,
        op::SUBSTRACT => Op::Sub,
        op::MULTIPLY => Op::Mul,
        op::DIVIDE => Op::Div,
        op::MODULO => Op::Rem,
        op::EQUALS => Op::Eq,
        op::NOT_EQUALS => Op::Ne,
        op::LESS => Op::Lt,
        op::LESS_EQUALS => Op::Le,
        op::GREATER => Op::Gt,
        op::GREATER_EQUALS => Op::Ge,
        op::IN => Op::In,
        _ => Op::Index,
    }
}

fn function(name: &str, member: bool) -> Option<Func> {
    Some(match (name, member) {
        ("size", _) => Func::Size,
        ("startsWith", true) => Func::StartsWith,
        ("endsWith", true) => Func::EndsWith,
        ("contains", true) => Func::Contains,
        ("matches", _) => Func::Matches(None),
        ("isEmail", true) => Func::IsEmail,
        ("isHostname", true) => Func::IsHostname,
        ("isIp", true) => Func::IsIp,
        ("isIpPrefix", true) => Func::IsIpPrefix,
        ("isUri", true) => Func::IsUri,
        ("isUriRef", true) => Func::IsUriRef,
        ("isHostAndPort", true) => Func::IsHostAndPort,
        ("isNan", true) => Func::IsNan,
        ("isInf", true) => Func::IsInf,
        ("unique", true) => Func::Unique,
        ("getField", false) => Func::GetField,
        ("int", false) => Func::ToInt,
        ("uint", false) => Func::ToUint,
        ("double", false) => Func::ToDouble,
        ("string", false) => Func::ToString,
        ("bytes", false) => Func::ToBytes,
        ("bool", false) => Func::ToBool,
        ("duration", false) => Func::ToDuration,
        ("timestamp", false) => Func::ToTimestamp,
        ("type", false) => Func::TypeOf,
        ("format", true) => Func::Format,
        ("charAt", true) => Func::CharAt,
        ("indexOf", true) => Func::IndexOf,
        ("lastIndexOf", true) => Func::LastIndexOf,
        ("lowerAscii", true) => Func::LowerAscii,
        ("upperAscii", true) => Func::UpperAscii,
        ("replace", true) => Func::Replace,
        ("split", true) => Func::Split,
        ("substring", true) => Func::Substring,
        ("trim", true) => Func::Trim,
        ("join", true) => Func::Join,
        ("reverse", true) => Func::Reverse,
        ("getFullYear", true) => Func::Time(Time::FullYear),
        ("getMonth", true) => Func::Time(Time::Month),
        ("getDayOfYear", true) => Func::Time(Time::DayOfYear),
        ("getDayOfMonth", true) => Func::Time(Time::DayOfMonth),
        ("getDate", true) => Func::Time(Time::Date),
        ("getDayOfWeek", true) => Func::Time(Time::DayOfWeek),
        ("getHours", true) => Func::Time(Time::Hours),
        ("getMinutes", true) => Func::Time(Time::Minutes),
        ("getSeconds", true) => Func::Time(Time::Seconds),
        ("getMilliseconds", true) => Func::Time(Time::Milliseconds),
        _ => return None,
    })
}
