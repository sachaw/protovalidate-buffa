//! CEL, compiled once against the descriptors into a typed tree.
//!
//! A rule's expression is parsed by `cel`, checked against the message types
//! it reads (an unknown field or an impossible call is a compilation error,
//! as in protovalidate's other implementations), and lowered to a [`Node`]
//! tree in which field names are field indices and the rule's own values
//! (`rules`, `rule`) are folded in as constants. A tree that tests only
//! `this` and its fields, as standard rules fold to, runs as a native check
//! ([`pred`]). Evaluating either reads the message through reflection and
//! allocates only to build a value (a concatenation, a violation message).
//!
//! What the tree does not express (optional values, and functions outside
//! protovalidate's library) is handed whole to the `cel` interpreter, so
//! every expression `cel` can run still runs.

mod compile;
mod eval;
mod fallback;
mod format;
mod functions;
mod pred;
#[cfg(test)]
mod tests;
mod types;
pub mod value;

use std::{borrow::Cow, cell::Cell, fmt, sync::Arc};

use buffa_descriptor::DescriptorPool;
use chrono::{DateTime, Utc};
pub use types::Ty;
use value::{Const, Str, Value};

/// An evaluation error: CEL's error value, reported as a runtime error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error(Cow<'static, str>);

impl Error {
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self(message.into())
    }

    pub fn no_overload(function: &str, args: &[value::Type]) -> Self {
        let args: Vec<_> = args.iter().map(|t| t.name()).collect();
        Self(format!("no such overload: {function}({})", args.join(", ")).into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A rule's expression that cannot be compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileError(pub String);

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The values an expression can see besides comprehension variables.
pub struct Bindings<'b> {
    pub pool: &'b Arc<DescriptorPool>,
    /// The type of `this`.
    pub this: Ty,
    /// `rules` and `rule`, when the expression belongs to a standard or
    /// predefined rule.
    pub consts: &'b [(&'static str, Const)],
}

/// One validation's view of the clock: `now` reads the same instant
/// everywhere in a validation.
#[derive(Default)]
pub struct Clock(Cell<Option<DateTime<Utc>>>);

impl Clock {
    pub fn now(&self) -> DateTime<Utc> {
        if let Some(now) = self.0.get() {
            return now;
        }
        let now = Utc::now();
        self.0.set(Some(now));
        now
    }
}

/// What a rule's expression decided.
pub enum Outcome<'a> {
    Pass,
    /// Failed; the message, when the expression produced one.
    Fail(Option<Str<'a>>),
}

/// A compiled expression.
pub struct Program(Kind);

enum Kind {
    /// A test of `this` alone, as a native check.
    Check(pred::Check),
    /// The tree, and how many comprehension variables it binds.
    Native(compile::Node, usize),
    Fallback(fallback::Program),
}

impl Program {
    /// Compiles `source`. `Ok(None)` is an expression that can never fail
    /// once its constants are folded in, and needs no evaluation.
    pub fn compile(source: &str, bindings: &Bindings<'_>) -> Result<Option<Self>, CompileError> {
        let ast = fallback::parser()
            .parse(source)
            .map_err(|e| CompileError(format!("failed to parse `{source}`: {e}")))?;
        match compile::compile(&ast, bindings) {
            Ok(node) => Ok(node.map(|(n, locals)| {
                Self(pred::Check::from_node(&n).map_or(Kind::Native(n, locals), Kind::Check))
            })),
            Err(compile::Refusal::Error(e)) => Err(CompileError(format!("`{source}`: {e}"))),
            Err(compile::Refusal::Unsupported) => {
                fallback::Program::compile(source, bindings).map(|p| Some(Self(Kind::Fallback(p))))
            }
        }
    }

    pub fn eval<'a>(&'a self, this: &Value<'a>, clock: &Clock) -> Result<Outcome<'a>, Error> {
        let result = match &self.0 {
            Kind::Check(check) => {
                return Ok(if check.pred.eval(this)? == check.fails_when {
                    Outcome::Fail(check.message.as_deref().map(Str::Ref))
                } else {
                    Outcome::Pass
                });
            }
            Kind::Native(node, locals) => eval::run(node, *locals, this, clock)?,
            Kind::Fallback(program) => return program.eval(this, clock),
        };
        outcome(result)
    }

    /// Calls `f` with the number of each field of `this` the expression
    /// reads directly; the interpreter's reads are not known.
    pub fn reads(&self, f: &mut dyn FnMut(u32)) {
        match &self.0 {
            Kind::Check(check) => check.pred.reads(f),
            Kind::Native(node, _) => node.reads(f),
            Kind::Fallback(_) => {}
        }
    }

    /// Whether this expression runs on the interpreter.
    #[cfg(test)]
    pub const fn is_fallback(&self) -> bool {
        matches!(self.0, Kind::Fallback(_))
    }
}

fn outcome(result: Value<'_>) -> Result<Outcome<'_>, Error> {
    match result {
        Value::Bool(true) => Ok(Outcome::Pass),
        Value::Bool(false) => Ok(Outcome::Fail(None)),
        Value::String(s) if s.is_empty() => Ok(Outcome::Pass),
        Value::String(s) => Ok(Outcome::Fail(Some(s))),
        other => Err(Error::new(format!(
            "expression outputs {}, wanted bool or string",
            other.type_of().name()
        ))),
    }
}
