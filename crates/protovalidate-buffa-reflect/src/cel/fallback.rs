//! Expressions the tree does not express, run on the `cel` interpreter.
//!
//! Messages are bound lazily through `cel`'s `Indexer`; lists and maps are
//! converted when bound. This path allocates per evaluation, and is only
//! taken by expressions outside what [`super::compile`] lowers.

use std::{
    collections::{HashMap, HashSet},
    rc::Rc,
    sync::{Arc, LazyLock},
};

use cel::{
    Context, Env, ExecutionError,
    common::{
        ast::{Expr, IdedExpr},
        traits::Indexer,
        types::{
            CelBool, CelBytes, CelDouble, CelDuration, CelInt, CelList, CelMap, CelMapKey as Key,
            CelNull, CelString, CelTimestamp, CelUInt, Kind, Type,
        },
        value::{CowVal, Val},
    },
    context::VariableResolver,
};

use super::{
    Bindings, Clock, CompileError, Error, Outcome,
    compile::Func,
    functions,
    value::{Bin, Const, List, Map, Msg, Str, Value},
};

pub struct Program {
    program: cel::Program,
    /// Fields read through `has()`; see [`MsgVal`].
    has: HashSet<String>,
    consts: Vec<(&'static str, Const)>,
}

static ENV: LazyLock<Arc<Env>> = LazyLock::new(|| Arc::new(env()));

/// The interpreter's parser, so both paths accept the same syntax.
pub fn parser() -> cel::parser::Parser {
    ENV.parser()
}

impl Program {
    pub fn compile(source: &str, bindings: &Bindings<'_>) -> Result<Self, CompileError> {
        let program = ENV
            .compile(source)
            .map_err(|e| CompileError(format!("failed to parse `{source}`: {e}")))?;
        let mut has = HashSet::new();
        presence_tested(program.expression(), &mut has);
        Ok(Self {
            program,
            has,
            consts: bindings.consts.to_vec(),
        })
    }

    #[inline(never)]
    pub fn eval<'a>(&'a self, this: &Value<'a>, clock: &Clock) -> Result<Outcome<'a>, Error> {
        let mut vars: Vec<(&str, Box<dyn Val + '_>)> = vec![
            ("this", to_val(this, &self.has)),
            (
                "now",
                Box::new(CelTimestamp::from(clock.now().fixed_offset())),
            ),
        ];
        for (name, c) in &self.consts {
            vars.push((name, to_val(&Value::from_const(c), &self.has)));
        }
        let bind = Bind { vars };
        let mut cx = Context::with_env(Arc::clone(&ENV));
        // SAFETY: the context only reads the resolver while `execute` runs,
        // and is dropped before `bind`.
        let resolver: &'static Bind<'static> = unsafe { std::mem::transmute(&bind) };
        cx.set_variable_resolver(resolver);
        let result = self.program.execute(&cx);
        drop(cx);
        match result {
            Ok(cel::Value::Bool(true)) => Ok(Outcome::Pass),
            Ok(cel::Value::Bool(false)) => Ok(Outcome::Fail(None)),
            Ok(cel::Value::String(s)) if s.is_empty() => Ok(Outcome::Pass),
            Ok(cel::Value::String(s)) => Ok(Outcome::Fail(Some(Str::Rc(Rc::from(s.as_str()))))),
            Ok(other) => Err(Error::new(format!(
                "expression outputs {other:?}, wanted bool or string"
            ))),
            Err(e) => Err(Error::new(e.to_string())),
        }
    }
}

struct Bind<'a> {
    vars: Vec<(&'a str, Box<dyn Val + 'a>)>,
}

// SAFETY: a `Bind` is made, read and dropped by one thread, in one
// evaluation; `cel` requires the bound for resolvers it may share.
unsafe impl Send for Bind<'_> {}
unsafe impl Sync for Bind<'_> {}

impl VariableResolver for Bind<'_> {
    fn resolve<'b>(&'b self, variable: &str) -> Option<CowVal<'b, 'b>> {
        self.vars
            .iter()
            .find(|(n, _)| *n == variable)
            .map(|(_, v)| CowVal::Borrowed(&**v))
    }
}

/// The field names an expression tests with `has()`. `cel` reads a
/// successful `Indexer::get` as presence, so such a field must be missing
/// when unset, while any other must read as its default.
fn presence_tested(e: &IdedExpr, out: &mut HashSet<String>) {
    match &e.expr {
        Expr::Select(s) => {
            if s.test {
                out.insert(s.field.clone());
            }
            presence_tested(&s.operand, out);
        }
        Expr::Call(c) => {
            if let Some(t) = &c.target {
                presence_tested(t, out);
            }
            c.args.iter().for_each(|a| presence_tested(a, out));
        }
        Expr::Comprehension(c) => {
            for x in [
                &c.iter_range,
                &c.accu_init,
                &c.loop_cond,
                &c.loop_step,
                &c.result,
            ] {
                presence_tested(x, out);
            }
        }
        Expr::List(l) => l.elements.iter().for_each(|x| presence_tested(x, out)),
        _ => {}
    }
}

fn to_val<'a>(v: &Value<'a>, has: &'a HashSet<String>) -> Box<dyn Val + 'a> {
    match v {
        Value::Null => Box::new(CelNull),
        Value::Bool(b) => Box::new(CelBool::from(*b)),
        Value::Int(i) => Box::new(CelInt::from(*i)),
        Value::Uint(u) => Box::new(CelUInt::from(*u)),
        Value::Double(d) => Box::new(CelDouble::from(*d)),
        Value::String(s) => Box::new(CelString::from((**s).to_owned())),
        Value::Bytes(b) => Box::new(CelBytes::from(b.to_vec())),
        Value::Duration(d) => Box::new(CelDuration::from(*d)),
        Value::Timestamp(t) => Box::new(CelTimestamp::from(t.fixed_offset())),
        Value::Type(t) => Box::new(CelString::from(t.name())),
        Value::Message(m) => Box::new(MsgVal { m: m.clone(), has }),
        Value::List(l) => {
            let items: Vec<_> = (0..l.len())
                .filter_map(|i| l.get(i))
                .map(|item| to_val(&item, has))
                .collect();
            Box::new(CelList::from(items))
        }
        Value::Map(m) => {
            let mut entries: HashMap<Key<'a>, Box<dyn Val + 'a>> = HashMap::with_capacity(m.len());
            m.for_each(&mut |k, v| {
                let key = match k {
                    Value::Bool(b) => Key::from(b),
                    Value::Int(i) => Key::from(i),
                    Value::Uint(u) => Key::from(u),
                    Value::String(s) => Key::from((*s).to_owned()),
                    _ => return true,
                };
                entries.insert(key, to_val(&v, has));
                true
            });
            Box::new(CelMap::from(entries))
        }
    }
}

static MESSAGE_TYPE: Type = Type::simple_type(Kind::Struct, "message");

/// A message, read lazily by field name.
struct MsgVal<'a> {
    m: Msg<'a>,
    has: &'a HashSet<String>,
}

// SAFETY: as for `Bind`.
unsafe impl Send for MsgVal<'_> {}
unsafe impl Sync for MsgVal<'_> {}

impl std::fmt::Debug for MsgVal<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{{..}}", self.m.descriptor().full_name())
    }
}

impl Val for MsgVal<'_> {
    fn get_type(&self) -> &Type {
        &MESSAGE_TYPE
    }

    fn cel_type() -> &'static Type {
        &MESSAGE_TYPE
    }

    fn as_indexer<'b, 'v>(&'b self) -> Option<&'b (dyn Indexer + 'v)>
    where
        Self: 'v,
    {
        Some(self)
    }

    fn clone_as_boxed<'v>(&self) -> Box<dyn Val + 'v>
    where
        Self: 'v,
    {
        Box::new(MsgVal {
            m: self.m.clone(),
            has: self.has,
        })
    }

    fn equals(&self, other: &dyn Val) -> bool {
        let _ = other;
        false
    }
}

impl Indexer for MsgVal<'_> {
    fn get<'b, 'v>(&'b self, idx: &dyn Val) -> Result<CowVal<'b, 'v>, ExecutionError>
    where
        Self: 'v,
    {
        let name: &str = <&str>::try_from(idx).unwrap_or_default();
        let Some(fd) = self.m.descriptor().field_by_name(name) else {
            return Err(ExecutionError::no_such_key(name));
        };
        if self.has.contains(name) && !self.m.has(fd) {
            return Err(ExecutionError::no_such_key(name));
        }
        let value = self
            .m
            .field_by_name(name)
            .ok_or_else(|| ExecutionError::no_such_key(name))?;
        Ok(CowVal::Owned(to_val(&value, self.has)))
    }

    fn steal<'v>(self: Box<Self>, idx: &dyn Val) -> Result<Box<dyn Val + 'v>, ExecutionError>
    where
        Self: 'v,
    {
        self.get(idx).map(CowVal::into_owned)
    }
}

/// Converts an interpreter value to a [`Value`], for protovalidate's
/// functions; messages do not cross back.
fn from_val(v: &dyn Val) -> Option<Value<'static>> {
    let v = cel::Value::try_from(v).ok()?;
    from_value(&v)
}

fn from_value(v: &cel::Value) -> Option<Value<'static>> {
    Some(match v {
        cel::Value::Null => Value::Null,
        cel::Value::Bool(b) => Value::Bool(*b),
        cel::Value::Int(i) => Value::Int(*i),
        cel::Value::UInt(u) => Value::Uint(*u),
        cel::Value::Float(d) => Value::Double(*d),
        cel::Value::String(s) => Value::String(Str::Rc(Rc::from(s.as_str()))),
        cel::Value::Bytes(b) => Value::Bytes(Bin::Rc(Rc::from(b.as_slice()))),
        cel::Value::Duration(d) => Value::Duration(*d),
        cel::Value::Timestamp(t) => Value::Timestamp(t.to_utc()),
        cel::Value::List(l) => Value::List(List::Owned(
            l.iter().map(from_value).collect::<Option<Vec<_>>>()?.into(),
        )),
        cel::Value::Map(m) => {
            let entries = m
                .map
                .iter()
                .map(|(k, v)| Some((from_value(&cel::Value::from(k))?, from_value(v)?)))
                .collect::<Option<Vec<_>>>()?;
            Value::Map(Map::Owned(entries.into()))
        }
        _ => return None,
    })
}

fn result<'b, 'v>(v: Value<'_>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    Ok(CowVal::Owned(match v {
        Value::Bool(b) => Box::new(CelBool::from(b)),
        Value::Int(i) => Box::new(CelInt::from(i)),
        Value::String(s) => Box::new(CelString::from((*s).to_owned())),
        other => {
            return Err(ExecutionError::function_error(
                "protovalidate",
                format!("unexpected result {other:?}"),
            ));
        }
    }))
}

fn bridge<'b, 'v>(
    func: &Func,
    name: &str,
    args: &[CowVal<'b, 'v>],
) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let values = args
        .iter()
        .map(|a| from_val(&**a))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| ExecutionError::function_error(name, "unsupported argument"))?;
    let out = functions::call(func, &values)
        .map_err(|e| ExecutionError::function_error(name, e.to_string()))?;
    result(out)
}

macro_rules! bridged {
    ($($f:ident => $func:expr, $name:literal;)*) => {
        $(
            fn $f<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
                bridge(&$func, $name, &args)
            }
        )*
    };
}

bridged! {
    is_email => Func::IsEmail, "isEmail";
    is_hostname => Func::IsHostname, "isHostname";
    is_uri => Func::IsUri, "isUri";
    is_uri_ref => Func::IsUriRef, "isUriRef";
    is_ip => Func::IsIp, "isIp";
    is_ip_prefix => Func::IsIpPrefix, "isIpPrefix";
    is_host_and_port => Func::IsHostAndPort, "isHostAndPort";
    is_nan => Func::IsNan, "isNan";
    is_inf => Func::IsInf, "isInf";
    unique => Func::Unique, "unique";
}

fn get_field<'b, 'v>(args: Vec<CowVal<'b, 'v>>) -> Result<CowVal<'b, 'v>, ExecutionError> {
    let [target, name] = <[CowVal<'b, 'v>; 2]>::try_from(args)
        .map_err(|_| ExecutionError::invalid_argument_count(2, 0))?;
    let indexer = target
        .as_indexer()
        .ok_or_else(|| ExecutionError::function_error("getField", "not a message"))?;
    let value = indexer.get(&*name)?.into_owned();
    Ok(CowVal::Owned(value))
}

fn env() -> Env {
    use cel::common::types::{BOOL_TYPE, DOUBLE_TYPE, DYN_TYPE, INT_TYPE, LIST_TYPE, STRING_TYPE};
    let mut env = Env::stdlib();
    env.add_extension(cel::extensions::strings)
        .expect("the strings extension declares once");
    let member: [(
        &str,
        &str,
        fn() -> Type,
        Vec<Type>,
        cel::common::functions::Function,
    ); 15] = [
        ("isEmail", "pv_is_email", || STRING_TYPE, vec![], is_email),
        (
            "isHostname",
            "pv_is_hostname",
            || STRING_TYPE,
            vec![],
            is_hostname,
        ),
        ("isUri", "pv_is_uri", || STRING_TYPE, vec![], is_uri),
        (
            "isUriRef",
            "pv_is_uri_ref",
            || STRING_TYPE,
            vec![],
            is_uri_ref,
        ),
        ("isIp", "pv_is_ip", || STRING_TYPE, vec![], is_ip),
        (
            "isIp",
            "pv_is_ip_int",
            || STRING_TYPE,
            vec![INT_TYPE],
            is_ip,
        ),
        (
            "isIpPrefix",
            "pv_is_ip_prefix",
            || STRING_TYPE,
            vec![],
            is_ip_prefix,
        ),
        (
            "isIpPrefix",
            "pv_is_ip_prefix_int",
            || STRING_TYPE,
            vec![INT_TYPE],
            is_ip_prefix,
        ),
        (
            "isIpPrefix",
            "pv_is_ip_prefix_bool",
            || STRING_TYPE,
            vec![BOOL_TYPE],
            is_ip_prefix,
        ),
        (
            "isIpPrefix",
            "pv_is_ip_prefix_int_bool",
            || STRING_TYPE,
            vec![INT_TYPE, BOOL_TYPE],
            is_ip_prefix,
        ),
        (
            "isHostAndPort",
            "pv_is_host_and_port",
            || STRING_TYPE,
            vec![BOOL_TYPE],
            is_host_and_port,
        ),
        ("isNan", "pv_is_nan", || DOUBLE_TYPE, vec![], is_nan),
        ("isInf", "pv_is_inf", || DOUBLE_TYPE, vec![], is_inf),
        (
            "isInf",
            "pv_is_inf_int",
            || DOUBLE_TYPE,
            vec![INT_TYPE],
            is_inf,
        ),
        ("unique", "pv_unique", || LIST_TYPE, vec![], unique),
    ];
    for (name, id, target, args, f) in member {
        env.add_member_overload(name, id, target(), args, f)
            .expect("protovalidate's functions declare once");
    }
    env.add_overload(
        "getField",
        "pv_get_field",
        vec![DYN_TYPE, STRING_TYPE],
        get_field,
    )
    .expect("getField declares once");
    env
}
