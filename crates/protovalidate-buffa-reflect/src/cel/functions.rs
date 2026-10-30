//! CEL's standard functions, its strings extension, and protovalidate's
//! library.

use std::{collections::HashSet, rc::Rc};

use chrono::{DateTime, Datelike, TimeDelta, Timelike, Utc};
use protovalidate_buffa::rules::string as rules;
use regex::Regex;

use super::{
    Error,
    compile::{Func, Op, Time},
    eval::select,
    format,
    value::{Bin, List, Str, Value},
};

/// The bounds of CEL's timestamps: years 1 through 9999.
const MIN_TIMESTAMP: i64 = -62_135_596_800;
const MAX_TIMESTAMP: i64 = 253_402_300_799;
/// The bounds of CEL's durations, about ±10000 years.
const MAX_DURATION_SECONDS: i64 = 315_576_000_000;

fn overload(name: &str, args: &[Value<'_>]) -> Error {
    let types: Vec<_> = args.iter().map(Value::type_of).collect();
    Error::no_overload(name, &types)
}

pub fn negate<'a>(v: &Value<'a>) -> Result<Value<'a>, Error> {
    match *v {
        Value::Int(i) => i.checked_neg().map(Value::Int).ok_or_else(overflow),
        Value::Double(d) => Ok(Value::Double(-d)),
        Value::Duration(d) => duration(-d),
        _ => Err(overload("-_", std::slice::from_ref(v))),
    }
}

fn overflow() -> Error {
    Error::new("integer overflow")
}

fn duration<'a>(d: TimeDelta) -> Result<Value<'a>, Error> {
    if d.num_seconds().abs() > MAX_DURATION_SECONDS {
        return Err(Error::new("duration out of range"));
    }
    Ok(Value::Duration(d))
}

fn timestamp<'a>(t: Option<DateTime<Utc>>) -> Result<Value<'a>, Error> {
    match t {
        Some(t) if (MIN_TIMESTAMP..=MAX_TIMESTAMP).contains(&t.timestamp()) => {
            Ok(Value::Timestamp(t))
        }
        _ => Err(Error::new("timestamp out of range")),
    }
}

#[expect(clippy::many_single_char_names, reason = "an operator's operands")]
pub fn arithmetic<'a>(op: Op, a: &Value<'a>, b: &Value<'a>) -> Result<Value<'a>, Error> {
    let name = match op {
        Op::Add => "_+_",
        Op::Sub => "_-_",
        Op::Mul => "_*_",
        Op::Div => "_/_",
        _ => "_%_",
    };
    match (a, b) {
        (Value::Int(x), Value::Int(y)) => {
            let (x, y) = (*x, *y);
            let r = match op {
                Op::Add => x.checked_add(y),
                Op::Sub => x.checked_sub(y),
                Op::Mul => x.checked_mul(y),
                Op::Div if y == 0 => return Err(Error::new("division by zero")),
                Op::Div => x.checked_div(y),
                _ if y == 0 => return Err(Error::new("modulus by zero")),
                _ => x.checked_rem(y),
            };
            r.map(Value::Int).ok_or_else(overflow)
        }
        (Value::Uint(x), Value::Uint(y)) => {
            let (x, y) = (*x, *y);
            let r = match op {
                Op::Add => x.checked_add(y),
                Op::Sub => x.checked_sub(y),
                Op::Mul => x.checked_mul(y),
                Op::Div if y == 0 => return Err(Error::new("division by zero")),
                Op::Div => x.checked_div(y),
                _ if y == 0 => return Err(Error::new("modulus by zero")),
                _ => x.checked_rem(y),
            };
            r.map(Value::Uint).ok_or_else(overflow)
        }
        (Value::Double(x), Value::Double(y)) => Ok(Value::Double(match op {
            Op::Add => x + y,
            Op::Sub => x - y,
            Op::Mul => x * y,
            Op::Div => x / y,
            _ => return Err(overload(name, &[a.clone(), b.clone()])),
        })),
        (Value::String(x), Value::String(y)) if op == Op::Add => {
            let mut s = String::with_capacity(x.len() + y.len());
            s.push_str(x);
            s.push_str(y);
            Ok(Value::str(s))
        }
        (Value::Bytes(x), Value::Bytes(y)) if op == Op::Add => {
            Ok(Value::Bytes(Bin::Rc([&**x, &**y].concat().into())))
        }
        (Value::List(x), Value::List(y)) if op == Op::Add => {
            let items: Vec<_> = x.items().into_iter().chain(y.items()).collect();
            Ok(Value::List(List::Owned(items.into())))
        }
        (Value::Duration(x), Value::Duration(y)) if matches!(op, Op::Add | Op::Sub) => {
            let r = if op == Op::Add {
                x.checked_add(y)
            } else {
                x.checked_sub(y)
            };
            duration(r.ok_or_else(overflow)?)
        }
        (Value::Timestamp(t), Value::Duration(d)) | (Value::Duration(d), Value::Timestamp(t))
            if op == Op::Add =>
        {
            timestamp(t.checked_add_signed(*d))
        }
        (Value::Timestamp(t), Value::Duration(d)) if op == Op::Sub => {
            timestamp(t.checked_sub_signed(*d))
        }
        (Value::Timestamp(x), Value::Timestamp(y)) if op == Op::Sub => duration(*x - *y),
        _ => Err(overload(name, &[a.clone(), b.clone()])),
    }
}

fn string<'v>(v: &'v Value<'_>, name: &str) -> Result<&'v str, Error> {
    match v {
        Value::String(s) => Ok(s),
        other => Err(overload(name, std::slice::from_ref(other))),
    }
}

fn int(v: &Value<'_>, name: &str) -> Result<i64, Error> {
    match v {
        Value::Int(i) => Ok(*i),
        other => Err(overload(name, std::slice::from_ref(other))),
    }
}

fn boolean(v: &Value<'_>, name: &str) -> Result<bool, Error> {
    match v {
        Value::Bool(b) => Ok(*b),
        other => Err(overload(name, std::slice::from_ref(other))),
    }
}

/// Calls `func`; the receiver, if any, is `args[0]`.
#[expect(clippy::too_many_lines, reason = "one arm per function")]
pub fn call<'a>(func: &Func, args: &[Value<'a>]) -> Result<Value<'a>, Error> {
    let arg = |i: usize| args.get(i).ok_or_else(|| Error::new("missing argument"));
    Ok(match func {
        Func::Size => Value::Int(size(arg(0)?)?),
        Func::StartsWith | Func::EndsWith | Func::Contains => {
            let name = match func {
                Func::StartsWith => "startsWith",
                Func::EndsWith => "endsWith",
                _ => "contains",
            };
            Value::Bool(match (arg(0)?, arg(1)?) {
                (Value::String(s), Value::String(p)) => match func {
                    Func::StartsWith => s.starts_with(&**p),
                    Func::EndsWith => s.ends_with(&**p),
                    _ => s.contains(&**p),
                },
                (Value::Bytes(s), Value::Bytes(p)) => match func {
                    Func::StartsWith => s.starts_with(p),
                    Func::EndsWith => s.ends_with(p),
                    _ => p.is_empty() || s.windows(p.len()).any(|w| w == &**p),
                },
                _ => return Err(overload(name, args)),
            })
        }
        Func::Matches(re) => {
            let s = string(arg(0)?, "matches")?;
            let matched = re.as_ref().map_or_else(
                || {
                    let pattern = string(arg(1)?, "matches")?;
                    Ok::<_, Error>(
                        Regex::new(pattern)
                            .map_err(|e| Error::new(format!("invalid regular expression: {e}")))?
                            .is_match(s),
                    )
                },
                |re| Ok(re.is_match(s)),
            )?;
            Value::Bool(matched)
        }
        Func::IsEmail => Value::Bool(rules::is_email(string(arg(0)?, "isEmail")?)),
        Func::IsHostname => Value::Bool(rules::is_hostname(string(arg(0)?, "isHostname")?)),
        Func::IsUri => Value::Bool(rules::is_uri(string(arg(0)?, "isUri")?)),
        Func::IsUriRef => Value::Bool(rules::is_uri_ref(string(arg(0)?, "isUriRef")?)),
        Func::IsIp => {
            let s = string(arg(0)?, "isIp")?;
            let version = match args.get(1) {
                Some(v) => int(v, "isIp")?,
                None => 0,
            };
            Value::Bool(match version {
                0 => rules::is_ip(s),
                4 => rules::is_ipv4(s),
                6 => rules::is_ipv6(s),
                _ => false,
            })
        }
        Func::IsIpPrefix => {
            let s = string(arg(0)?, "isIpPrefix")?;
            let (version, strict) = match &args[1..] {
                [] => (0, false),
                [Value::Int(v)] => (*v, false),
                [Value::Bool(b)] => (0, *b),
                [Value::Int(v), Value::Bool(b)] => (*v, *b),
                _ => return Err(overload("isIpPrefix", args)),
            };
            Value::Bool(match (version, strict) {
                (0, false) => rules::is_ip_with_prefixlen(s),
                (4, false) => rules::is_ipv4_with_prefixlen(s),
                (6, false) => rules::is_ipv6_with_prefixlen(s),
                (0, true) => rules::is_ip_prefix(s),
                (4, true) => rules::is_ipv4_prefix(s),
                (6, true) => rules::is_ipv6_prefix(s),
                _ => false,
            })
        }
        Func::IsHostAndPort => {
            let s = string(arg(0)?, "isHostAndPort")?;
            let port_required = boolean(arg(1)?, "isHostAndPort")?;
            Value::Bool(host_and_port(s, port_required))
        }
        Func::IsNan => match arg(0)? {
            Value::Double(d) => Value::Bool(d.is_nan()),
            _ => return Err(overload("isNan", args)),
        },
        Func::IsInf => match (arg(0)?, args.get(1)) {
            (Value::Double(d), None) => Value::Bool(d.is_infinite()),
            (Value::Double(d), Some(Value::Int(sign))) => Value::Bool(match sign.signum() {
                1 => *d == f64::INFINITY,
                -1 => *d == f64::NEG_INFINITY,
                _ => d.is_infinite(),
            }),
            _ => return Err(overload("isInf", args)),
        },
        Func::Unique => Value::Bool(unique(arg(0)?)?),
        Func::GetField => select(arg(0)?, string(arg(1)?, "getField")?)?,
        Func::ToInt => to_int(arg(0)?)?,
        Func::ToUint => to_uint(arg(0)?)?,
        Func::ToDouble => to_double(arg(0)?)?,
        Func::ToString => to_string(arg(0)?)?,
        Func::ToBytes => match arg(0)? {
            Value::String(s) => Value::Bytes(match s {
                Str::Ref(s) => Bin::Ref(s.as_bytes()),
                Str::Rc(s) => Bin::Rc(Rc::from(s.as_bytes())),
            }),
            b @ Value::Bytes(_) => b.clone(),
            _ => return Err(overload("bytes", args)),
        },
        Func::ToBool => match arg(0)? {
            b @ Value::Bool(_) => b.clone(),
            Value::String(s) => Value::Bool(match &**s {
                "true" | "TRUE" | "True" | "t" | "1" => true,
                "false" | "FALSE" | "False" | "f" | "0" => false,
                _ => return Err(Error::new(format!("cannot convert {:?} to bool", &**s))),
            }),
            _ => return Err(overload("bool", args)),
        },
        Func::ToDuration => match arg(0)? {
            d @ Value::Duration(_) => d.clone(),
            Value::String(s) => duration(
                protovalidate_buffa::cel::parse_duration(s)
                    .ok_or_else(|| Error::new(format!("invalid duration {:?}", &**s)))?,
            )?,
            _ => return Err(overload("duration", args)),
        },
        Func::ToTimestamp => match arg(0)? {
            t @ Value::Timestamp(_) => t.clone(),
            Value::String(s) => timestamp(
                DateTime::parse_from_rfc3339(s)
                    .map_err(|e| Error::new(format!("invalid timestamp {:?}: {e}", &**s)))
                    .map(|t| Some(t.to_utc()))?,
            )?,
            Value::Int(i) => timestamp(DateTime::from_timestamp(*i, 0))?,
            _ => return Err(overload("timestamp", args)),
        },
        Func::TypeOf => Value::Type(arg(0)?.type_of()),
        Func::Format => {
            let template = string(arg(0)?, "format")?;
            let Value::List(list) = arg(1)? else {
                return Err(overload("format", args));
            };
            Value::str(format::format(template, list)?)
        }
        Func::CharAt => {
            let s = string(arg(0)?, "charAt")?;
            let i = usize::try_from(int(arg(1)?, "charAt")?)
                .map_err(|_| Error::new("index out of range"))?;
            let count = s.chars().count();
            if i > count {
                return Err(Error::new(format!("index out of range: {i}")));
            }
            Value::str(s.chars().nth(i).map(String::from).unwrap_or_default())
        }
        Func::IndexOf | Func::LastIndexOf => {
            let s = string(arg(0)?, "indexOf")?;
            let needle = string(arg(1)?, "indexOf")?;
            let chars: Vec<char> = s.chars().collect();
            let needle: Vec<char> = needle.chars().collect();
            let last = matches!(func, Func::LastIndexOf);
            let start = match args.get(2) {
                Some(v) => {
                    let i = int(v, "indexOf")?;
                    let i = usize::try_from(i)
                        .ok()
                        .filter(|&i| i <= chars.len())
                        .ok_or_else(|| Error::new(format!("index out of range: {i}")))?;
                    Some(i)
                }
                None => None,
            };
            Value::Int(char_index(&chars, &needle, start, last))
        }
        Func::LowerAscii => Value::str(string(arg(0)?, "lowerAscii")?.to_ascii_lowercase()),
        Func::UpperAscii => Value::str(string(arg(0)?, "upperAscii")?.to_ascii_uppercase()),
        Func::Trim => Value::str(string(arg(0)?, "trim")?.trim().to_owned()),
        Func::Reverse => Value::str(string(arg(0)?, "reverse")?.chars().rev().collect()),
        Func::Replace => {
            let s = string(arg(0)?, "replace")?;
            let from = string(arg(1)?, "replace")?;
            let to = string(arg(2)?, "replace")?;
            let limit = match args.get(3) {
                Some(n) => usize::try_from(int(n, "replace")?).ok(),
                None => None,
            };
            Value::str(limit.map_or_else(|| s.replace(from, to), |n| s.replacen(from, to, n)))
        }
        Func::Split => {
            let s = string(arg(0)?, "split")?;
            let sep = string(arg(1)?, "split")?;
            let parts: Vec<Value<'a>> = match args.get(2).map(|n| int(n, "split")).transpose()? {
                Some(0) => Vec::new(),
                Some(n) if n > 0 => s
                    .splitn(usize::try_from(n).unwrap_or(usize::MAX), sep)
                    .map(|p| Value::str(p.to_owned()))
                    .collect(),
                _ => s.split(sep).map(|p| Value::str(p.to_owned())).collect(),
            };
            Value::List(List::Owned(parts.into()))
        }
        Func::Substring => {
            let s = string(arg(0)?, "substring")?;
            let chars: Vec<char> = s.chars().collect();
            let range = |v: &Value<'_>| -> Result<usize, Error> {
                let i = int(v, "substring")?;
                usize::try_from(i)
                    .ok()
                    .filter(|&i| i <= chars.len())
                    .ok_or_else(|| Error::new(format!("index out of range: {i}")))
            };
            let start = range(arg(1)?)?;
            let end = match args.get(2) {
                Some(v) => range(v)?,
                None => chars.len(),
            };
            if start > end {
                return Err(Error::new("invalid substring range"));
            }
            Value::str(chars[start..end].iter().collect())
        }
        Func::Join => {
            let Value::List(list) = arg(0)? else {
                return Err(overload("join", args));
            };
            let sep = match args.get(1) {
                Some(v) => string(v, "join")?,
                None => "",
            };
            let mut out = String::new();
            for (i, item) in list.items().iter().enumerate() {
                if i > 0 {
                    out.push_str(sep);
                }
                match item {
                    Value::String(s) => out.push_str(s),
                    _ => return Err(Error::new("join requires a list of strings")),
                }
            }
            Value::str(out)
        }
        Func::Time(t) => Value::Int(time(*t, arg(0)?, args.get(1))?),
    })
}

fn size(v: &Value<'_>) -> Result<i64, Error> {
    let n = match v {
        Value::String(s) => s.chars().count(),
        Value::Bytes(b) => b.len(),
        Value::List(l) => l.len(),
        Value::Map(m) => m.len(),
        other => return Err(overload("size", std::slice::from_ref(other))),
    };
    i64::try_from(n).map_err(|_| overflow())
}

fn char_index(chars: &[char], needle: &[char], start: Option<usize>, last: bool) -> i64 {
    let found = if last {
        let end = start.map_or(chars.len(), |s| (s + needle.len()).min(chars.len()));
        (0..=end.saturating_sub(needle.len()))
            .rev()
            .find(|&i| i + needle.len() <= end && chars[i..i + needle.len()] == *needle)
    } else {
        let start = start.unwrap_or(0);
        (start..=chars.len().saturating_sub(needle.len()))
            .find(|&i| i + needle.len() <= chars.len() && chars[i..i + needle.len()] == *needle)
    };
    found.map_or(-1, |i| i64::try_from(i).unwrap_or(-1))
}

fn host_and_port(s: &str, port_required: bool) -> bool {
    if rules::is_host_and_port(s) {
        return true;
    }
    if port_required {
        return false;
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return rules::is_ipv6(inner) && !inner.contains('%') || rules::is_ipv6(inner);
    }
    rules::is_hostname(s) || rules::is_ipv4(s)
}

fn unique(v: &Value<'_>) -> Result<bool, Error> {
    let Value::List(list) = v else {
        return Err(overload("unique", std::slice::from_ref(v)));
    };
    // Items are hashed into a small filter; only a possible repeat builds a
    // set.
    let mut filter = [0u64; 4];
    let mut repeats = false;
    let mut error = None;
    list.for_each(&mut |item| {
        let h = match hash(&item) {
            Ok(Some(h)) => h.wrapping_mul(0x9E37_79B9_7F4A_7C15),
            Ok(None) => return true,
            Err(e) => {
                error = Some(e);
                return false;
            }
        };
        let (word, bit) = ((h >> 62) as usize, 1 << ((h >> 56) & 63));
        repeats = filter[word] & bit != 0;
        filter[word] |= bit;
        !repeats
    });
    if let Some(e) = error {
        return Err(e);
    }
    if !repeats {
        return Ok(true);
    }
    let mut seen = HashSet::new();
    let mut unique = true;
    list.for_each(&mut |item| {
        if let Ok(Some(key)) = key(&item) {
            unique = seen.insert(key);
        }
        unique
    });
    Ok(unique)
}

/// A hash of an item that agrees with [`key`].
fn hash(item: &Value<'_>) -> Result<Option<u64>, Error> {
    let bytes = |b: &[u8]| {
        b.iter().fold(0xcbf2_9ce4_8422_2325, |h, &c| {
            (h ^ u64::from(c)).wrapping_mul(0x100_0000_01b3)
        })
    };
    Ok(match item {
        Value::String(s) => Some(bytes(s.as_bytes())),
        Value::Bytes(b) => Some(bytes(b)),
        other => key(other)?.map(|k| match k {
            Key::Bool(b) => u64::from(b),
            #[expect(clippy::cast_possible_truncation, reason = "a hash")]
            Key::Int(i) => (i as u64) ^ ((i >> 64) as u64),
            Key::Double(d) => d,
            Key::Bytes(b) => bytes(&b),
        }),
    })
}

/// An item as `unique()` compares it: numbers by value; `None` for NaN,
/// which equals nothing.
fn key(item: &Value<'_>) -> Result<Option<Key>, Error> {
    Ok(Some(match item {
        Value::Bool(b) => Key::Bool(*b),
        Value::Int(i) => Key::Int(i128::from(*i)),
        Value::Uint(u) => Key::Int(i128::from(*u)),
        Value::Double(d) if d.is_nan() => return Ok(None),
        Value::Double(d) if d.fract() == 0.0 && d.abs() < 1.8e19 =>
        {
            #[expect(clippy::cast_possible_truncation, reason = "integral and in range")]
            Key::Int(*d as i128)
        }
        Value::Double(d) => Key::Double(d.to_bits()),
        Value::String(s) => Key::Bytes(s.as_bytes().to_vec()),
        Value::Bytes(b) => Key::Bytes(b.to_vec()),
        other => return Err(overload("unique", &[other.clone()])),
    }))
}

#[derive(Hash, PartialEq, Eq)]
enum Key {
    Bool(bool),
    Int(i128),
    Double(u64),
    Bytes(Vec<u8>),
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "CEL's conversion, range-checked"
)]
fn to_int<'a>(v: &Value<'a>) -> Result<Value<'a>, Error> {
    Ok(Value::Int(match v {
        Value::Int(i) => *i,
        Value::Uint(u) => i64::try_from(*u).map_err(|_| Error::new("int out of range"))?,
        Value::Double(d) => {
            if !d.is_finite() || *d <= -9.223_372_036_854_776e18 || *d >= 9.223_372_036_854_776e18 {
                return Err(Error::new("int out of range"));
            }
            *d as i64
        }
        Value::String(s) => s
            .parse()
            .map_err(|_| Error::new(format!("cannot convert {:?} to int", &**s)))?,
        Value::Timestamp(t) => t.timestamp(),
        Value::Duration(d) => d.num_seconds(),
        other => return Err(overload("int", std::slice::from_ref(other))),
    }))
}

#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "CEL's conversions, range-checked"
)]
fn to_uint<'a>(v: &Value<'a>) -> Result<Value<'a>, Error> {
    Ok(Value::Uint(match v {
        Value::Uint(u) => *u,
        Value::Int(i) => u64::try_from(*i).map_err(|_| Error::new("uint out of range"))?,
        Value::Double(d) => {
            if !d.is_finite() || *d <= -1.0 || *d >= 1.844_674_407_370_955_2e19 {
                return Err(Error::new("uint out of range"));
            }
            *d as u64
        }
        Value::String(s) => s
            .parse()
            .map_err(|_| Error::new(format!("cannot convert {:?} to uint", &**s)))?,
        other => return Err(overload("uint", std::slice::from_ref(other))),
    }))
}

#[expect(clippy::cast_precision_loss, reason = "CEL's conversion to double")]
fn to_double<'a>(v: &Value<'a>) -> Result<Value<'a>, Error> {
    Ok(Value::Double(match v {
        Value::Double(d) => *d,
        Value::Int(i) => *i as f64,
        Value::Uint(u) => *u as f64,
        Value::String(s) => s
            .parse()
            .map_err(|_| Error::new(format!("cannot convert {:?} to double", &**s)))?,
        other => return Err(overload("double", std::slice::from_ref(other))),
    }))
}

fn to_string<'a>(v: &Value<'a>) -> Result<Value<'a>, Error> {
    Ok(match v {
        s @ Value::String(_) => s.clone(),
        Value::Bytes(b) => match b {
            Bin::Ref(b) => Value::String(Str::Ref(
                std::str::from_utf8(b).map_err(|_| Error::new("invalid UTF-8 in bytes"))?,
            )),
            Bin::Rc(b) => Value::str(
                std::str::from_utf8(b)
                    .map_err(|_| Error::new("invalid UTF-8 in bytes"))?
                    .to_owned(),
            ),
        },
        Value::Int(_) | Value::Uint(_) | Value::Double(_) | Value::Bool(_) => {
            Value::str(format::to_text(v)?)
        }
        Value::Duration(_) | Value::Timestamp(_) => Value::str(format::to_text(v)?),
        Value::Type(t) => Value::String(Str::Ref(t.name())),
        other => return Err(overload("string", std::slice::from_ref(other))),
    })
}

fn time(t: Time, v: &Value<'_>, zone: Option<&Value<'_>>) -> Result<i64, Error> {
    if let Value::Duration(d) = v {
        return Ok(match t {
            Time::Hours => d.num_hours(),
            Time::Minutes => d.num_minutes(),
            Time::Seconds => d.num_seconds(),
            Time::Milliseconds => i64::from(d.subsec_nanos() / 1_000_000),
            _ => return Err(Error::new("no such overload")),
        });
    }
    let Value::Timestamp(ts) = v else {
        return Err(Error::new("no such overload"));
    };
    let zone = match zone {
        Some(Value::String(z)) => Some(&**z),
        Some(_) => return Err(Error::new("no such overload")),
        None => None,
    };
    let fields = zoned(*ts, zone)?;
    Ok(match t {
        Time::FullYear => i64::from(fields.year),
        Time::Month => i64::from(fields.month0),
        Time::DayOfYear => i64::from(fields.ordinal0),
        Time::DayOfMonth => i64::from(fields.day0),
        Time::Date => i64::from(fields.day0) + 1,
        Time::DayOfWeek => i64::from(fields.weekday),
        Time::Hours => i64::from(fields.hour),
        Time::Minutes => i64::from(fields.minute),
        Time::Seconds => i64::from(fields.second),
        Time::Milliseconds => i64::from(fields.nanos / 1_000_000),
    })
}

struct Fields {
    year: i32,
    month0: u32,
    ordinal0: u32,
    day0: u32,
    weekday: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
}

fn fields<T: Datelike + Timelike>(t: &T) -> Fields {
    Fields {
        year: t.year(),
        month0: t.month0(),
        ordinal0: t.ordinal0(),
        day0: t.day0(),
        weekday: t.weekday().num_days_from_sunday(),
        hour: t.hour(),
        minute: t.minute(),
        second: t.second(),
        nanos: t.nanosecond(),
    }
}

fn zoned(ts: DateTime<Utc>, zone: Option<&str>) -> Result<Fields, Error> {
    let Some(zone) = zone else {
        return Ok(fields(&ts));
    };
    if let Some(offset) = fixed_offset(zone) {
        return Ok(fields(&ts.with_timezone(&offset)));
    }
    named_zone(ts, zone)
}

/// `+HH:MM`, `-HH:MM` or `HH:MM`, as CEL accepts besides IANA names.
fn fixed_offset(zone: &str) -> Option<chrono::FixedOffset> {
    let (sign, rest) = match zone.as_bytes().first()? {
        b'+' => (1, &zone[1..]),
        b'-' => (-1, &zone[1..]),
        _ => (1, zone),
    };
    let (h, m) = rest.split_once(':')?;
    let secs = h.parse::<i32>().ok()? * 3600 + m.parse::<i32>().ok()? * 60;
    chrono::FixedOffset::east_opt(sign * secs)
}

#[cfg(feature = "tz")]
fn named_zone(ts: DateTime<Utc>, zone: &str) -> Result<Fields, Error> {
    let tz: chrono_tz::Tz = zone
        .parse()
        .map_err(|_| Error::new(format!("unknown time zone {zone:?}")))?;
    Ok(fields(&ts.with_timezone(&tz)))
}

#[cfg(not(feature = "tz"))]
fn named_zone(ts: DateTime<Utc>, zone: &str) -> Result<Fields, Error> {
    if zone.eq_ignore_ascii_case("utc") {
        return Ok(fields(&ts));
    }
    Err(Error::new(format!(
        "time zone {zone:?} needs the `tz` feature"
    )))
}
