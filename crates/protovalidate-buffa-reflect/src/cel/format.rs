//! The strings extension's `format()`, and CEL's text forms of values.

use std::fmt::Write as _;

use chrono::SecondsFormat;

use super::{
    Error,
    value::{List, Value},
};

pub fn format(template: &str, args: &List<'_>) -> Result<String, Error> {
    let mut out = String::with_capacity(template.len() + 16);
    let mut next = 0;
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '%' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'%') {
            chars.next();
            out.push('%');
            continue;
        }
        let precision = if chars.peek() == Some(&'.') {
            chars.next();
            let mut digits = String::new();
            while let Some(d) = chars.peek().copied().filter(char::is_ascii_digit) {
                digits.push(d);
                chars.next();
            }
            Some(
                digits
                    .parse::<usize>()
                    .map_err(|_| Error::new("invalid precision"))?,
            )
        } else {
            None
        };
        let verb = chars
            .next()
            .ok_or_else(|| Error::new("format: unterminated verb"))?;
        let arg = args
            .get(next)
            .ok_or_else(|| Error::new(format!("format: missing argument {next}")))?;
        next += 1;
        match verb {
            's' => out.push_str(&to_text(&arg)?),
            'd' => match arg {
                Value::Int(i) => write!(out, "{i}").expect("writing to a string"),
                Value::Uint(u) => write!(out, "{u}").expect("writing to a string"),
                Value::Double(d) if d.is_nan() || d.is_infinite() => out.push_str(&double(d)),
                _ => return Err(Error::new("format: %d needs an integer")),
            },
            'f' | 'e' => {
                let d = match arg {
                    Value::Double(d) => d,
                    #[expect(clippy::cast_precision_loss, reason = "formatting")]
                    Value::Int(i) => i as f64,
                    #[expect(clippy::cast_precision_loss, reason = "formatting")]
                    Value::Uint(u) => u as f64,
                    _ => return Err(Error::new("format: %f needs a number")),
                };
                let p = precision.unwrap_or(6);
                if d.is_nan() || d.is_infinite() {
                    out.push_str(&double(d));
                } else if verb == 'f' {
                    write!(out, "{d:.p$}").expect("writing to a string");
                } else {
                    out.push_str(&exponent(d, p));
                }
            }
            'x' | 'X' => {
                let hex = match arg {
                    Value::Int(i) if i < 0 => format!("-{:x}", i.unsigned_abs()),
                    Value::Int(i) => format!("{i:x}"),
                    Value::Uint(u) => format!("{u:x}"),
                    Value::String(s) => s.bytes().fold(String::new(), |mut a, b| {
                        write!(a, "{b:02x}").expect("writing to a string");
                        a
                    }),
                    Value::Bytes(b) => b.iter().fold(String::new(), |mut a, b| {
                        write!(a, "{b:02x}").expect("writing to a string");
                        a
                    }),
                    _ => return Err(Error::new("format: %x needs an integer, string or bytes")),
                };
                out.push_str(&if verb == 'X' { hex.to_uppercase() } else { hex });
            }
            'o' => match arg {
                Value::Int(i) => write!(out, "{i:o}").expect("writing to a string"),
                Value::Uint(u) => write!(out, "{u:o}").expect("writing to a string"),
                _ => return Err(Error::new("format: %o needs an integer")),
            },
            'b' => match arg {
                Value::Int(i) => write!(out, "{i:b}").expect("writing to a string"),
                Value::Uint(u) => write!(out, "{u:b}").expect("writing to a string"),
                Value::Bool(b) => write!(out, "{b}").expect("writing to a string"),
                _ => return Err(Error::new("format: %b needs an integer")),
            },
            other => return Err(Error::new(format!("format: unknown verb %{other}"))),
        }
    }
    Ok(out)
}

fn exponent(d: f64, precision: usize) -> String {
    let s = format!("{d:.precision$e}");
    // Rust writes `1.5e2`; CEL, like C, writes `1.5e+02`.
    match s.split_once('e') {
        Some((mantissa, exp)) => {
            let (sign, digits) = exp.strip_prefix('-').map_or(("+", exp), |d| ("-", d));
            format!("{mantissa}e{sign}{digits:0>2}")
        }
        None => s,
    }
}

fn double(d: f64) -> String {
    if d.is_nan() {
        "NaN".into()
    } else if d.is_infinite() {
        if d > 0.0 {
            "+Inf".into()
        } else {
            "-Inf".into()
        }
    } else if d.fract() == 0.0 && d.abs() < 1e21 {
        format!("{d:.0}")
    } else {
        format!("{d}")
    }
}

/// A value's text, as `string()` and `%s` render it.
pub fn to_text(v: &Value<'_>) -> Result<String, Error> {
    Ok(match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Int(i) => i.to_string(),
        Value::Uint(u) => u.to_string(),
        Value::Double(d) => double(*d),
        Value::String(s) => (**s).to_owned(),
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Duration(d) => {
            let secs = d.num_seconds();
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                format!("{secs}s")
            } else {
                let frac = format!("{:09}", nanos.unsigned_abs());
                let sign = if secs == 0 && nanos < 0 { "-" } else { "" };
                format!("{sign}{secs}.{}s", frac.trim_end_matches('0'))
            }
        }
        Value::Timestamp(t) => t.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        Value::Type(t) => t.name().into(),
        Value::List(l) => {
            let mut out = String::from("[");
            for (i, item) in l.items().iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&to_text(item)?);
            }
            out.push(']');
            out
        }
        Value::Map(m) => {
            let mut out = String::from("{");
            let mut first = true;
            let mut err = None;
            m.for_each(&mut |k, v| {
                if !first {
                    out.push_str(", ");
                }
                first = false;
                match (to_text(&k), to_text(&v)) {
                    (Ok(k), Ok(v)) => {
                        out.push_str(&k);
                        out.push_str(": ");
                        out.push_str(&v);
                        true
                    }
                    (Err(e), _) | (_, Err(e)) => {
                        err = Some(e);
                        false
                    }
                }
            });
            if let Some(e) = err {
                return Err(e);
            }
            out.push('}');
            out
        }
        Value::Message(m) => {
            if m.descriptor().full_name() == "google.protobuf.FieldMask"
                && let Some(Value::List(paths)) = m.field_by_name("paths")
            {
                return to_text(&Value::List(paths));
            }
            format!("{}{{}}", m.descriptor().full_name())
        }
    })
}
