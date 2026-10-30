//! Walking an encoded message against its plan.

use std::borrow::Cow;

use buffa_descriptor::ScalarType;
use protovalidate_buffa::{FieldPath, FieldPathElement, FieldType, Subscript, Violation};

use crate::{
    cel::{
        Clock, Outcome,
        value::{self, Gathered, List, Map, Msg, Prim, Value},
    },
    plan::{Check, Elem, MessagePlan, Plans, Route, Rule, ValuePlan},
    wire::{self, Card, Found, Kind, Malformed, Raw},
};

/// Why a validation stopped before it finished.
pub enum Abort {
    Compile(String),
    Runtime(String),
    /// The bytes are not an encoding of the message.
    Malformed,
}

/// Where a value sits, as a chain of frames on the stack: the path is only
/// written out when a violation is reported.
struct Path<'p, 'a> {
    parent: Option<&'p Self>,
    elem: &'a Elem,
    sub: Sub<'p, 'a>,
}

enum Sub<'k, 'a> {
    None,
    Index(usize),
    Key(&'k Value<'a>),
}

/// The rule a violation reports.
#[derive(Clone, Copy)]
enum RulePath<'a> {
    Elems(&'a [Elem]),
    Required,
}

pub struct Walker<'a> {
    plans: &'a Plans,
    clock: Clock,
    depth: u32,
    /// The slots of the messages being walked, the innermost last.
    pub found: Vec<Found>,
    pub violations: Vec<Violation>,
}

impl<'a> Walker<'a> {
    pub fn new(plans: &'a Plans, found: Vec<Found>) -> Self {
        Self {
            plans,
            clock: Clock::default(),
            depth: 0,
            found,
            violations: Vec::new(),
        }
    }

    pub fn root(&mut self, msg: &Msg<'a>) -> Result<(), Box<Abort>> {
        self.message(0, msg, None)
    }

    fn message(
        &mut self,
        plan: usize,
        msg: &Msg<'a>,
        path: Option<&Path<'_, 'a>>,
    ) -> Result<(), Box<Abort>> {
        let plans = self.plans;
        let plan: &'a MessagePlan = &plans.messages[plan];
        if let Some(e) = &plan.error {
            return Err(Box::new(Abort::Compile(e.clone())));
        }
        if self.depth >= wire::DEPTH {
            return Err(Box::new(Abort::Malformed));
        }
        let pool = msg.pool;

        // One pass over the encoding finds the fields the plan reads.
        let base = self.found.len();
        self.found.resize(base + plan.slots.len(), Found::EMPTY);
        if !plan.slots.is_empty() {
            let found = &mut self.found[base..];
            msg.src
                .visit_at(&mut |n, raw, at| {
                    let Some(route) = plan.dispatch.route(n) else {
                        return Ok(());
                    };
                    if route.wires & raw.wire() == 0 {
                        return Ok(());
                    }
                    let s = usize::from(route.slot);
                    if route.flags != 0 {
                        let slot = &plan.slots[s];
                        if route.flags & Route::CLOSED != 0 && !slot.read.shape.accepts(raw, pool)
                            || route.flags & Route::PACKED != 0 && matches!(raw, Raw::Len([]))
                        {
                            return Ok(());
                        }
                        for &other in &slot.siblings {
                            found[other].clear();
                        }
                    }
                    found[s].take(raw, at, n);
                    Ok::<(), Malformed>(())
                })
                .map_err(|_| Box::new(Abort::Malformed))?;
        }
        let result = self.fields(plan, msg, base, path);
        self.found.truncate(base);
        result
    }

    #[expect(
        clippy::too_many_lines,
        reason = "a message's checks, in the order they report"
    )]
    fn fields(
        &mut self,
        plan: &'a MessagePlan,
        msg: &Msg<'a>,
        base: usize,
        path: Option<&Path<'_, 'a>>,
    ) -> Result<(), Box<Abort>> {
        let pool = msg.pool;
        let n = plan.slots.len();
        let present = |found: &[Found], s: usize| {
            value::present(&found[base + s], &plan.slots[s].read, &msg.src, pool)
        };

        if !plan.rules.is_empty() {
            // Failures are reported once the rules no longer read the slots.
            let mut failed = Vec::new();
            {
                let gathered = Gathered {
                    dispatch: &plan.dispatch,
                    found: &self.found[base..base + n],
                };
                let this = Value::Message(Msg {
                    gathered: Some(&gathered),
                    ..msg.clone()
                });
                for rule in &plan.rules {
                    match rule.program.passes(&this, &self.clock) {
                        Ok(true) => {}
                        Ok(false) => failed.push((rule, failure(rule, &this, &self.clock))),
                        Err(e) => {
                            return Err(Box::new(Abort::Runtime(format!("{}: {e}", rule.id))));
                        }
                    }
                }
            }
            for (rule, message) in failed {
                self.report(
                    path,
                    None,
                    RulePath::Elems(&rule.path),
                    &rule.id,
                    message,
                    false,
                );
            }
        }
        for o in &plan.message_oneofs {
            let set = o
                .fields
                .iter()
                .filter(|&&s| present(&self.found, s))
                .count();
            let message = if set > 1 {
                format!("only one of {} can be set", o.names)
            } else if o.required && set == 0 {
                format!("one of {} must be set", o.names)
            } else {
                continue;
            };
            self.report(
                path,
                None,
                RulePath::Elems(&[]),
                "message.oneof",
                message,
                false,
            );
        }
        for (members, name) in &plan.oneofs {
            if !members.iter().any(|&s| self.found[base + s].last.is_some()) {
                self.report(
                    path,
                    Some(name),
                    RulePath::Elems(&[]),
                    "required",
                    "exactly one field is required in oneof".into(),
                    false,
                );
            }
        }
        self.depth += 1;
        for field in &plan.fields {
            if let Some(e) = &field.error {
                return Err(Box::new(Abort::Compile(e.clone())));
            }
            let present = present(&self.found, field.slot);
            let found = self.found[base + field.slot];
            let here = Path {
                parent: path,
                elem: &field.elem,
                sub: Sub::None,
            };
            if field.required && !present {
                self.report(
                    Some(&here),
                    None,
                    RulePath::Required,
                    "required",
                    "value is required".into(),
                    false,
                );
                continue;
            }
            if field.skip_unset && !present {
                continue;
            }
            let read = &plan.slots[field.slot].read;
            // A message field whose only rules are its type's own needs no
            // value, only its message.
            if let (Some(child), Kind::Message(index), None, true) = (
                field.value.message,
                read.shape.kind,
                read.wkt,
                read.shape.card == Card::Singular && field.value.only_message(),
            ) {
                let src = found.message(&msg.src, read.shape.number);
                self.message(child, &Msg::new(src, index, pool), Some(&here))?;
                continue;
            }
            if let (true, Card::Singular, Kind::Scalar(_) | Kind::Enum(_)) =
                (field.value.prim, read.shape.card, read.shape.kind)
            {
                let s = match read.shape.kind {
                    Kind::Scalar(s) => s,
                    _ => ScalarType::Int32,
                };
                let p = found
                    .last(&msg.src)
                    .map_or_else(|| value::zero(s), |raw| value::prim(raw, s));
                self.prim(&field.value, p, &here, false)?;
                continue;
            }
            let value = match read.shape.card {
                Card::Singular => value::singular(&found, &msg.src, read, pool),
                _ => Msg::new(msg.src.within(found.span), msg.index, pool).read(read),
            };
            self.value(&field.value, &value, &here, false)?;
        }
        self.depth -= 1;
        Ok(())
    }

    fn value(
        &mut self,
        plan: &'a ValuePlan,
        v: &Value<'a>,
        path: &Path<'_, 'a>,
        for_key: bool,
    ) -> Result<(), Box<Abort>> {
        if plan.ignore_zero && is_zero(v) {
            return Ok(());
        }
        for check in &plan.checks {
            match check {
                Check::Rule(rule) => match rule.program.passes(v, &self.clock) {
                    Ok(true) => {}
                    Ok(false) => self.failed(rule, v, path, for_key),
                    Err(e) => return Err(Box::new(Abort::Runtime(format!("{}: {e}", rule.id)))),
                },
                Check::DefinedEnum { values, path: rule } => {
                    if let Value::Int(n) = v {
                        self.defined(values, rule, *n, path, for_key);
                    }
                }
                Check::AnyIn {
                    url,
                    urls,
                    path: rule,
                    not,
                } => {
                    let Value::Message(m) = v else { continue };
                    let Prim::Str(url) = m.prim(url, ScalarType::String) else {
                        continue;
                    };
                    let listed = urls.iter().any(|u| u.as_bytes() == url);
                    if listed == *not {
                        let (id, message) = if *not {
                            ("any.not_in", "type URL must not be in the block list")
                        } else {
                            ("any.in", "type URL must be in the allow list")
                        };
                        self.report(
                            Some(path),
                            None,
                            RulePath::Elems(rule),
                            id,
                            message.into(),
                            for_key,
                        );
                    }
                }
            }
        }
        if let (Some(child), Value::Message(m)) = (plan.message, v) {
            self.message(child, m, Some(path))?;
        }
        if let (Some(items), Value::List(list)) = (&plan.items, v) {
            self.items(items, list, path)?;
        }
        if let (Some(entries), Value::Map(map)) = (&plan.entries, v) {
            self.entries(&entries.0, &entries.1, map, path)?;
        }
        Ok(())
    }

    /// [`value`](Self::value), for a plan whose checks all run on scalars.
    fn prim(
        &mut self,
        plan: &'a ValuePlan,
        p: Prim<'_>,
        path: &Path<'_, 'a>,
        for_key: bool,
    ) -> Result<(), Box<Abort>> {
        if plan.ignore_zero && p.is_zero() {
            return Ok(());
        }
        for check in &plan.checks {
            match check {
                Check::Rule(rule) => match rule.program.passes_prim(p, &self.clock) {
                    Some(true) => {}
                    Some(false) => self.failed(rule, &p.value(), path, for_key),
                    None => {
                        let v = p.value();
                        match rule.program.passes(&v, &self.clock) {
                            Ok(true) => {}
                            Ok(false) => self.failed(rule, &v, path, for_key),
                            Err(e) => {
                                return Err(Box::new(Abort::Runtime(format!("{}: {e}", rule.id))));
                            }
                        }
                    }
                },
                Check::DefinedEnum { values, path: rule } => {
                    if let Prim::Int(n) = p {
                        self.defined(values, rule, n, path, for_key);
                    }
                }
                Check::AnyIn { .. } => {}
            }
        }
        Ok(())
    }

    fn failed(&mut self, rule: &'a Rule, v: &Value<'_>, path: &Path<'_, 'a>, for_key: bool) {
        let message = failure(rule, v, &self.clock);
        self.report(
            Some(path),
            None,
            RulePath::Elems(&rule.path),
            &rule.id,
            message,
            for_key,
        );
    }

    fn defined(
        &mut self,
        values: &[i32],
        rule: &'a [Elem],
        n: i64,
        path: &Path<'_, 'a>,
        for_key: bool,
    ) {
        if i32::try_from(n).is_ok_and(|n| values.binary_search(&n).is_err()) {
            self.report(
                Some(path),
                None,
                RulePath::Elems(rule),
                "enum.defined_only",
                "value must be one of the defined enum values".into(),
                for_key,
            );
        }
    }

    fn items(
        &mut self,
        plan: &'a ValuePlan,
        list: &List<'a>,
        path: &Path<'_, 'a>,
    ) -> Result<(), Box<Abort>> {
        let mut result = Ok(());
        let mut i = 0;
        if plan.prim
            && list.prims(&mut |item| {
                let here = Path {
                    parent: path.parent,
                    elem: path.elem,
                    sub: Sub::Index(i),
                };
                i += 1;
                result = self.prim(plan, item, &here, false);
                result.is_ok()
            })
        {
            return result;
        }
        list.for_each(&mut |item| {
            let here = Path {
                parent: path.parent,
                elem: path.elem,
                sub: Sub::Index(i),
            };
            i += 1;
            result = self.value(plan, &item, &here, false);
            result.is_ok()
        });
        result
    }

    fn entries(
        &mut self,
        keys: &'a ValuePlan,
        values: &'a ValuePlan,
        map: &Map<'a>,
        path: &Path<'_, 'a>,
    ) -> Result<(), Box<Abort>> {
        let mut result = Ok(());
        map.for_each(&mut |k, v| {
            let here = Path {
                parent: path.parent,
                elem: path.elem,
                sub: Sub::Key(&k),
            };
            result = self
                .value(keys, &k, &here, true)
                .and_then(|()| self.value(values, &v, &here, false));
            result.is_ok()
        });
        result
    }

    fn report(
        &mut self,
        path: Option<&Path<'_, 'a>>,
        oneof: Option<&str>,
        rule: RulePath<'_>,
        id: &str,
        message: String,
        for_key: bool,
    ) {
        let mut elements = Vec::new();
        let mut at = path;
        while let Some(p) = at {
            elements.push(field_element(p));
            at = p.parent;
        }
        elements.reverse();
        if let Some(name) = oneof {
            elements.push(FieldPathElement {
                field_name: Some(Cow::Owned(name.to_owned())),
                ..FieldPathElement::default()
            });
        }
        let rule = match rule {
            RulePath::Elems(elems) => elems.iter().map(rule_element).collect(),
            RulePath::Required => vec![FieldPathElement {
                field_number: Some(25),
                field_name: Some(Cow::Borrowed("required")),
                field_type: Some(FieldType::Bool),
                ..FieldPathElement::default()
            }],
        };
        self.violations.push(Violation {
            field: FieldPath { elements },
            rule: FieldPath { elements: rule },
            rule_id: Cow::Owned(id.to_owned()),
            message: Cow::Owned(message),
            for_key,
        });
    }
}

/// A failed rule's message: the one its expression produced, or its own.
fn failure<'a>(rule: &'a Rule, v: &Value<'a>, clock: &Clock) -> String {
    match rule.program.eval(v, clock) {
        Ok(Outcome::Fail(Some(m))) => m.to_string(),
        _ => rule.message.to_string(),
    }
}

fn field_element(p: &Path<'_, '_>) -> FieldPathElement {
    let e = p.elem;
    let (key_type, value_type, subscript) = match &p.sub {
        Sub::None => (None, None, None),
        Sub::Index(i) => (None, None, Some(Subscript::Index(*i as u64))),
        Sub::Key(k) => (
            e.entry.map(|(k, _)| k),
            e.entry.map(|(_, v)| v),
            match k {
                Value::Bool(b) => Some(Subscript::BoolKey(*b)),
                Value::Int(i) => Some(Subscript::IntKey(*i)),
                Value::Uint(u) => Some(Subscript::UintKey(*u)),
                Value::String(s) => Some(Subscript::StringKey(Cow::Owned(s.to_string()))),
                _ => None,
            },
        ),
    };
    FieldPathElement {
        field_number: Some(e.number),
        field_name: Some(Cow::Owned(e.name.to_string())),
        field_type: Some(e.ty),
        key_type,
        value_type,
        subscript,
    }
}

fn rule_element(e: &Elem) -> FieldPathElement {
    FieldPathElement {
        field_number: Some(e.number),
        field_name: Some(Cow::Owned(e.name.to_string())),
        field_type: Some(e.ty),
        key_type: None,
        value_type: None,
        subscript: e.index.map(Subscript::Index),
    }
}

fn is_zero(v: &Value<'_>) -> bool {
    match v {
        Value::Null => true,
        Value::Bool(b) => !b,
        Value::Int(i) => *i == 0,
        Value::Uint(u) => *u == 0,
        Value::Double(d) => *d == 0.0,
        Value::String(s) => s.is_empty(),
        Value::Bytes(b) => b.is_empty(),
        Value::Duration(d) => d.is_zero(),
        Value::Timestamp(t) => t.timestamp() == 0 && t.timestamp_subsec_nanos() == 0,
        Value::List(l) => l.len() == 0,
        Value::Map(m) => m.len() == 0,
        Value::Message(m) => m.descriptor().fields().iter().all(|fd| !m.has(fd)),
        Value::Type(_) => false,
    }
}
