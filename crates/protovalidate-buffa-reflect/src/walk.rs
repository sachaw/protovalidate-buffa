//! Walking a message through reflection against its plan.

use std::borrow::Cow;

use buffa_descriptor::reflect::ReflectMessage;
use protovalidate_buffa::{FieldPath, FieldPathElement, FieldType, Subscript, Violation};

use crate::{
    cel::{
        Clock, Outcome,
        value::{List, Map, Msg, Value},
    },
    plan::{Check, Elem, MessagePlan, Plans, ValuePlan},
};

/// Why a validation stopped before it finished.
pub enum Abort {
    Compile(String),
    Runtime(String),
}

/// Where a value sits, as a chain of frames on the stack: the path is only
/// written out when a violation is reported.
struct Path<'p, 'a> {
    parent: Option<&'p Path<'p, 'a>>,
    elem: &'a Elem,
    sub: Sub<'a>,
}

enum Sub<'a> {
    None,
    Index(usize),
    Key(Value<'a>),
}

/// The rule a violation reports.
enum RulePath<'a> {
    Elems(&'a [Elem]),
    Required,
}

pub struct Walker<'a> {
    plans: &'a Plans,
    clock: Clock,
    pub violations: Vec<Violation>,
}

impl<'a> Walker<'a> {
    pub fn new(plans: &'a Plans) -> Self {
        Self {
            plans,
            clock: Clock::default(),
            violations: Vec::new(),
        }
    }

    pub fn root(&mut self, msg: &'a dyn ReflectMessage) -> Result<(), Abort> {
        self.message(0, &Msg::Ref(msg), None)
    }

    fn message(
        &mut self,
        plan: usize,
        msg: &Msg<'a>,
        path: Option<&Path<'_, 'a>>,
    ) -> Result<(), Abort> {
        let plans = self.plans;
        let plan: &'a MessagePlan = &plans.messages[plan];
        if let Some(e) = &plan.error {
            return Err(Abort::Compile(e.clone()));
        }
        if !plan.rules.is_empty() {
            let this = Value::Message(msg.clone());
            for rule in &plan.rules {
                match rule.program.eval(&this, &self.clock) {
                    Ok(Outcome::Pass) => {}
                    Ok(Outcome::Fail(m)) => {
                        let message = m.map_or_else(|| rule.message.to_string(), |m| m.to_string());
                        self.report(
                            path,
                            None,
                            RulePath::Elems(&rule.path),
                            &rule.id,
                            message,
                            false,
                        );
                    }
                    Err(e) => return Err(Abort::Runtime(format!("{}: {e}", rule.id))),
                }
            }
        }
        let md = msg.descriptor();
        for o in &plan.message_oneofs {
            let set = o
                .fields
                .iter()
                .filter(|&&f| msg.has(&md.fields()[f]))
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
        for (i, name) in &plan.oneofs {
            let oneof = &md.oneofs()[*i];
            let set = match msg {
                Msg::Ref(m) => m.which_oneof(oneof).is_some(),
                Msg::Owned(m) => m.which_oneof(oneof).is_some(),
                Msg::Default(..) => false,
            };
            if !set {
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
        for field in &plan.fields {
            if let Some(e) = &field.error {
                return Err(Abort::Compile(e.clone()));
            }
            let fd = &md.fields()[field.index];
            let present = msg.has(fd);
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
            let value = msg.field(field.index);
            self.value(&field.value, &value, &here, false)?;
        }
        Ok(())
    }

    fn value(
        &mut self,
        plan: &'a ValuePlan,
        v: &Value<'a>,
        path: &Path<'_, 'a>,
        for_key: bool,
    ) -> Result<(), Abort> {
        if plan.ignore_zero && is_zero(v) {
            return Ok(());
        }
        for check in &plan.checks {
            match check {
                Check::Rule(rule) => match rule.program.eval(v, &self.clock) {
                    Ok(Outcome::Pass) => {}
                    Ok(Outcome::Fail(m)) => {
                        let message = m.map_or_else(|| rule.message.to_string(), |m| m.to_string());
                        self.report(
                            Some(path),
                            None,
                            RulePath::Elems(&rule.path),
                            &rule.id,
                            message,
                            for_key,
                        );
                    }
                    Err(e) => return Err(Abort::Runtime(format!("{}: {e}", rule.id))),
                },
                Check::DefinedEnum { values, path: rule } => {
                    if let Value::Int(n) = v
                        && i32::try_from(*n).is_ok_and(|n| values.binary_search(&n).is_err())
                    {
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
                Check::AnyIn {
                    urls,
                    path: rule,
                    not,
                } => {
                    let Value::Message(m) = v else { continue };
                    let url = match m.field_by_name("type_url") {
                        Some(Value::String(s)) => s,
                        _ => continue,
                    };
                    let listed = urls.iter().any(|u| **u == *url);
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

    fn items(
        &mut self,
        plan: &'a ValuePlan,
        list: &List<'a>,
        path: &Path<'_, 'a>,
    ) -> Result<(), Abort> {
        for i in 0..list.len() {
            let Some(item) = list.get(i) else { continue };
            let here = Path {
                parent: path.parent,
                elem: path.elem,
                sub: Sub::Index(i),
            };
            self.value(plan, &item, &here, false)?;
        }
        Ok(())
    }

    fn entries(
        &mut self,
        keys: &'a ValuePlan,
        values: &'a ValuePlan,
        map: &Map<'a>,
        path: &Path<'_, 'a>,
    ) -> Result<(), Abort> {
        let mut result = Ok(());
        map.for_each(&mut |k, v| {
            let here = Path {
                parent: path.parent,
                elem: path.elem,
                sub: Sub::Key(k),
            };
            result = self
                .value(keys, &key_value(&here), &here, true)
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

fn key_value<'a>(p: &Path<'_, 'a>) -> Value<'a> {
    match &p.sub {
        Sub::Key(k) => k.clone(),
        _ => Value::Null,
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
        Value::Message(Msg::Default(..)) => true,
        Value::Message(m) => m.descriptor().fields().iter().all(|fd| !m.has(fd)),
        Value::Type(_) => false,
    }
}
