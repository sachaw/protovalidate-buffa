//! Compiling a message type's rules, read from its descriptors, into a plan.
//!
//! Standard rules are not special-cased: each rule field in `validate.proto`
//! carries its own CEL (its `predefined` option), exactly as a user's
//! predefined rule does, and is compiled with the rule's values folded in.
//! What `validate.proto` does not express in CEL (`required`, `ignore`,
//! oneofs, `enum.defined_only`, `any.in`, and descending into items, map
//! entries and messages) is planned natively, as in protovalidate's other
//! implementations.

use std::{collections::HashMap, sync::Arc};

use buffa::{
    ExtensionSet,
    unknown_fields::{UnknownFieldData, UnknownFields},
};
use buffa_descriptor::{
    DescriptorPool, EnumValueDescriptor, FieldDescriptor, FieldKind, MessageDescriptor,
    MessageIndex, ScalarType, SingularKind,
    features::FieldPresence,
    reflect::{DynamicMessage, ReflectCow, ReflectMessage, ValueRef},
};
use protovalidate_buffa::FieldType;

use crate::{
    cel::{
        Bindings, Program, Ty,
        value::{self, Const, ConstMsg, Msg, Read, Wkt},
    },
    wire::{Card, Kind, Src},
};

/// A path element, kept in a plan and written out only for a violation.
#[derive(Clone, Debug)]
pub struct Elem {
    pub number: i32,
    pub name: Box<str>,
    pub ty: FieldType,
    /// For a map field: its key and value types.
    pub entry: Option<(FieldType, FieldType)>,
    /// The index of a `cel` or `cel_expression` rule.
    pub index: Option<u64>,
}

/// Every message plan reached from one root type.
pub struct Plans {
    pub messages: Vec<MessagePlan>,
    /// The standard rules that do not run as native checks, by id.
    pub interpreted: Vec<Box<str>>,
    pub root: MessageIndex,
    /// The pool the plans index into, which this keeps alive.
    pub pool: Arc<DescriptorPool>,
}

#[derive(Default)]
pub struct MessagePlan {
    pub error: Option<String>,
    pub rules: Vec<Rule>,
    pub message_oneofs: Vec<MessageOneof>,
    /// Oneofs that require a member: their members, by slot, and name.
    pub oneofs: Vec<(Box<[usize]>, Box<str>)>,
    pub fields: Vec<FieldPlan>,
    /// The fields a walk reads, each in a slot.
    pub slots: Vec<Slot>,
    pub dispatch: Dispatch,
    /// Whether every check of the message, and of those it holds, runs on
    /// scalars read off the wire, so a quick pass can tell a valid message.
    pub quick: bool,
}

/// A field a walk reads: how, and the slots of the other members of its
/// oneof, which setting it clears.
pub struct Slot {
    pub read: value::Read,
    pub siblings: Box<[usize]>,
}

pub struct MessageOneof {
    /// The fields, by index while planning and by slot once laid out.
    pub fields: Box<[usize]>,
    pub names: Box<str>,
    pub required: bool,
}

pub struct FieldPlan {
    /// The field's index while planning, and its slot once laid out.
    pub slot: usize,
    pub op: Op,
    pub elem: Elem,
    pub required: bool,
    /// Unset fields are skipped: the field tracks presence, or the rules
    /// ignore its zero value.
    pub skip_unset: bool,
    pub error: Option<String>,
    pub value: ValuePlan,
}

/// How a walk checks a field, worked out once its plan is laid out.
#[derive(Clone, Copy)]
pub enum Op {
    /// A singular scalar (an enum as an int32) whose checks all run on the
    /// scalar read off the wire; with whether it has explicit presence.
    Prim(ScalarType, bool),
    /// A singular `Timestamp` or `Duration` whose checks all run on its
    /// seconds and nanoseconds read off the wire.
    Time(Wkt),
    /// A singular message checked by its type's rules alone: its plan.
    Message(usize, MessageIndex),
    /// Anything else, read as a CEL value.
    Value,
}

#[derive(Default)]
pub struct ValuePlan {
    /// Skips a zero item, key or value (`IGNORE_IF_ZERO_VALUE` below a
    /// repeated or map field).
    pub ignore_zero: bool,
    pub checks: Vec<Check>,
    /// The plan of an embedded message, by index into [`Plans::messages`].
    pub message: Option<usize>,
    pub items: Option<Box<Self>>,
    pub entries: Option<Box<(Self, Self)>>,
    /// Every check is a native check of a scalar, which runs on the scalar
    /// read off the wire, with no CEL value.
    pub prim: bool,
}

pub enum Check {
    Rule(Rule),
    DefinedEnum {
        values: Box<[i32]>,
        path: Box<[Elem]>,
    },
    AnyIn {
        /// How to read an `Any`'s `type_url`.
        url: Read,
        urls: Box<[Box<str>]>,
        path: Box<[Elem]>,
        not: bool,
    },
}

pub struct Rule {
    pub program: Program,
    pub id: Box<str>,
    pub message: Box<str>,
    pub path: Box<[Elem]>,
}

impl ValuePlan {
    /// Whether the value is a message checked by its own type's rules alone.
    pub const fn only_message(&self) -> bool {
        self.message.is_some()
            && !self.ignore_zero
            && self.checks.is_empty()
            && self.items.is_none()
            && self.entries.is_none()
    }

    const fn is_empty(&self) -> bool {
        self.checks.is_empty()
            && self.message.is_none()
            && self.items.is_none()
            && self.entries.is_none()
    }
}

/// The `buf.validate` extensions a pool declares.
struct Schema {
    field: Ext,
    message: Option<Ext>,
    oneof: Option<Ext>,
    predefined: Option<Ext>,
}

#[derive(Clone, Copy)]
struct Ext {
    number: u32,
    message: MessageIndex,
}

impl Schema {
    fn of(pool: &DescriptorPool) -> Option<Self> {
        let ext = |name: &str| -> Option<Ext> {
            let e = pool.extension(pool.extension_index(name)?);
            let FieldKind::Singular(SingularKind::Message(message)) = e.field().kind() else {
                return None;
            };
            Some(Ext {
                number: e.field().number(),
                message,
            })
        };
        Some(Self {
            field: ext("buf.validate.field")?,
            message: ext("buf.validate.message"),
            oneof: ext("buf.validate.oneof"),
            predefined: ext("buf.validate.predefined"),
        })
    }
}

/// Reads an extension out of an options message's unknown fields. Repeated
/// occurrences of a message field merge, as concatenating them does.
fn extension(
    pool: &Arc<DescriptorPool>,
    unknown: &UnknownFields,
    ext: Ext,
) -> Option<DynamicMessage> {
    let mut bytes = Vec::new();
    for f in unknown {
        if f.number == ext.number
            && let UnknownFieldData::LengthDelimited(data) = &f.data
        {
            bytes.extend_from_slice(data);
        }
    }
    if bytes.is_empty() {
        return None;
    }
    DynamicMessage::decode(Arc::clone(pool), ext.message, &bytes).ok()
}

/// A set field of a rules message, by name.
fn get<'m>(m: &'m dyn ReflectMessage, name: &str) -> Option<ValueRef<'m>> {
    let fd = m.message_descriptor().field_by_name(name)?;
    m.has(fd).then(|| m.get(fd))
}

fn get_bool(m: &dyn ReflectMessage, name: &str) -> bool {
    matches!(get(m, name), Some(ValueRef::Bool(true)))
}

fn get_message<'m>(m: &'m dyn ReflectMessage, name: &str) -> Option<ReflectCow<'m>> {
    match get(m, name)? {
        ValueRef::Message(c) => Some(c),
        _ => None,
    }
}

fn get_strings<'m>(m: &'m dyn ReflectMessage, name: &str) -> Vec<&'m str> {
    let mut out = Vec::new();
    if let Some(ValueRef::List(l)) = get(m, name) {
        for i in 0..l.len() {
            if let Some(ValueRef::String(s)) = l.get(i) {
                out.push(s);
            }
        }
    }
    out
}

fn get_messages<'m>(m: &'m dyn ReflectMessage, name: &str) -> Vec<ReflectCow<'m>> {
    let mut out = Vec::new();
    if let Some(ValueRef::List(l)) = get(m, name) {
        for i in 0..l.len() {
            if let Some(ValueRef::Message(c)) = l.get(i) {
                out.push(c);
            }
        }
    }
    out
}

const IGNORE_IF_ZERO_VALUE: i32 = 1;
const IGNORE_ALWAYS: i32 = 3;

fn ignore(rules: Option<&dyn ReflectMessage>) -> i32 {
    match rules.and_then(|r| get(r, "ignore")) {
        Some(ValueRef::EnumNumber(n)) => n,
        _ => 0,
    }
}

pub fn field_type(fd: &FieldDescriptor, kind: SingularKind) -> FieldType {
    match kind {
        SingularKind::Scalar(s) => scalar_type(s),
        SingularKind::Enum(_) => FieldType::Enum,
        SingularKind::Message(_) if fd.is_delimited() => FieldType::Group,
        SingularKind::Message(_) => FieldType::Message,
    }
}

const fn scalar_type(s: ScalarType) -> FieldType {
    match s {
        ScalarType::Double => FieldType::Double,
        ScalarType::Float => FieldType::Float,
        ScalarType::Int64 => FieldType::Int64,
        ScalarType::Uint64 => FieldType::Uint64,
        ScalarType::Int32 => FieldType::Int32,
        ScalarType::Fixed64 => FieldType::Fixed64,
        ScalarType::Fixed32 => FieldType::Fixed32,
        ScalarType::Bool => FieldType::Bool,
        ScalarType::String => FieldType::String,
        ScalarType::Bytes => FieldType::Bytes,
        ScalarType::Uint32 => FieldType::Uint32,
        ScalarType::Sfixed32 => FieldType::Sfixed32,
        ScalarType::Sfixed64 => FieldType::Sfixed64,
        ScalarType::Sint32 => FieldType::Sint32,
        ScalarType::Sint64 => FieldType::Sint64,
    }
}

fn elem(fd: &FieldDescriptor, name: Option<String>) -> Elem {
    let (ty, entry) = match fd.kind() {
        FieldKind::Singular(k) | FieldKind::List(k) => (field_type(fd, k), None),
        FieldKind::Map { key, value } => (
            FieldType::Message,
            Some((scalar_type(key), field_type(fd, value))),
        ),
    };
    Elem {
        number: i32::try_from(fd.number()).unwrap_or(i32::MAX),
        name: name.unwrap_or_else(|| fd.name().to_owned()).into(),
        ty,
        entry,
        index: None,
    }
}

/// Where a value sits: a field, or an item, key or value of one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Site {
    Field,
    Item,
    Key,
    Value,
}

pub struct Builder<'p> {
    pool: &'p Arc<DescriptorPool>,
    interpreted: std::cell::RefCell<Vec<Box<str>>>,
    schema: Option<Schema>,
    plans: Vec<MessagePlan>,
    index: HashMap<MessageIndex, usize>,
}

impl<'p> Builder<'p> {
    pub fn new(pool: &'p Arc<DescriptorPool>) -> Self {
        Self {
            pool,
            interpreted: std::cell::RefCell::default(),
            schema: Schema::of(pool),
            plans: Vec::new(),
            index: HashMap::new(),
        }
    }

    /// Plans `root` and every message type it reaches.
    pub fn build(mut self, root: MessageIndex) -> Plans {
        self.message(root);
        prune(&mut self.plans);
        let mut types: Vec<_> = self.index.iter().map(|(&m, &i)| (i, m)).collect();
        types.sort_unstable_by_key(|&(i, _)| i);
        for (i, m) in types {
            layout(&mut self.plans[i], self.pool.message(m), self.pool);
        }
        mark_quick(&mut self.plans);
        Plans {
            messages: self.plans,
            root,
            pool: Arc::clone(self.pool),
            interpreted: self.interpreted.into_inner(),
        }
    }

    fn message(&mut self, idx: MessageIndex) -> usize {
        if let Some(&i) = self.index.get(&idx) {
            return i;
        }
        let i = self.plans.len();
        self.plans.push(MessagePlan::default());
        self.index.insert(idx, i);
        let plan = self.message_plan(idx);
        self.plans[i] = plan;
        i
    }

    fn message_plan(&mut self, idx: MessageIndex) -> MessagePlan {
        let pool = self.pool;
        let md = pool.message(idx);
        let mut plan = MessagePlan::default();
        let Some(schema) = &self.schema else {
            return plan;
        };
        let (message_ext, oneof_ext) = (schema.message, schema.oneof);
        let rules = message_ext.and_then(|ext| {
            md.options()
                .and_then(|o| extension(pool, o.unknown_fields(), ext))
        });
        let rules = rules.as_ref().map(|r| r as &dyn ReflectMessage);

        if let Some(r) = rules {
            let this = Ty::Message(idx);
            let exprs = get_strings(r, "cel_expression")
                .into_iter()
                .map(|e| (e.to_owned(), String::new(), e.to_owned()));
            let cel = get_messages(r, "cel")
                .into_iter()
                .map(|rule| rule_parts(&*rule));
            for (id, message, expression) in exprs.chain(cel) {
                match self.rule(&expression, this.clone(), &[], id, message, Box::new([])) {
                    Ok(Some(rule)) => plan.rules.push(rule),
                    Ok(None) => {}
                    Err(e) => {
                        plan.error = Some(e);
                        return plan;
                    }
                }
            }
        }

        let mut in_message_oneof = vec![false; md.fields().len()];
        for rule in rules.map(|r| get_messages(r, "oneof")).unwrap_or_default() {
            match message_oneof(md, &*rule) {
                Ok(o) => {
                    for &f in &o.fields {
                        in_message_oneof[f] = true;
                    }
                    plan.message_oneofs.push(o);
                }
                Err(e) => {
                    plan.error = Some(e);
                    return plan;
                }
            }
        }

        for o in md.oneofs() {
            let required = oneof_ext
                .and_then(|ext| {
                    o.options()
                        .and_then(|opts| extension(pool, opts.unknown_fields(), ext))
                })
                .is_some_and(|r| get_bool(&r, "required"));
            if required && !o.is_synthetic() {
                let members = o.field_indices().iter().map(|&f| usize::from(f)).collect();
                plan.oneofs.push((members, o.name().into()));
            }
        }

        for (i, fd) in md.fields().iter().enumerate() {
            if let Some(f) = self.field(i, fd, in_message_oneof[i]) {
                plan.fields.push(f);
            }
        }
        plan
    }

    fn field(
        &mut self,
        index: usize,
        fd: &FieldDescriptor,
        in_message_oneof: bool,
    ) -> Option<FieldPlan> {
        let pool = self.pool;
        let ext = self.schema.as_ref()?.field;
        let rules = fd
            .options()
            .and_then(|o| extension(pool, o.unknown_fields(), ext));
        let rules = rules.as_ref().map(|r| r as &dyn ReflectMessage);
        let mut ignore = ignore(rules);
        if ignore == IGNORE_ALWAYS {
            return None;
        }
        if in_message_oneof && rules.is_some() && rules.and_then(|r| get(r, "ignore")).is_none() {
            ignore = IGNORE_IF_ZERO_VALUE;
        }
        let presence = fd.presence() == FieldPresence::Explicit
            || fd.oneof_index().is_some()
            || matches!(fd.kind(), FieldKind::Singular(SingularKind::Message(_)));
        let (value, error) = match self.value(fd, rules, Site::Field, &[]) {
            Ok(v) => (v, None),
            Err(e) => (ValuePlan::default(), Some(e)),
        };
        Some(FieldPlan {
            slot: index,
            op: Op::Value,
            elem: elem(fd, None),
            required: rules.is_some_and(|r| get_bool(r, "required")),
            skip_unset: presence || ignore == IGNORE_IF_ZERO_VALUE,
            error,
            value,
        })
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the steps of planning one value, in order"
    )]
    fn value(
        &mut self,
        fd: &FieldDescriptor,
        rules: Option<&dyn ReflectMessage>,
        site: Site,
        prefix: &[Elem],
    ) -> Result<ValuePlan, String> {
        let pool = self.pool;
        let mut plan = ValuePlan::default();
        if ignore(rules) == IGNORE_ALWAYS {
            return Ok(plan);
        }
        plan.ignore_zero = site != Site::Field && ignore(rules) == IGNORE_IF_ZERO_VALUE;

        let kind = match (site, fd.kind()) {
            (Site::Field, _) => None,
            (Site::Item, FieldKind::List(k)) => Some(k),
            (Site::Key, FieldKind::Map { key, .. }) => Some(SingularKind::Scalar(key)),
            (Site::Value, FieldKind::Map { value, .. }) => Some(value),
            _ => return Err(format!("{} is not repeated or a map", fd.name())),
        };
        let this = match (kind, fd.kind()) {
            (Some(k), _) | (None, FieldKind::Singular(k)) => Ty::of_singular(k, pool),
            (None, _) => Ty::of_field(fd, pool),
        };
        // The element this value holds, unless it is a whole list or map.
        let singular = match (kind, fd.kind()) {
            (Some(k), _) | (None, FieldKind::Singular(k)) => Some(k),
            _ => None,
        };

        if let Some(r) = rules {
            let field_rules = self.pool.message(
                self.schema
                    .as_ref()
                    .expect("rules imply a schema")
                    .field
                    .message,
            );
            for (name, list) in [("cel_expression", true), ("cel", false)] {
                let Some(rule_fd) = field_rules.field_by_name(name) else {
                    continue;
                };
                let parts: Vec<_> = if list {
                    get_strings(r, name)
                        .into_iter()
                        .map(|e| (e.to_owned(), String::new(), e.to_owned()))
                        .collect()
                } else {
                    get_messages(r, name)
                        .into_iter()
                        .map(|m| rule_parts(&*m))
                        .collect()
                };
                for (i, (id, message, expression)) in parts.into_iter().enumerate() {
                    let mut path = prefix.to_vec();
                    let mut e = elem(rule_fd, None);
                    e.index = Some(i as u64);
                    path.push(e);
                    if let Some(rule) =
                        self.rule(&expression, this.clone(), &[], id, message, path.into())?
                    {
                        plan.checks.push(Check::Rule(rule));
                    }
                }
            }
        }

        let message = match singular {
            Some(SingularKind::Message(m)) => Some(m),
            _ => None,
        };
        if let Some(m) = message {
            plan.message = Some(self.message(m));
        }

        let type_rules = rules.and_then(|r| {
            let oneof = r
                .message_descriptor()
                .oneofs()
                .iter()
                .find(|o| o.name() == "type")?;
            let fd = r.which_oneof(oneof)?;
            match r.get(fd) {
                ValueRef::Message(m) => Some((fd.clone(), m.to_dynamic())),
                _ => None,
            }
        });
        if let Some((type_fd, type_rules)) = &type_rules {
            let wkt = message.and_then(|m| value::wkt(pool.message(m)));
            let expected = match (site, fd.kind()) {
                (Site::Field, FieldKind::Map { .. }) => Some("map".to_owned()),
                (Site::Field, FieldKind::List(_)) => Some("repeated".to_owned()),
                _ => match singular {
                    Some(SingularKind::Scalar(s)) => Some(scalar_rules(s).to_owned()),
                    Some(SingularKind::Enum(_)) => Some("enum".to_owned()),
                    Some(SingularKind::Message(m)) => match wkt {
                        Some(Wkt::Any) => Some("any".to_owned()),
                        Some(Wkt::Duration) => Some("duration".to_owned()),
                        Some(Wkt::FieldMask) => Some("field_mask".to_owned()),
                        Some(Wkt::Timestamp) => Some("timestamp".to_owned()),
                        Some(Wkt::Wrapper) => {
                            Some(scalar_rules(wrapped(pool.message(m))).to_owned())
                        }
                        _ => None,
                    },
                    None => None,
                },
            };
            match expected {
                Some(e) if e != type_fd.name() => {
                    return Err(format!(
                        "expected rule \"buf.validate.FieldRules.{e}\", got \"buf.validate.FieldRules.{}\" on field \"{}\"",
                        type_fd.name(),
                        fd.name()
                    ));
                }
                None if message.is_some() => {
                    return Err(format!(
                        "mismatched message rules, \"buf.validate.FieldRules.{}\" is not a valid rule for field \"{}\"",
                        type_fd.name(),
                        fd.name()
                    ));
                }
                _ => {}
            }
            let this = match (wkt, message) {
                (Some(Wkt::Wrapper), Some(m)) => Ty::of_scalar(wrapped(pool.message(m))),
                _ => this,
            };
            self.standard(&mut plan, type_fd, type_rules, &this, fd, singular, prefix)?;
        }

        if let (Site::Field, FieldKind::Map { .. }) = (site, fd.kind()) {
            let map = type_rules
                .as_ref()
                .filter(|(t, _)| t.name() == "map")
                .map(|(t, r)| (t, r));
            let (keys, values) = match map {
                Some((_, r)) => (get_message(r, "keys"), get_message(r, "values")),
                None => (None, None),
            };
            let path = |name: &str| -> Vec<Elem> {
                let mut p = prefix.to_vec();
                let (t, r) = map.expect("named only with map rules");
                p.push(elem(t, None));
                p.push(elem(
                    r.message_descriptor()
                        .field_by_name(name)
                        .expect("MapRules has keys and values"),
                    None,
                ));
                p
            };
            let key_plan = match &keys {
                Some(k) => self.value(fd, Some(&**k), Site::Key, &path("keys"))?,
                None => self.value(fd, None, Site::Key, prefix)?,
            };
            let value_plan = match &values {
                Some(v) => self.value(fd, Some(&**v), Site::Value, &path("values"))?,
                None => self.value(fd, None, Site::Value, prefix)?,
            };
            if !key_plan.is_empty() || !value_plan.is_empty() {
                plan.entries = Some(Box::new((key_plan, value_plan)));
            }
        }

        if let (Site::Field, FieldKind::List(_)) = (site, fd.kind()) {
            let repeated = type_rules.as_ref().filter(|(t, _)| t.name() == "repeated");
            let items = repeated.and_then(|(_, r)| get_message(r, "items"));
            let items_plan = match (&items, repeated) {
                (Some(i), Some((t, r))) => {
                    let mut p = prefix.to_vec();
                    p.push(elem(t, None));
                    p.push(elem(
                        r.message_descriptor()
                            .field_by_name("items")
                            .expect("RepeatedRules has items"),
                        None,
                    ));
                    self.value(fd, Some(&**i), Site::Item, &p)?
                }
                _ => self.value(fd, None, Site::Item, prefix)?,
            };
            if !items_plan.is_empty() {
                plan.items = Some(Box::new(items_plan));
            }
        }
        Ok(plan)
    }

    /// The standard and predefined rules set in a `FieldRules.type` message.
    #[expect(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the value's whole context; native rules, then predefined rules"
    )]
    fn standard(
        &self,
        plan: &mut ValuePlan,
        type_fd: &FieldDescriptor,
        type_rules: &DynamicMessage,
        this: &Ty,
        fd: &FieldDescriptor,
        singular: Option<SingularKind>,
        prefix: &[Elem],
    ) -> Result<(), String> {
        let pool = self.pool;
        let type_elem = elem(type_fd, None);
        let rules_md = type_rules.message_descriptor();
        let rules_idx = pool.message_index(rules_md.full_name());
        let Some(rules_index) = rules_idx else {
            return Err(format!("{} is not in the pool", rules_md.full_name()));
        };
        let rules_msg = ConstMsg {
            bytes: type_rules.encode_to_vec().into(),
            index: rules_index,
            pool: Arc::clone(pool),
        };
        let rules = Msg::new(Src::Bytes(&rules_msg.bytes), rules_index, pool);
        let mut set: Vec<(FieldDescriptor, Elem, Const)> = Vec::new();
        type_rules.for_each_set(&mut |rule_fd, _| {
            let declared = rules_md.field(rule_fd.number()).is_some();
            let name = if declared {
                None
            } else {
                rules_idx
                    .and_then(|i| pool.extension_for(i, rule_fd.number()))
                    .map(|e| format!("[{}]", e.full_name()))
            };
            set.push((
                rule_fd.clone(),
                elem(rule_fd, name),
                read_const(&rules, rules_md, rule_fd, pool),
            ));
        });
        let rules_const = Const::Message(Arc::new(rules_msg));
        // Declared rules first, in field order; then extensions by number.
        set.sort_by_key(|(f, e, _)| {
            (
                e.name.starts_with('['),
                rules_md
                    .fields()
                    .iter()
                    .position(|d| d.number() == f.number())
                    .unwrap_or(usize::MAX),
                f.number(),
            )
        });

        for (rule_fd, rule_elem, rule_value) in set {
            if type_fd.name() == "enum" && rule_fd.name() == "defined_only" {
                if matches!(rule_value, Const::Bool(true))
                    && let Some(SingularKind::Enum(e)) = singular
                {
                    let mut values: Vec<i32> = pool
                        .enumeration(e)
                        .values()
                        .iter()
                        .map(EnumValueDescriptor::number)
                        .collect();
                    values.sort_unstable();
                    let mut path = prefix.to_vec();
                    path.push(type_elem.clone());
                    path.push(rule_elem);
                    plan.checks.push(Check::DefinedEnum {
                        values: values.into(),
                        path: path.into(),
                    });
                }
                continue;
            }
            if type_fd.name() == "any" && matches!(rule_fd.name(), "in" | "not_in") {
                let urls: Vec<Box<str>> = match &rule_value {
                    Const::List(l) => l
                        .iter()
                        .filter_map(|c| match c {
                            Const::String(s) => Some(s.clone()),
                            _ => None,
                        })
                        .collect(),
                    _ => Vec::new(),
                };
                let url = match singular {
                    Some(SingularKind::Message(m)) => {
                        let md = pool.message(m);
                        md.field_by_name("type_url")
                            .map(|fd| Read::of(md, fd, pool))
                    }
                    _ => None,
                };
                if let (false, Some(url)) = (urls.is_empty(), url) {
                    let mut path = prefix.to_vec();
                    path.push(type_elem.clone());
                    path.push(rule_elem);
                    plan.checks.push(Check::AnyIn {
                        url,
                        urls: urls.into(),
                        path: path.into(),
                        not: rule_fd.name() == "not_in",
                    });
                }
                continue;
            }
            let Some(predefined) = self.schema.as_ref().and_then(|s| s.predefined) else {
                continue;
            };
            let Some(predefined) = rule_fd
                .options()
                .and_then(|o| extension(pool, o.unknown_fields(), predefined))
            else {
                continue;
            };
            let consts = [("rules", rules_const.clone()), ("rule", rule_value)];
            for rule in get_messages(&predefined, "cel") {
                let (id, message, expression) = rule_parts(&*rule);
                let mut path = prefix.to_vec();
                path.push(type_elem.clone());
                path.push(rule_elem.clone());
                if let Some(rule) = self
                    .rule(&expression, this.clone(), &consts, id, message, path.into())
                    .map_err(|e| {
                        format!(
                            "failed to compile rule {} on {}: {e}",
                            rule_elem.name,
                            fd.name()
                        )
                    })?
                {
                    if !rule.program.is_native() && !rule_elem.name.starts_with('[') {
                        self.interpreted.borrow_mut().push(rule.id.clone());
                    }
                    plan.checks.push(Check::Rule(rule));
                }
            }
        }
        Ok(())
    }

    fn rule(
        &self,
        expression: &str,
        this: Ty,
        consts: &[(&'static str, Const)],
        id: String,
        message: String,
        path: Box<[Elem]>,
    ) -> Result<Option<Rule>, String> {
        let bindings = Bindings {
            pool: self.pool,
            this,
            consts,
        };
        let program = Program::compile(expression, &bindings).map_err(|e| e.0)?;
        let message = if message.is_empty() {
            format!("{expression:?} returned false")
        } else {
            message
        };
        Ok(program.map(|program| Rule {
            program,
            id: id.into(),
            message: message.into(),
            path,
        }))
    }
}

fn rule_parts(rule: &dyn ReflectMessage) -> (String, String, String) {
    let s = |name| match get(rule, name) {
        Some(ValueRef::String(s)) => s.to_owned(),
        _ => String::new(),
    };
    (s("id"), s("message"), s("expression"))
}

fn message_oneof(
    md: &MessageDescriptor,
    rule: &dyn ReflectMessage,
) -> Result<MessageOneof, String> {
    let names = get_strings(rule, "fields");
    if names.is_empty() {
        return Err(format!(
            "at least one field must be specified in oneof rule for the message {}",
            md.full_name()
        ));
    }
    let mut fields = Vec::with_capacity(names.len());
    for name in &names {
        let Some(i) = md.fields().iter().position(|f| f.name() == *name) else {
            return Err(format!(
                "field {name} not found in message {}",
                md.full_name()
            ));
        };
        if fields.contains(&i) {
            return Err(format!(
                "duplicate {name} in oneof rule for the message {}",
                md.full_name()
            ));
        }
        fields.push(i);
    }
    Ok(MessageOneof {
        fields: fields.into(),
        names: names.join(", ").into(),
        required: get_bool(rule, "required"),
    })
}

const fn scalar_rules(s: ScalarType) -> &'static str {
    match s {
        ScalarType::Double => "double",
        ScalarType::Float => "float",
        ScalarType::Int64 => "int64",
        ScalarType::Uint64 => "uint64",
        ScalarType::Int32 => "int32",
        ScalarType::Fixed64 => "fixed64",
        ScalarType::Fixed32 => "fixed32",
        ScalarType::Bool => "bool",
        ScalarType::String => "string",
        ScalarType::Bytes => "bytes",
        ScalarType::Uint32 => "uint32",
        ScalarType::Sfixed32 => "sfixed32",
        ScalarType::Sfixed64 => "sfixed64",
        ScalarType::Sint32 => "sint32",
        ScalarType::Sint64 => "sint64",
    }
}

/// The scalar a wrapper type wraps.
fn wrapped(md: &MessageDescriptor) -> ScalarType {
    match md.fields().first().map(FieldDescriptor::kind) {
        Some(FieldKind::Singular(SingularKind::Scalar(s))) => s,
        _ => ScalarType::Bytes,
    }
}

/// Drops what can never report: messages with no rules anywhere below them,
/// and fields that only lead to such messages.
fn prune(plans: &mut [MessagePlan]) {
    let n = plans.len();
    let mut live = vec![false; n];
    loop {
        let mut changed = false;
        for i in 0..n {
            if !live[i] && message_live(&plans[i], &live) {
                live[i] = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    for plan in plans.iter_mut() {
        for f in &mut plan.fields {
            prune_value(&mut f.value, &live);
        }
        plan.fields
            .retain(|f| f.required || f.error.is_some() || !f.value.is_empty());
    }
}

fn message_live(plan: &MessagePlan, live: &[bool]) -> bool {
    plan.error.is_some()
        || !plan.rules.is_empty()
        || !plan.message_oneofs.is_empty()
        || !plan.oneofs.is_empty()
        || plan
            .fields
            .iter()
            .any(|f| f.required || f.error.is_some() || value_live(&f.value, live))
}

fn value_live(v: &ValuePlan, live: &[bool]) -> bool {
    !v.checks.is_empty()
        || v.message.is_some_and(|m| live[m])
        || v.items.as_ref().is_some_and(|i| value_live(i, live))
        || v.entries
            .as_ref()
            .is_some_and(|e| value_live(&e.0, live) || value_live(&e.1, live))
}

/// Marks the plans a quick pass covers: no rule of the message itself, and
/// each field's checks on scalars, of messages the pass covers too.
fn mark_quick(plans: &mut [MessagePlan]) {
    for p in plans.iter_mut() {
        p.quick = p.error.is_none()
            && p.rules.is_empty()
            && p.message_oneofs.is_empty()
            && p.fields
                .iter()
                .all(|f| f.error.is_none() && quick_field(f, &p.slots[f.slot].read));
    }
    // A cycle of message types stays covered unless one of them is not.
    loop {
        let mut changed = false;
        for i in 0..plans.len() {
            let child = |f: &FieldPlan| match f.op {
                Op::Message(c, _) => Some(c),
                _ => None,
            };
            if plans[i].quick
                && plans[i]
                    .fields
                    .iter()
                    .filter_map(child)
                    .any(|c| !plans[c].quick)
            {
                plans[i].quick = false;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

fn quick_field(f: &FieldPlan, read: &Read) -> bool {
    let v = &f.value;
    match f.op {
        Op::Prim(..) | Op::Time(_) | Op::Message(..) => true,
        Op::Value => {
            v.message.is_none()
                && match (read.shape.card, read.wkt) {
                    (Card::List, _) => {
                        v.checks.is_empty()
                            && v.entries.is_none()
                            && v.items.as_ref().is_some_and(|i| i.prim)
                    }
                    (Card::Map(_), _) => {
                        v.checks.is_empty()
                            && v.items.is_none()
                            && v.entries.as_ref().is_some_and(|e| e.0.prim && e.1.prim)
                    }
                    (Card::Singular, Some(Wkt::Wrapper)) => v.prim,
                    (Card::Singular, Some(Wkt::Any)) => {
                        !v.ignore_zero
                            && v.items.is_none()
                            && v.entries.is_none()
                            && v.checks.iter().all(|c| matches!(c, Check::AnyIn { .. }))
                    }
                    _ => false,
                }
        }
    }
}

/// Marks the value plans whose checks all run on scalars.
fn mark_prim(v: &mut ValuePlan) {
    v.prim = v.message.is_none()
        && v.items.is_none()
        && v.entries.is_none()
        && v.checks.iter().all(|c| match c {
            Check::Rule(r) => r.program.is_scalar(),
            Check::DefinedEnum { .. } => true,
            Check::AnyIn { .. } => false,
        });
    if let Some(items) = &mut v.items {
        mark_prim(items);
    }
    if let Some(entries) = &mut v.entries {
        mark_prim(&mut entries.0);
        mark_prim(&mut entries.1);
    }
}

fn prune_value(v: &mut ValuePlan, live: &[bool]) {
    if v.message.is_some_and(|m| !live[m]) {
        v.message = None;
    }
    if let Some(items) = &mut v.items {
        prune_value(items, live);
        if items.is_empty() {
            v.items = None;
        }
    }
    if let Some(entries) = &mut v.entries {
        prune_value(&mut entries.0, live);
        prune_value(&mut entries.1, live);
        if entries.0.is_empty() && entries.1.is_empty() {
            v.entries = None;
        }
    }
}

/// A rule's value, read from the encoded rules.
fn read_const(
    rules: &Msg<'_>,
    md: &MessageDescriptor,
    fd: &FieldDescriptor,
    pool: &DescriptorPool,
) -> Const {
    let read = Read::of(md, fd, pool);
    rules.read(&read).to_const()
}

/// Gives each field a walk reads a slot, and a dispatch from field numbers
/// to slots.
fn layout(plan: &mut MessagePlan, md: &MessageDescriptor, pool: &DescriptorPool) {
    let mut by_field: Vec<Option<usize>> = vec![None; md.fields().len()];
    let mut order: Vec<usize> = Vec::new();
    let mut slot = |f: usize, by_field: &mut Vec<Option<usize>>| -> usize {
        if let Some(s) = by_field[f] {
            return s;
        }
        // Setting a oneof member clears the others, so a slot for one is a
        // slot for all.
        let members: Vec<usize> = md.fields()[f].oneof_index().map_or_else(
            || vec![f],
            |o| {
                md.oneofs()[usize::from(o)]
                    .field_indices()
                    .iter()
                    .map(|&i| usize::from(i))
                    .collect()
            },
        );
        for m in members {
            if by_field[m].is_none() {
                by_field[m] = Some(order.len());
                order.push(m);
            }
        }
        by_field[f].expect("just given a slot")
    };
    for field in &mut plan.fields {
        let read = Read::of(md, &md.fields()[field.slot], pool);
        field.slot = slot(field.slot, &mut by_field);
        mark_prim(&mut field.value);
        field.op = match (read.shape.card, read.shape.kind, read.wkt) {
            (Card::Singular, Kind::Scalar(s), _) if field.value.prim => {
                Op::Prim(s, read.shape.explicit)
            }
            (Card::Singular, Kind::Enum(_), _) if field.value.prim => {
                Op::Prim(ScalarType::Int32, read.shape.explicit)
            }
            (Card::Singular, Kind::Message(_), Some(w @ (Wkt::Timestamp | Wkt::Duration)))
                if field.value.prim =>
            {
                Op::Time(w)
            }
            (Card::Singular, Kind::Message(m), None) if field.value.only_message() => {
                Op::Message(field.value.message.unwrap_or_default(), m)
            }
            _ => Op::Value,
        };
    }
    let mut read = Vec::new();
    for rule in &plan.rules {
        rule.program.reads(&mut |n| read.push(n));
    }
    for n in read {
        if let Some(f) = md.fields().iter().position(|f| f.number() == n) {
            slot(f, &mut by_field);
        }
    }
    for o in &mut plan.message_oneofs {
        o.fields = o.fields.iter().map(|&f| slot(f, &mut by_field)).collect();
    }
    for (members, _) in &mut plan.oneofs {
        *members = members.iter().map(|&f| slot(f, &mut by_field)).collect();
    }
    plan.slots = order
        .iter()
        .map(|&f| {
            let fd = &md.fields()[f];
            let siblings = fd.oneof_index().map_or_else(Box::default, |o| {
                md.oneofs()[usize::from(o)]
                    .field_indices()
                    .iter()
                    .map(|&i| usize::from(i))
                    .filter(|&i| i != f)
                    .filter_map(|i| by_field[i])
                    .collect()
            });
            Slot {
                read: Read::of(md, fd, pool),
                siblings,
            }
        })
        .collect();
    plan.dispatch = Dispatch::new(
        order
            .iter()
            .zip(&plan.slots)
            .enumerate()
            .map(|(s, (&f, slot))| (md.fields()[f].number(), Route::of(s, slot))),
    );
}

/// Where a field number goes in a walk: its slot, the wire types it takes
/// (a bit per type), and what else taking one needs.
#[derive(Clone, Copy)]
pub struct Route {
    pub slot: u16,
    pub wires: u8,
    pub flags: u8,
}

impl Route {
    /// A closed enum's value, which must be one the enum declares.
    pub const CLOSED: u8 = 1;
    /// A oneof member, which clears the others.
    pub const SIBLINGS: u8 = 2;
    /// A packed list, whose empty runs hold nothing.
    pub const PACKED: u8 = 4;

    fn of(slot: usize, s: &Slot) -> Self {
        let shape = &s.read.shape;
        let mut flags = 0;
        if matches!(shape.kind, Kind::Enum(Some(_))) && !matches!(shape.card, Card::Map(_)) {
            flags |= Self::CLOSED;
        }
        if !s.siblings.is_empty() {
            flags |= Self::SIBLINGS;
        }
        if shape.card == Card::List && shape.kind.packable() {
            flags |= Self::PACKED;
        }
        Self {
            slot: u16::try_from(slot).unwrap_or(u16::MAX),
            wires: shape.wires(),
            flags,
        }
    }
}

/// Field numbers to routes.
#[derive(Default)]
pub enum Dispatch {
    /// Indexed by field number.
    Dense(Box<[Option<Route>]>),
    /// Sorted by field number.
    Sparse(Box<[(u32, Route)]>),
    #[default]
    None,
}

impl Dispatch {
    fn new(routes: impl Iterator<Item = (u32, Route)>) -> Self {
        let mut pairs: Vec<(u32, Route)> = routes.collect();
        let Some(max) = pairs.iter().map(|p| p.0).max() else {
            return Self::None;
        };
        if max as usize <= 64 + 4 * pairs.len() {
            let mut dense = vec![None; max as usize + 1];
            for (n, r) in pairs {
                dense[n as usize] = Some(r);
            }
            Self::Dense(dense.into())
        } else {
            pairs.sort_unstable_by_key(|p| p.0);
            Self::Sparse(pairs.into())
        }
    }

    #[inline]
    pub fn route(&self, number: u32) -> Option<Route> {
        match self {
            Self::Dense(d) => d.get(number as usize).copied().flatten(),
            Self::Sparse(p) => p
                .binary_search_by_key(&number, |&(n, _)| n)
                .ok()
                .map(|i| p[i].1),
            Self::None => None,
        }
    }

    #[inline]
    pub fn get(&self, number: u32) -> Option<usize> {
        self.route(number).map(|r| usize::from(r.slot))
    }
}
