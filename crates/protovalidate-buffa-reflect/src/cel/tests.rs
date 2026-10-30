//! The compiled tree against the `cel` interpreter: every expression here
//! must reach the same outcome on both.

use std::sync::Arc;

use buffa_descriptor::{
    DescriptorPool,
    generated::descriptor::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MessageOptions,
        field_descriptor_proto::{Label, Type},
    },
    reflect::{DynamicMessage, MapKey, MapValue, ReflectMessage, ReflectMessageMut, Value as V},
};

use super::{Bindings, Clock, Outcome, Program, Ty, fallback, value::Value};

fn field(
    name: &str,
    number: i32,
    label: Label,
    ty: Type,
    type_name: Option<&str>,
) -> FieldDescriptorProto {
    FieldDescriptorProto {
        name: Some(name.into()),
        number: Some(number),
        label: Some(label),
        r#type: Some(ty),
        type_name: type_name.map(Into::into),
        json_name: Some(name.into()),
        ..Default::default()
    }
}

/// `t.Test { int32 a; string s; repeated int32 xs; double d; map<string, int32> m; Test n; bytes b }`.
fn pool() -> Arc<DescriptorPool> {
    use Label::{LABEL_OPTIONAL as O, LABEL_REPEATED as R};
    let entry = DescriptorProto {
        name: Some("MEntry".into()),
        field: vec![
            field("key", 1, O, Type::TYPE_STRING, None),
            field("value", 2, O, Type::TYPE_INT32, None),
        ],
        options: MessageOptions {
            map_entry: Some(true),
            ..Default::default()
        }
        .into(),
        ..Default::default()
    };
    let test = DescriptorProto {
        name: Some("Test".into()),
        field: vec![
            field("a", 1, O, Type::TYPE_INT32, None),
            field("s", 2, O, Type::TYPE_STRING, None),
            field("xs", 3, R, Type::TYPE_INT32, None),
            field("d", 4, O, Type::TYPE_DOUBLE, None),
            field("m", 5, R, Type::TYPE_MESSAGE, Some(".t.Test.MEntry")),
            field("n", 6, O, Type::TYPE_MESSAGE, Some(".t.Test")),
            field("b", 7, O, Type::TYPE_BYTES, None),
        ],
        nested_type: vec![entry],
        ..Default::default()
    };
    let file = FileDescriptorProto {
        name: Some("t.proto".into()),
        package: Some("t".into()),
        syntax: Some("proto3".into()),
        message_type: vec![test],
        ..Default::default()
    };
    Arc::new(
        DescriptorPool::new(FileDescriptorSet {
            file: vec![file],
            ..Default::default()
        })
        .expect("a valid descriptor"),
    )
}

fn message(pool: &Arc<DescriptorPool>) -> DynamicMessage {
    let mut m = DynamicMessage::new_by_name(Arc::clone(pool), "t.Test").expect("declared");
    let md = pool.message_by_name("t.Test").expect("declared");
    let set = |m: &mut DynamicMessage, name: &str, v: V| {
        m.set(md.field_by_name(name).expect("declared"), v)
    };
    set(&mut m, "a", V::I32(5));
    set(&mut m, "s", V::String("héllo".into()));
    set(&mut m, "xs", V::List(vec![V::I32(1), V::I32(2), V::I32(3)]));
    set(&mut m, "d", V::F64(1.5));
    set(
        &mut m,
        "m",
        V::Map(MapValue::from_entries(vec![(
            MapKey::String("k".into()),
            V::I32(1),
        )])),
    );
    set(&mut m, "b", V::Bytes(vec![0x61, 0x62]));
    m
}

/// The outcome as text: `pass`, `fail`, `fail: <message>` or `error`.
fn show(r: Result<Outcome<'_>, super::Error>) -> String {
    match r {
        Ok(Outcome::Pass) => "pass".into(),
        Ok(Outcome::Fail(None)) => "fail".into(),
        Ok(Outcome::Fail(Some(m))) => format!("fail: {}", &*m),
        Err(_) => "error".into(),
    }
}

fn both(source: &str) -> (String, String) {
    let pool = pool();
    let msg = message(&pool);
    let idx = pool.message_index("t.Test").expect("declared");
    let bindings = Bindings {
        pool: &pool,
        this: Ty::Message(idx),
        consts: &[],
    };
    let this = Value::Message(super::value::Msg::Ref(&msg as &dyn ReflectMessage));
    let clock = Clock::default();
    let compiled = match Program::compile(source, &bindings) {
        Ok(Some(p)) => {
            assert!(!p.is_fallback(), "`{source}` should compile to the tree");
            show(p.eval(&this, &clock))
        }
        Ok(None) => "pass".into(),
        Err(_) => "compile error".into(),
    };
    let interpreted = match fallback::Program::compile(source, &bindings) {
        Ok(p) => show(p.eval(&this, &clock)),
        Err(_) => "compile error".into(),
    };
    (compiled, interpreted)
}

#[test]
fn compiled_agrees_with_the_interpreter() {
    let expressions = [
        "this.a > 3",
        "this.a + 1 == 6",
        "this.a * 2 - 1 == 9",
        "this.a / 0 == 1",
        "this.a % 2 == 1",
        "-this.a < 0",
        "this.a < 10u",
        "this.a == 5.0",
        "this.d > 1",
        "this.d == 1.5",
        "int(this.d) == 1",
        "uint(this.a) == 5u",
        "double(this.a) == 5.0",
        "string(this.a) == '5'",
        "this.s.size() == 5",
        "size(this.s) == 5",
        "this.s.startsWith('hé')",
        "this.s.endsWith('lo')",
        "this.s.contains('ll')",
        "this.s.matches('^h.llo$')",
        "this.s + '!' == 'héllo!'",
        "this.b == b'ab'",
        "this.b.size() == 2",
        "string(this.b) == 'ab'",
        "this.xs.size() == 3",
        "this.xs[1] == 2",
        "this.xs[5] == 0",
        "2 in this.xs",
        "this.xs.all(x, x > 0)",
        "this.xs.all(x, x > 1)",
        "this.xs.exists(x, x == 2)",
        "this.xs.exists_one(x, x > 1)",
        "this.xs.exists_one(x, x > 2)",
        "this.xs.map(x, x * 2) == [2, 4, 6]",
        "this.xs.filter(x, x > 1) == [2, 3]",
        "this.xs.map(x, x > 1, x * 10) == [20, 30]",
        "this.xs + [4] == [1, 2, 3, 4]",
        "this.m['k'] == 1",
        "this.m['z'] == 1",
        "'k' in this.m",
        "has(this.m.k)",
        "this.m.all(k, k == 'k')",
        "has(this.n)",
        "has(this.a)",
        "this.n.a == 0",
        "this.n.n.s == ''",
        "dyn(this).nope == 1",
        "this.a > 3 ? 'big' : ''",
        "this.a > 9 ? 'big' : ''",
        "this.a > 3 && this.s == 'x'",
        "this.a > 3 || this.xs[9] == 1",
        "this.xs[9] == 1 || this.a > 3",
        "this.xs[9] == 1 && this.a > 9",
        "!(this.a > 3)",
        "duration('1s') < duration('2s')",
        "duration('1m') == duration('60s')",
        "timestamp('2020-01-01T00:00:00Z') < timestamp('2021-01-01T00:00:00Z')",
        "timestamp('2020-01-01T00:00:00Z') + duration('24h') == timestamp('2020-01-02T00:00:00Z')",
        "timestamp('2020-03-04T05:06:07Z').getFullYear() == 2020",
        "timestamp('2020-03-04T05:06:07Z').getMonth() == 2",
        "timestamp('2020-03-04T05:06:07Z').getDayOfMonth() == 3",
        "timestamp('2020-03-04T05:06:07Z').getHours() == 5",
        "'abc'.charAt(1) == 'b'",
        "'abcabc'.indexOf('c') == 2",
        "'abcabc'.lastIndexOf('c') == 5",
        "'abc'.substring(1) == 'bc'",
        "'abc'.replace('b', 'x') == 'axc'",
        "'a,b'.split(',').size() == 2",
        "['a', 'b'].join('-') == 'a-b'",
        "' x '.trim() == 'x'",
        "'AbC'.lowerAscii() == 'abc'",
        "'AbC'.upperAscii() == 'ABC'",
        "'%s and %d'.format(['x', 5]) == 'x and 5'",
        "'a@example.com'.isEmail()",
        "'not an email'.isEmail()",
        "'example.com'.isHostname()",
        "'127.0.0.1'.isIp(4)",
        "'::1'.isIp(4)",
        "'10.0.0.0/8'.isIpPrefix(true)",
        "'https://example.com'.isUri()",
        "'example.com:443'.isHostAndPort(true)",
        "[1, 2, 3].unique()",
        "[1, 2, 1].unique()",
        "(0.0 / 0.0).isNan()",
        "(1.0 / 0.0).isInf()",
        "(1.0 / 0.0).isInf(-1)",
        "getField(this, 'a') == 5",
        "type(this.a) == int",
        "{'a': 1}['a'] == 1",
        "9223372036854775807 + 1 > 0",
    ];
    let mut differ = Vec::new();
    for e in expressions {
        let (compiled, interpreted) = both(e);
        if compiled != interpreted {
            differ.push(format!(
                "{e}: compiled {compiled}, interpreted {interpreted}"
            ));
        }
    }
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}

#[test]
fn the_interpreter_runs_what_the_tree_does_not() {
    let pool = pool();
    let msg = message(&pool);
    let idx = pool.message_index("t.Test").expect("declared");
    let bindings = Bindings {
        pool: &pool,
        this: Ty::Message(idx),
        consts: &[],
    };
    let this = Value::Message(super::value::Msg::Ref(&msg as &dyn ReflectMessage));
    let clock = Clock::default();
    for (source, want) in [
        ("this.?a.orValue(0) == 5", "pass"),
        ("this.?nope.hasValue()", "fail"),
        ("optional.of(this.a).value() == 5", "pass"),
    ] {
        let program = Program::compile(source, &bindings)
            .unwrap_or_else(|e| panic!("{source}: {e}"))
            .expect("not constant");
        assert!(
            program.is_fallback(),
            "{source} should run on the interpreter"
        );
        assert_eq!(show(program.eval(&this, &clock)), want, "{source}");
    }
}

#[test]
fn wrong_expressions_do_not_compile() {
    let pool = pool();
    let idx = pool.message_index("t.Test").expect("declared");
    let bindings = Bindings {
        pool: &pool,
        this: Ty::Message(idx),
        consts: &[],
    };
    for source in [
        // protovalidate wants a bool or a string.
        "this.a",
        "this.nope > 0",
        "this.a.startsWith('x')",
        "this.s > 1",
        "this.xs.all(x, x.startsWith('a'))",
        "nope == 1",
        "this.s.matches('(')",
        "this.a ==",
    ] {
        assert!(
            Program::compile(source, &bindings).is_err(),
            "{source} should not compile"
        );
    }
}
