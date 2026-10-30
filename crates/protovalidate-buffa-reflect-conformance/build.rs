//! Compiles the conformance harness's protos into a descriptor set (the
//! executor reads requests and writes responses as dynamic messages), and a
//! few of the conformance cases into reflective types with the plugin's
//! generated validators, so the two validators can be compared on the same
//! messages.

use std::{
    collections::BTreeMap,
    fmt::Write as _,
    path::{Path, PathBuf},
};

use buffa::Message as _;
use buffa_codegen::generated::{compiler::CodeGeneratorRequest, descriptor::FileDescriptorSet};

/// The cases the benchmark and the agreement tests use.
const CASES: &[&str] = &[
    "buf/validate/conformance/cases/kitchen_sink.proto",
    "buf/validate/conformance/cases/custom_rules/custom_rules.proto",
    "buf/validate/conformance/cases/strings.proto",
    "buf/validate/conformance/cases/repeated.proto",
    "buf/validate/conformance/cases/maps.proto",
    "buf/validate/conformance/cases/other_package/embed.proto",
];

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("set by cargo"));
    let protos = manifest.join("../protovalidate-buffa-conformance/proto");
    println!("cargo:rerun-if-changed={}", protos.display());
    println!("cargo:rerun-if-env-changed=PROTOC");

    let protoc = protoc();
    let include = Path::new(&protoc)
        .parent()
        .and_then(Path::parent)
        .map(|prefix| prefix.join("include"))
        .filter(|p| p.join("google/protobuf/descriptor.proto").exists())
        .expect("protoc's include directory");
    let descriptors = |out: &Path, files: &[&str]| {
        let status = std::process::Command::new(&protoc)
            .arg(format!("--descriptor_set_out={}", out.display()))
            .arg("--include_imports")
            .arg(format!("-I{}", protos.display()))
            .arg(format!("-I{}", include.display()))
            .args(files)
            .status()
            .expect("run protoc");
        assert!(status.success(), "protoc failed");
    };

    descriptors(
        &out_dir.join("harness.fds"),
        &["buf/validate/conformance/harness/harness.proto"],
    );

    let cases = out_dir.join("cases.fds");
    descriptors(&cases, CASES);
    buffa_build::Config::new()
        .descriptor_set(&cases)
        .files(CASES)
        .includes(&[protos.to_string_lossy().into_owned()])
        .generate_reflection(true)
        .include_file("_buffa_include.rs")
        .compile()
        .expect("buffa-build");

    let fds = FileDescriptorSet::decode_from_slice(&std::fs::read(&cases).expect("read cases"))
        .expect("decode cases");
    let request = CodeGeneratorRequest {
        file_to_generate: CASES.iter().map(|f| (*f).to_owned()).collect(),
        proto_file: fds.file,
        ..Default::default()
    };
    let scanned = protoc_gen_protovalidate_buffa::scan::gather(&request).expect("scan");
    let mut by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for file in protoc_gen_protovalidate_buffa::emit::render(&scanned).expect("emit") {
        let name = file.name.expect("generated name");
        if name == "mod.rs" || name.ends_with(".mod.rs") {
            continue;
        }
        let stem = name.trim_end_matches(".rs");
        let package = stem.rsplit_once('.').map_or(stem, |(p, _)| p).to_owned();
        let out = format!("pv_{name}");
        std::fs::write(out_dir.join(&out), file.content.expect("generated content"))
            .expect("write validators");
        by_package.entry(package).or_default().push(out);
    }
    merge_include(&out_dir, &by_package);
}

/// Mounts each package's validators inside its module of buffa's tree.
fn merge_include(out_dir: &Path, by_package: &BTreeMap<String, Vec<String>>) {
    let buffa = std::fs::read_to_string(out_dir.join("_buffa_include.rs")).expect("read include");
    let mut out = String::new();
    let mut stack: Vec<String> = Vec::new();
    for line in buffa.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub mod ") {
            let name = rest.trim_end_matches('{').trim();
            stack.push(name.to_owned());
        } else if trimmed == "}" {
            for f in by_package.get(&stack.join(".")).into_iter().flatten() {
                writeln!(out, "include!(concat!(env!(\"OUT_DIR\"), \"/{f}\"));")
                    .expect("writing to a string");
            }
            stack.pop();
        }
        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(out_dir.join("_include.rs"), out).expect("write include");
}

fn protoc() -> String {
    if let Ok(p) = std::env::var("PROTOC") {
        return p;
    }
    let output = std::process::Command::new("which")
        .arg("protoc")
        .output()
        .expect("protoc on PATH, or PROTOC set");
    let path = String::from_utf8(output.stdout).expect("UTF-8 path");
    let path = path.trim();
    std::fs::canonicalize(path)
        .map_or_else(|_| path.to_owned(), |p| p.to_string_lossy().into_owned())
}
