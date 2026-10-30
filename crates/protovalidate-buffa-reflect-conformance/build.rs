//! Compiles the conformance harness's own protos into a descriptor set: the
//! executor reads the harness's requests and writes its responses as dynamic
//! messages, as it reads the cases.

use std::path::{Path, PathBuf};

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
    let status = std::process::Command::new(&protoc)
        .arg(format!(
            "--descriptor_set_out={}",
            out_dir.join("harness.fds").display()
        ))
        .arg("--include_imports")
        .arg(format!("-I{}", protos.display()))
        .arg(format!("-I{}", include.display()))
        .arg("buf/validate/conformance/harness/harness.proto")
        .status()
        .expect("run protoc");
    assert!(status.success(), "protoc failed");
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
