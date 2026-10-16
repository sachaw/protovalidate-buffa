// Shared by the example crates' build scripts through `include!`.

use std::{env, fs, path::PathBuf, process::Command};

use buffa::Message as _;
use buffa_codegen::generated::{compiler::CodeGeneratorRequest, descriptor::FileDescriptorSet};

/// Compile `sources` with their imports into a plugin request, as `protoc`
/// or `buf generate` would hand it to a plugin.
fn request(sources: &[&str]) -> anyhow::Result<CodeGeneratorRequest> {
    let schemas = "../../../crates/protovalidate-buffa-protos/proto";
    println!("cargo:rerun-if-changed=../proto");
    println!("cargo:rerun-if-changed=../build_support.rs");
    println!("cargo:rerun-if-env-changed=PROTOC");
    let descriptors = out_dir()?.join("descriptors.binpb");
    let status = Command::new(env::var_os("PROTOC").unwrap_or_else(|| "protoc".into()))
        .arg("-I../proto")
        .arg(format!("-I{schemas}"))
        .arg("--include_imports")
        .arg(format!("--descriptor_set_out={}", descriptors.display()))
        .args(sources)
        .status()?;
    anyhow::ensure!(status.success(), "protoc failed to compile {sources:?}");
    let fds = FileDescriptorSet::decode_from_slice(&fs::read(descriptors)?)?;
    Ok(CodeGeneratorRequest {
        file_to_generate: sources.iter().map(|s| (*s).to_string()).collect(),
        proto_file: fds.file,
        ..Default::default()
    })
}

fn out_dir() -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(env::var("OUT_DIR")?))
}

/// Generate Buffa types for `sources`, mapping dependency packages to their
/// types crates.
#[allow(dead_code, reason = "used by the types crates only")]
fn types(sources: &[&str], extern_paths: &[(&str, &str)]) -> anyhow::Result<()> {
    let request = request(sources)?;
    let mut config = buffa_codegen::CodeGenConfig::default();
    config.file_per_package = true;
    config.extern_paths = extern_paths
        .iter()
        .map(|(proto, rust)| ((*proto).to_string(), (*rust).to_string()))
        .collect();
    let out = out_dir()?;
    for file in buffa_codegen::generate(&request.proto_file, &request.file_to_generate, &config)? {
        fs::write(out.join(&file.name), file.content)?;
    }
    Ok(())
}

/// Run the validator plugin on `sources` with plugin `parameter`.
#[allow(dead_code, reason = "used by the validator crates only")]
fn validators(sources: &[&str], parameter: &str) -> anyhow::Result<()> {
    use protoc_gen_protovalidate_buffa::emit;

    let mut request = request(sources)?;
    request.parameter = Some(parameter.to_string());
    let out = out_dir()?;
    for file in emit::render_request(&request, &emit::Options::parse(parameter)?)? {
        fs::write(
            out.join(file.name.as_deref().expect("generated filename")),
            file.content.as_deref().expect("generated content"),
        )?;
    }
    Ok(())
}
