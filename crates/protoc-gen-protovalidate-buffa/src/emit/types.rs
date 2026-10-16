//! Resolve protobuf type names to the Rust paths buffa generated for them.
//!
//! Every path goes through [`buffa_codegen::context::CodeGenContext`], the
//! resolver buffa itself and `connectrpc-codegen` use, so validators name
//! types exactly where buffa put them: nested-message modules, keyword
//! escapes, module-name deconfliction, well-known types, and `extern_path`
//! mappings into other crates.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use buffa_codegen::{
    CodeGenConfig,
    context::{CodeGenContext, SENTINEL_MOD, SplitPath},
    generated::descriptor::{DescriptorProto, EnumDescriptorProto, FileDescriptorProto},
    idents::rust_path_to_tokens,
};
use proc_macro2::TokenStream;
use quote::quote;

use crate::scan::{FieldKind, MessageValidators};

/// Type-path resolution for one generation run.
pub struct Types<'a> {
    ctx: CodeGenContext<'a>,
    /// Every resolved path must be absolute (`::` or `crate::`). Set when
    /// validators live outside the module that holds the types, where a
    /// relative path cannot resolve.
    require_absolute: bool,
}

impl<'a> Types<'a> {
    pub fn new(
        files: &'a [FileDescriptorProto],
        files_to_generate: &[String],
        config: &'a CodeGenConfig,
        require_absolute: bool,
    ) -> Self {
        Self {
            ctx: CodeGenContext::for_generate(files, files_to_generate, config),
            require_absolute,
        }
    }

    /// Split the path to `full_name` (no leading dot) at its package root,
    /// as seen from validators emitted at the root of `current_package`.
    fn split(&self, full_name: &str, current_package: &str) -> Result<SplitPath> {
        let split = self
            .ctx
            .rust_type_relative_split(&format!(".{full_name}"), current_package, 0)
            .ok_or_else(|| {
                anyhow!("type {full_name} not found in descriptor set (missing proto import?)")
            })?;
        if self.require_absolute && !split.is_extern {
            bail!(
                "type {full_name} is not covered by any extern_path mapping. Add \
                 extern_path=.{package}=<rust path> (or extern_path=.=<rust path>) to the \
                 plugin options.",
                package = full_name
                    .rsplit_once('.')
                    .map_or("", |(package, _)| package),
            );
        }
        Ok(split)
    }

    /// The owned message or enum type.
    pub fn owned(&self, full_name: &str, current_package: &str) -> Result<TokenStream> {
        let split = self.split(full_name, current_package)?;
        Ok(join(&split.to_package, &split.within_package))
    }

    /// The borrowed view type, with an elided lifetime.
    pub fn view(&self, full_name: &str, current_package: &str) -> Result<TokenStream> {
        let split = self.split(full_name, current_package)?;
        let path = join(
            &split.to_package,
            &format!("{SENTINEL_MOD}::view::{}View", split.within_package),
        );
        Ok(quote! { #path<'_> })
    }

    /// The path to the package that declares `full_name`, as a string; empty
    /// for the current package in relative mode. Oneof enums and views hang
    /// off this root under buffa's `__buffa` module.
    pub fn package_root(&self, full_name: &str, current_package: &str) -> Result<String> {
        Ok(self.split(full_name, current_package)?.to_package)
    }
}

/// `prefix::rest`, or `rest` alone when `prefix` is empty.
fn join(prefix: &str, rest: &str) -> TokenStream {
    if prefix.is_empty() {
        rust_path_to_tokens(rest)
    } else {
        rust_path_to_tokens(&format!("{prefix}::{rest}"))
    }
}

/// Build stand-in descriptors for callers that render validators without a
/// `CodeGeneratorRequest`.
///
/// Each message keeps its declared package; referenced types outside
/// `messages` are placed by the protobuf naming convention (lowercase package
/// segments, then PascalCase type names). The result feeds the same resolver
/// as real descriptors.
pub fn synthesize_descriptors(
    messages: &[MessageValidators],
) -> (Vec<FileDescriptorProto>, Vec<String>) {
    let packages: BTreeSet<&str> = messages.iter().map(|m| m.package.as_str()).collect();
    let mut types: BTreeMap<String, (String, Kind)> = BTreeMap::new();
    for message in messages {
        types.insert(
            message.proto_name.clone(),
            (message.package.clone(), Kind::Message),
        );
    }
    let mut referenced = Vec::new();
    for message in messages {
        for field in &message.field_rules {
            collect_references(&field.field_type, &mut referenced);
        }
    }
    for (full_name, kind) in referenced {
        if types.contains_key(&full_name) {
            continue;
        }
        let package = packages
            .iter()
            .filter(|package| {
                !package.is_empty()
                    && full_name
                        .strip_prefix(**package)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            .max_by_key(|package| package.len())
            .map_or_else(|| conventional_package(&full_name), |p| (*p).to_string());
        types.insert(full_name, (package, kind));
    }
    let mut by_package: BTreeMap<String, DescriptorProto> = BTreeMap::new();
    for (full_name, (package, kind)) in &types {
        let local = if package.is_empty() {
            full_name.as_str()
        } else {
            full_name
                .strip_prefix(package.as_str())
                .and_then(|rest| rest.strip_prefix('.'))
                .unwrap_or(full_name)
        };
        let root = by_package.entry(package.clone()).or_default();
        insert(root, &local.split('.').collect::<Vec<_>>(), *kind);
    }

    let mut files = Vec::new();
    let mut to_generate = Vec::new();
    for (package, root) in by_package {
        let name = format!("__protovalidate_buffa/{package}.proto");
        if package != "google.protobuf" {
            to_generate.push(name.clone());
        }
        files.push(FileDescriptorProto {
            name: Some(name),
            package: (!package.is_empty()).then_some(package),
            syntax: Some("proto3".into()),
            message_type: root.nested_type,
            enum_type: root.enum_type,
            ..Default::default()
        });
    }
    (files, to_generate)
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Message,
    Enum,
}

fn collect_references(kind: &FieldKind, out: &mut Vec<(String, Kind)>) {
    match kind {
        FieldKind::Message { full_name } => out.push((full_name.clone(), Kind::Message)),
        FieldKind::Enum { full_name } => out.push((full_name.clone(), Kind::Enum)),
        FieldKind::Repeated(inner) | FieldKind::Optional(inner) | FieldKind::Wrapper(inner) => {
            collect_references(inner, out);
        }
        FieldKind::Map { key, value } => {
            collect_references(key, out);
            collect_references(value, out);
        }
        _ => {}
    }
}

/// The package of `full_name` by convention: every segment before the first
/// one that starts with an uppercase letter.
fn conventional_package(full_name: &str) -> String {
    let segments: Vec<&str> = full_name.split('.').collect();
    let split = segments
        .iter()
        .position(|s| s.chars().next().is_some_and(char::is_uppercase))
        .unwrap_or_else(|| segments.len().saturating_sub(1));
    segments[..split].join(".")
}

/// Insert a (possibly nested) type into a container message.
fn insert(container: &mut DescriptorProto, path: &[&str], kind: Kind) {
    let Some((first, rest)) = path.split_first() else {
        return;
    };
    if rest.is_empty() {
        match kind {
            Kind::Message => {
                if !container
                    .nested_type
                    .iter()
                    .any(|m| m.name.as_deref() == Some(first))
                {
                    container.nested_type.push(DescriptorProto {
                        name: Some((*first).to_string()),
                        ..Default::default()
                    });
                }
            }
            Kind::Enum => container.enum_type.push(EnumDescriptorProto {
                name: Some((*first).to_string()),
                ..Default::default()
            }),
        }
        return;
    }
    let index = container
        .nested_type
        .iter()
        .position(|m| m.name.as_deref() == Some(first))
        .unwrap_or_else(|| {
            container.nested_type.push(DescriptorProto {
                name: Some((*first).to_string()),
                ..Default::default()
            });
            container.nested_type.len() - 1
        });
    insert(&mut container.nested_type[index], rest, kind);
}
