//! Orchestrate the emit phase: group scanned validators by source `.proto`
//! file or package, with optional module packaging.

use std::collections::BTreeMap;

use anyhow::Result;
use buffa_codegen::generated::{
    compiler::{CodeGeneratorRequest, code_generator_response::File},
    descriptor::FileDescriptorProto,
};
use proc_macro2::TokenStream;
use quote::quote;

use crate::scan::MessageValidators;

/// Plugin options parsed from `opt:` in `buf.gen.yaml`.
///
/// # Examples
///
/// ```
/// use protoc_gen_protovalidate_buffa::emit::{self, Options};
///
/// let options = Options {
///     packaging: false,
///     file_per_package: true,
///     ..Options::default()
/// };
/// let files = emit::render_with_options(&[], &options)?;
/// assert!(files.is_empty());
/// # Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct Options {
    /// Rust module path under which the protobuf message types live —
    /// the `mod.rs` packaging file emits `pub(crate) use <proto_module>::<pkg>::*;`
    /// inside each leaf package so local and cross-package type names resolve.
    /// Ignored when [`Self::packaging`] is `false`.
    pub proto_module: String,
    /// Emit the `mod.rs` and `<package>.mod.rs` module files (default: `true`).
    /// Set to `false` to emit only validators with a `.validate.rs` suffix,
    /// for inclusion in the same module as the message types.
    pub packaging: bool,
    /// Merge validators by declared protobuf package (default: `false`).
    /// When `false`, emit one validator file per source proto. When `true`,
    /// use the package name as the filename stem, or `__buffa` for the unnamed
    /// package, matching Buffa. Independent of [`Self::packaging`].
    pub file_per_package: bool,
}

impl Options {
    /// The `extern_path` mappings type resolution runs with.
    fn effective_extern_paths(&self) -> Vec<(String, String)> {
        if self.packaging {
            vec![(".".to_string(), self.proto_module.clone())]
        } else {
            Vec::new()
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            proto_module: "crate::proto".to_string(),
            packaging: true,
            file_per_package: false,
        }
    }
}

pub mod cel;
pub mod cel_compile;
pub mod field;
pub mod oneof;
pub mod repeated;
pub(crate) mod types;

/// Generated message representation targeted by a validation body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    Owned,
    View,
}

impl Shape {
    /// Expression exposing protobuf's canonical map semantics for this shape.
    pub(crate) fn map_access(
        self,
        accessor: &proc_macro2::Ident,
        field_number: i32,
    ) -> TokenStream {
        match self {
            Self::Owned => quote! { (&self.#accessor) },
            Self::View => {
                let binding = canonical_map_ident(field_number);
                quote! { (&#binding) }
            }
        }
    }
}

/// What the field emitters need to know about the file being generated.
pub(crate) struct Scope<'a> {
    pub(crate) schemas: &'a cel::SchemaIndex,
    types: &'a types::Types<'a>,
    /// Protobuf package of the file; relative type paths start here.
    package: &'a str,
}

impl Scope<'_> {
    /// The Rust type a message-typed value has in `shape`.
    pub(crate) fn message_type(&self, full_name: &str, shape: Shape) -> Result<TokenStream> {
        match shape {
            Shape::Owned => self.types.owned(full_name, self.package),
            Shape::View => self.types.view(full_name, self.package),
        }
    }

    /// The Rust enum type for `full_name`.
    pub(crate) fn enum_type(&self, full_name: &str) -> Result<TokenStream> {
        self.types.owned(full_name, self.package)
    }

    /// The module holding the oneof enums of message `full_name`
    /// (`<package root>::__buffa::[view::]oneof::<message path>`).
    pub(crate) fn oneof_module(
        &self,
        full_name: &str,
        package: &str,
        shape: Shape,
    ) -> Result<TokenStream> {
        let root = self.types.package_root(full_name, self.package)?;
        Ok(oneof_module(&root, package, full_name, shape))
    }

    /// The expression validating nested message `value` of type `full_name`,
    /// or `None` when the type has no generated validator (well-known types).
    pub(crate) fn nested_validate(
        &self,
        full_name: &str,
        shape: Shape,
        value: &TokenStream,
    ) -> Result<Option<TokenStream>> {
        if full_name.starts_with("google.protobuf.") {
            return Ok(None);
        }
        let ty = self.message_type(full_name, shape)?;
        Ok(Some(quote! {
            <#ty as ::protovalidate_buffa::Validate>::validate(#value)
        }))
    }
}

/// The oneof-enum module for message `full_name` in `package`, whose package
/// module is reached through `root` (empty for the current module).
pub(crate) fn oneof_module(
    root: &str,
    package: &str,
    full_name: &str,
    shape: Shape,
) -> TokenStream {
    let within = if package.is_empty() {
        full_name
    } else {
        full_name
            .strip_prefix(package)
            .and_then(|rest| rest.strip_prefix('.'))
            .unwrap_or(full_name)
    };
    let module = oneof::module_path(within);
    let kind = match shape {
        Shape::Owned => quote! { __buffa::oneof },
        Shape::View => quote! { __buffa::view::oneof },
    };
    if root.is_empty() {
        quote! { #kind::#module }
    } else {
        let root = buffa_codegen::idents::rust_path_to_tokens(root);
        quote! { #root::#kind::#module }
    }
}

fn canonical_map_ident(field_number: i32) -> proc_macro2::Ident {
    quote::format_ident!("__pv_map_{field_number}")
}

fn needs_canonical_map(field: &crate::scan::FieldValidator) -> bool {
    use crate::scan::{FieldKind, Ignore};

    if matches!(field.ignore, Ignore::Always) {
        return false;
    }
    let FieldKind::Map { value, .. } = &field.field_type else {
        return false;
    };
    field.standard.map.is_some()
        || !field.cel.is_empty()
        || !field.standard.predefined.is_empty()
        || matches!(
            value.as_ref(),
            FieldKind::Message { full_name } if !full_name.starts_with("google.protobuf.")
        )
}

fn canonical_map_bindings(msg: &MessageValidators, shape: Shape) -> Vec<TokenStream> {
    if shape == Shape::Owned {
        return Vec::new();
    }
    msg.field_rules
        .iter()
        .filter(|field| needs_canonical_map(field))
        .map(|field| {
            let accessor = field_ident(&field.rust_name);
            let binding = canonical_map_ident(field.field_number);
            quote! {
                let #binding =
                    ::protovalidate_buffa::__private::CanonicalMap::from_view(&self.#accessor);
            }
        })
        .collect()
}

/// Build the Rust identifier that accesses a proto field (or oneof) on a
/// buffa-generated struct.
///
/// Delegates to the same function buffa uses to name its struct fields
/// (`buffa_codegen::idents::make_field_ident`), so accessors emitted here line
/// up with the generated message types on keyword names (e.g. `type` →
/// `r#type`, `self` → `self_`). Re-deriving idents with
/// `format_ident!`/`Ident::new`/`parse_str` instead would panic or mismatch.
pub(crate) fn field_ident(name: &str) -> proc_macro2::Ident {
    buffa_codegen::idents::make_field_ident(name)
}

/// Render one output `.rs` file per source `.proto` file.
///
/// Output path: `"example/v1/foo.proto"` → `"example.v1.foo.rs"`.
///
/// Without descriptors, type paths follow protobuf naming conventions:
/// packages are the lowercase leading segments and nested types live in
/// snake_case modules. Use [`render_request`] to resolve them against the
/// request's descriptors instead.
///
/// # Errors
///
/// Returns an error if a type path cannot be resolved, if a field emitter
/// fails, or if `prettyplease` cannot format the generated `TokenStream`.
pub fn render(messages: &[MessageValidators]) -> Result<Vec<File>> {
    render_with_options(messages, &Options::default())
}

/// Same as [`render`] but threads parsed plugin options through.
///
/// By default, also emits a `mod.rs` packaging file that mirrors the proto-package
/// hierarchy as nested `pub mod` declarations, and per-package
/// `<pkg>.mod.rs` files that flat-`include!()` each per-source output.
/// Removes the need for an external "generate mod tree" script in
/// projects that consume this plugin.
///
/// [`Options::file_per_package`] independently groups validators by declared
/// protobuf package instead of source file. With [`Options::packaging`] set
/// to `false`, emits no module files, adds `.validate` before the `.rs` suffix,
/// and ignores `proto_module`. Set `packaging=false,file_per_package=true` for one
/// `<package>.validate.rs` per package beside the corresponding Buffa types.
///
/// # Errors
///
/// See [`render`].
pub fn render_with_options(messages: &[MessageValidators], opts: &Options) -> Result<Vec<File>> {
    let (files, to_generate) = types::synthesize_descriptors(messages);
    render_set(&files, &to_generate, messages, opts)
}

/// Scan `request` and render its validators, resolving every type path
/// against the request's descriptors exactly as buffa does.
///
/// This is what the plugin binary runs. Prefer it over [`render_with_options`]
/// for in-process generation: [`render_with_options`] has no descriptors and
/// derives paths from protobuf names instead.
///
/// # Errors
///
/// Returns an error if scanning fails (see [`crate::scan::gather`]), if a
/// referenced type is missing from the request, or for the reasons listed on
/// [`render`].
pub fn render_request(request: &CodeGeneratorRequest, opts: &Options) -> Result<Vec<File>> {
    let messages = crate::scan::gather(request)?;
    render_set(
        &request.proto_file,
        &request.file_to_generate,
        &messages,
        opts,
    )
}

/// Render validators for `messages`, resolving type paths against `files`.
fn render_set(
    descriptors: &[FileDescriptorProto],
    to_generate: &[String],
    messages: &[MessageValidators],
    opts: &Options,
) -> Result<Vec<File>> {
    let mut config = buffa_codegen::CodeGenConfig::default();
    config.extern_paths = opts.effective_extern_paths();
    let types = types::Types::new(descriptors, to_generate, &config, false);

    let mut groups: BTreeMap<&str, Vec<&MessageValidators>> = BTreeMap::new();
    for m in messages {
        let key = if opts.file_per_package {
            &m.package
        } else {
            &m.source_file
        };
        groups.entry(key).or_default().push(m);
    }

    let mut files = Vec::new();
    // Map proto package (e.g. "example.v1alpha1") → list of emitted
    // filenames, so the packaging file can `include!()` each per-package
    // file under the right `pub mod` nesting.
    let mut by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, msgs) in groups {
        let package = msgs.first().map_or("", |m| m.package.as_str());
        let schemas = cel::build_schema_index(messages, &types, package)?;
        let scope = Scope {
            schemas: &schemas,
            types: &types,
            package,
        };
        let body = render_file(&msgs, &scope)?;
        let stem = if opts.file_per_package {
            let filename = buffa_codegen::package_to_filename(key);
            filename
                .strip_suffix(".rs")
                .unwrap_or(&filename)
                .to_string()
        } else {
            key.trim_end_matches(".proto").replace('/', ".")
        };
        let path = if opts.packaging {
            format!("{stem}.rs")
        } else {
            format!("{stem}.validate.rs")
        };
        let body_str = body.to_string();
        let parsed = syn::parse2(body.clone()).map_err(|e| {
            anyhow::anyhow!("syn parse failed for {key}: {e}\n--- BEGIN TOKENS ---\n{body_str}\n--- END TOKENS ---")
        })?;
        // The package is everything before the trailing file stem in the
        // dotted form ("example.v1alpha1.style" → package "example.v1alpha1").
        let package = if opts.file_per_package {
            key.to_string()
        } else {
            match stem.rsplit_once('.') {
                Some((p, _)) => p.to_string(),
                None => stem.clone(),
            }
        };
        by_package.entry(package).or_default().push(path.clone());
        files.push(File {
            name: Some(path),
            content: Some(prettyplease::unparse(&parsed)),
            insertion_point: None,
            generated_code_info: None.into(),
            ..Default::default()
        });
    }

    if !opts.packaging {
        return Ok(files);
    }

    // For each leaf package, emit a `<pkg>.mod.rs` that flat-includes
    // every per-source file in that package. Mirrors the convention used
    // by `buffa-codegen` and the Connect plugin so this output drops into
    // the same `pub mod <pkg> { include!("<pkg>.mod.rs"); }` shape.
    for (package, file_names) in &by_package {
        let includes: Vec<TokenStream> = file_names
            .iter()
            .map(|f| {
                let lit = proc_macro2::Literal::string(f);
                quote! { include!(#lit); }
            })
            .collect();
        let body = quote! {
            #( #includes )*
        };
        let label = buffa_codegen::package_to_mod_filename(package);
        let formatted = format_token_stream(
            &body,
            "// @generated by protoc-gen-protovalidate-buffa. DO NOT EDIT.\n",
            &label,
        )?;
        files.push(File {
            name: Some(label),
            content: Some(formatted),
            insertion_point: None,
            generated_code_info: None.into(),
            ..Default::default()
        });
    }

    let mod_rs = render_mod_rs(&by_package, opts)?;
    files.push(File {
        name: Some("mod.rs".to_string()),
        content: Some(mod_rs),
        insertion_point: None,
        generated_code_info: None.into(),
        ..Default::default()
    });
    Ok(files)
}

/// Parse `tokens` as a `syn::File` and run `prettyplease` over it,
/// prepending the given header comment. Used for both per-package
/// `.mod.rs` files and the top-level packaging `mod.rs` so they share
/// the same formatting as the per-source outputs.
fn format_token_stream(tokens: &TokenStream, header: &str, label: &str) -> Result<String> {
    let body_str = tokens.to_string();
    let parsed: syn::File = syn::parse2(tokens.clone()).map_err(|e| {
        anyhow::anyhow!(
            "syn parse failed for {label}: {e}\n--- BEGIN TOKENS ---\n{body_str}\n--- END TOKENS ---"
        )
    })?;
    Ok(format!("{}{}", header, prettyplease::unparse(&parsed)))
}

/// Build a trie of proto-package segments, with a flag at each leaf
/// saying "this package has its own `<pkg>.mod.rs` to include".
#[derive(Default)]
struct PackageNode {
    children: std::collections::BTreeMap<String, Self>,
    package: Option<String>,
}

/// Emit the top-level packaging `mod.rs` — nested `pub mod <segment>`
/// blocks mirroring each proto package, with each leaf `include!()`-ing
/// the per-package `<pkg>.mod.rs` (which in turn `include!()`s each
/// per-source file). Inside the leaf module the proto-message crate's
/// matching package is imported with crate visibility so the generated
/// `impl Validate for <Type>` blocks resolve `<Type>` by its short name and
/// sibling packages can reference its enums through this module tree.
///
/// Shape matches the `buffa-codegen` / Connect plugin convention:
///
/// ```text
/// mod.rs
///   pub mod example {
///       pub mod v1alpha1 {
///           pub(crate) use crate::proto::example::v1alpha1::*;
///           include!("example.v1alpha1.mod.rs");
///       }
///   }
/// ```
fn render_mod_rs(
    by_package: &std::collections::BTreeMap<String, Vec<String>>,
    opts: &Options,
) -> Result<String> {
    let mut root = PackageNode::default();
    for package in by_package.keys() {
        let mut cur = &mut root;
        for seg in package.split('.').filter(|seg| !seg.is_empty()) {
            cur = cur.children.entry(seg.to_string()).or_default();
        }
        cur.package = Some(package.clone());
    }

    let proto_module: syn::Path = syn::parse_str(&opts.proto_module)
        .map_err(|e| anyhow::anyhow!("invalid proto_module path {:?}: {e}", opts.proto_module))?;
    let body_inner = render_package_node(&root, &[], &proto_module);
    let body = quote! {
        #![allow(
            non_camel_case_types,
            dead_code,
            unused_imports,
            clippy::derivable_impls,
            clippy::match_single_binding,
            clippy::uninlined_format_args,
            clippy::doc_lazy_continuation,
            clippy::module_inception
        )]
        #body_inner
    };
    format_token_stream(
        &body,
        "// @generated by protoc-gen-protovalidate-buffa. DO NOT EDIT.\n\
         //\n\
         // Packaging mod tree for the per-package validator files emitted alongside.\n\
         // Each leaf module imports the matching proto-message package with crate\n\
         // visibility so local impl targets and cross-package enum references resolve.\n\n",
        "mod.rs",
    )
}

fn render_package_node(
    node: &PackageNode,
    path_so_far: &[&str],
    proto_module: &syn::Path,
) -> TokenStream {
    let leaf = node.package.as_ref().map_or_else(TokenStream::new, |pkg| {
        let segs: Vec<syn::Ident> = path_so_far
            .iter()
            .map(|s| quote::format_ident!("{}", s))
            .collect();
        let pkg_mod = buffa_codegen::package_to_mod_filename(pkg);
        let pkg_lit = proc_macro2::Literal::string(&pkg_mod);
        let import = if segs.is_empty() {
            quote! { pub(crate) use #proto_module ::*; }
        } else {
            quote! { pub(crate) use #proto_module :: #( #segs )::* ::*; }
        };
        quote! {
            #import
            include!(#pkg_lit);
        }
    });
    let children: Vec<TokenStream> = node
        .children
        .iter()
        .map(|(seg, child)| {
            let ident = quote::format_ident!("{}", seg);
            let mut next = path_so_far.to_vec();
            next.push(seg);
            let inner = render_package_node(child, &next, proto_module);
            quote! {
                pub mod #ident {
                    use super::*;
                    #inner
                }
            }
        })
        .collect();
    quote! {
        #leaf
        #( #children )*
    }
}

fn render_file(msgs: &[&MessageValidators], scope: &Scope<'_>) -> Result<TokenStream> {
    let impls: Vec<TokenStream> = msgs
        .iter()
        .map(|m| render_message(m, scope))
        .collect::<Result<_>>()?;
    Ok(quote! {
        #( #impls )*
    })
}

/// Outer attribute set applied to every emitted `impl` / `static`. The code
/// is machine-generated and gets included via `include!()`, which means
/// inner attributes aren't allowed — instead every top-level item carries
/// an outer allow. Suppresses: unused `mut` on `violations` vectors for
/// messages whose rules produce violations only conditionally, unused
/// `value`/`key` map iteration locals when only one half is referenced,
/// parenthesised literal groups emitted by `prettyplease`, and a handful
/// of codegen-side diagnostics that have no user-facing reader.
pub(crate) fn gen_allows() -> TokenStream {
    quote! {
        #[allow(
            clippy::all,
            unused_mut,
            unused_variables,
            unused_parens,
            dead_code,
            unreachable_patterns,
            reason = "protovalidate-buffa generated validators — codegen emits uniform scaffolding regardless of which rules apply"
        )]
    }
}

fn render_message(msg: &MessageValidators, scope: &Scope<'_>) -> Result<TokenStream> {
    use std::collections::HashSet;
    let rust_path = scope.message_type(&msg.proto_name, Shape::Owned)?;
    let view_path = scope.message_type(&msg.proto_name, Shape::View)?;

    // Fields listed in a `(buf.validate.message).oneof` get implicit
    // IGNORE_IF_ZERO_VALUE semantics: their rule checks only fire when the
    // field is set (non-default). Wrap those blocks in a zero-value guard.
    let implicit_ignore: HashSet<&str> = msg
        .message_oneofs
        .iter()
        .flat_map(|o| o.fields.iter().map(String::as_str))
        .collect();
    let render_field_blocks = |shape| {
        msg.field_rules
            .iter()
            .map(|f| {
                let inner = field::emit(f, scope, shape)?;
                if !inner.is_empty()
                    && implicit_ignore.contains(f.field_name.as_str())
                    && !matches!(f.ignore, crate::scan::Ignore::Always)
                {
                    let accessor = field_ident(&f.rust_name);
                    let guard = match &f.field_type {
                        crate::scan::FieldKind::Message { .. }
                        | crate::scan::FieldKind::Wrapper(_) => {
                            Some(quote! { self.#accessor.is_set() })
                        }
                        crate::scan::FieldKind::Optional(_) => {
                            Some(quote! { self.#accessor.is_some() })
                        }
                        _ => field::nonzero_guard(&f.field_type, &accessor),
                    };
                    if let Some(g) = guard {
                        Ok(quote! { if #g { #inner } })
                    } else {
                        Ok(inner)
                    }
                } else {
                    Ok(inner)
                }
            })
            .collect::<Result<Vec<TokenStream>>>()
    };
    let owned_field_blocks = render_field_blocks(Shape::Owned)?;
    let view_field_blocks = render_field_blocks(Shape::View)?;
    let oneof_blocks: Vec<TokenStream> = msg
        .oneof_rules
        .iter()
        .map(|v| oneof::emit(v, msg, scope))
        .collect::<Result<_>>()?;
    let view_oneof_blocks: Vec<TokenStream> = msg
        .oneof_rules
        .iter()
        .map(|v| oneof::emit_view(v, msg, scope))
        .collect::<Result<_>>()?;

    // `(buf.validate.message).oneof` — fields where at most one may be set.
    let owned_message_oneof_blocks: Vec<TokenStream> = msg
        .message_oneofs
        .iter()
        .map(|spec| emit_message_oneof(msg, spec, scope, Shape::Owned))
        .collect::<Result<_>>()?;
    let view_message_oneof_blocks: Vec<TokenStream> = msg
        .message_oneofs
        .iter()
        .map(|spec| emit_message_oneof(msg, spec, scope, Shape::View))
        .collect::<Result<_>>()?;

    let (cel_statics, owned_cel_calls) = cel::emit_message_level(msg, scope, Shape::Owned)?;
    let (_, view_cel_calls) = cel::emit_message_level(msg, scope, Shape::View)?;
    let owned_map_bindings = canonical_map_bindings(msg, Shape::Owned);
    let view_map_bindings = canonical_map_bindings(msg, Shape::View);

    let allows = gen_allows();
    if let Some(reason) = &msg.compile_error {
        let impls = [&rust_path, &view_path].map(|rust_path| {
            quote! {
                #allows
                impl ::protovalidate_buffa::Validate for #rust_path {
                    fn validate(
                        &self,
                    ) -> ::core::result::Result<(), ::protovalidate_buffa::ValidationError> {
                        Err(::protovalidate_buffa::ValidationError {
                            compile_error: ::core::option::Option::Some(
                                ::std::string::String::from(#reason),
                            ),
                            ..::core::default::Default::default()
                        })
                    }
                }
            }
        });
        return Ok(quote! {
            #( #impls )*
        });
    }
    // Wrap each static + impl in the same outer allow set.
    let statics_with_allows: Vec<TokenStream> = cel_statics
        .into_iter()
        .map(|s| quote! { #allows #s })
        .collect();
    let render_impl = |rust_path: &TokenStream,
                       map_bindings: &[TokenStream],
                       field_blocks: &[TokenStream],
                       oneof_blocks: &[TokenStream],
                       message_oneof_blocks: &[TokenStream],
                       cel_calls: &[TokenStream]| {
        quote! {
            #allows
            impl ::protovalidate_buffa::Validate for #rust_path {
                fn validate(
                    &self,
                ) -> ::core::result::Result<(), ::protovalidate_buffa::ValidationError> {
                    #( #map_bindings )*
                    let mut violations: ::std::vec::Vec<::protovalidate_buffa::Violation> =
                        ::std::vec::Vec::new();
                    #( #field_blocks )*
                    #( #oneof_blocks )*
                    #( #message_oneof_blocks )*
                    #( #cel_calls )*
                    // Lift any `__cel_runtime_error__` marker violation to the
                    // typed `runtime_error` field so callers can pattern-match
                    // instead of sniffing `rule_id` strings.
                    if let Some(index) = violations
                        .iter()
                        .position(|v| v.rule_id == "__cel_runtime_error__")
                    {
                        let v = violations.swap_remove(index);
                        return ::core::result::Result::Err(
                            ::protovalidate_buffa::ValidationError {
                                runtime_error: ::core::option::Option::Some(v.message.into_owned()),
                                ..::core::default::Default::default()
                            },
                        );
                    }
                    if violations.is_empty() {
                        Ok(())
                    } else {
                        Err(::protovalidate_buffa::ValidationError {
                            violations,
                            ..::core::default::Default::default()
                        })
                    }
                }
            }
        }
    };
    let impls = [
        render_impl(
            &rust_path,
            &owned_map_bindings,
            &owned_field_blocks,
            &oneof_blocks,
            &owned_message_oneof_blocks,
            &owned_cel_calls,
        ),
        render_impl(
            &view_path,
            &view_map_bindings,
            &view_field_blocks,
            &view_oneof_blocks,
            &view_message_oneof_blocks,
            &view_cel_calls,
        ),
    ];
    Ok(quote! {
        #( #statics_with_allows )*
        #( #impls )*
    })
}

/// Emit a `(buf.validate.message).oneof` rule. Counts how many listed fields
/// are considered "set"; emits `message.oneof` violation if zero (only when
/// required) or more than one.
fn emit_message_oneof(
    msg: &crate::scan::MessageValidators,
    spec: &crate::scan::MessageOneofSpec,
    scope: &Scope<'_>,
    shape: Shape,
) -> Result<TokenStream> {
    use crate::scan::FieldKind;
    let oneof_root = scope.types.package_root(&msg.proto_name, scope.package)?;
    let checks: Vec<TokenStream> = spec
        .fields
        .iter()
        .filter_map(|name| {
            let fv = msg.field_rules.iter().find(|f| &f.field_name == name)?;
            let ident = field_ident(&fv.rust_name);
            // Explicit-presence fields count when present, even with a default
            // value. Fields without presence count when non-default.
            let expr = if let Some(oneof_name) = &fv.oneof_name {
                let oneof = msg
                    .oneof_rules
                    .iter()
                    .find(|oneof| &oneof.name == oneof_name)?;
                let accessor = field_ident(&oneof.rust_name);
                let module = oneof_module(&oneof_root, &msg.package, &msg.proto_name, shape);
                let enumeration = field_ident(&oneof::to_pascal_case(oneof_name));
                let variant = field_ident(&oneof::to_pascal_case(&fv.field_name));
                quote! {
                    matches!(
                        &self.#accessor,
                        Some(#module::#enumeration::#variant(_))
                    )
                }
            } else {
                match &fv.field_type {
                    FieldKind::Message { .. } | FieldKind::Wrapper(_) => {
                        quote! { self.#ident.is_set() }
                    }
                    FieldKind::Repeated(_) | FieldKind::Map { .. } => {
                        quote! { !self.#ident.is_empty() }
                    }
                    FieldKind::Optional(_) => quote! { self.#ident.is_some() },
                    FieldKind::String | FieldKind::Bytes => quote! { !self.#ident.is_empty() },
                    FieldKind::Bool => quote! { self.#ident },
                    FieldKind::Int32 | FieldKind::Sint32 | FieldKind::Sfixed32 => {
                        quote! { self.#ident != 0i32 }
                    }
                    FieldKind::Int64 | FieldKind::Sint64 | FieldKind::Sfixed64 => {
                        quote! { self.#ident != 0i64 }
                    }
                    FieldKind::Uint32 | FieldKind::Fixed32 => quote! { self.#ident != 0u32 },
                    FieldKind::Uint64 | FieldKind::Fixed64 => quote! { self.#ident != 0u64 },
                    FieldKind::Float => quote! { self.#ident != 0f32 },
                    FieldKind::Double => quote! { self.#ident != 0f64 },
                    FieldKind::Enum { .. } => quote! { (self.#ident as i32) != 0i32 },
                }
            };
            Some(quote! { if #expr { __count += 1; } })
        })
        .collect();
    let required = spec.required;
    Ok(quote! {
        {
            let mut __count: usize = 0;
            #( #checks )*
            if __count > 1 {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("message.oneof"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            } else if __count == 0 && #required {
                violations.push(::protovalidate_buffa::Violation {
                    field: ::protovalidate_buffa::FieldPath::default(),
                    rule: ::protovalidate_buffa::FieldPath::default(),
                    rule_id: ::std::borrow::Cow::Borrowed("message.oneof"),
                    message: ::std::borrow::Cow::Borrowed(""),
                    for_key: false,
                });
            }
        }
    })
}
