//! Restricted service definitions keep the wire contract explicit and portable.
use proc_macro::TokenStream;
use quote::{format_ident, quote};
use std::collections::BTreeSet;
use syn::{
    parse_macro_input, spanned::Spanned, FnArg, GenericArgument, ItemTrait, Pat, PathArguments,
    ReturnType, TraitItem, Type,
};

#[proc_macro_attribute]
pub fn service(attr: TokenStream, input: TokenStream) -> TokenStream {
    let mut name = None;
    let mut version = None;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("name") {
            name = Some(meta.value()?.parse::<syn::LitStr>()?);
        } else if meta.path.is_ident("version") {
            version = Some(meta.value()?.parse::<syn::LitInt>()?);
        } else {
            return Err(meta.error("expected name or version"));
        }
        Ok(())
    });
    parse_macro_input!(attr with parser);
    let item = parse_macro_input!(input as ItemTrait);
    expand(item, name, version)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

fn err(node: impl Spanned, text: &str) -> syn::Error {
    syn::Error::new(node.span(), text)
}

fn owned(ty: &Type) -> syn::Result<()> {
    use syn::visit::Visit;
    struct Check(Option<syn::Error>);
    impl<'a> Visit<'a> for Check {
        fn visit_type(&mut self, ty: &'a Type) {
            if matches!(
                ty,
                Type::Reference(_) | Type::Ptr(_) | Type::ImplTrait(_) | Type::TraitObject(_)
            ) {
                self.0 = Some(err(ty, "service values must be owned serializable types"));
            }
            syn::visit::visit_type(self, ty);
        }
        fn visit_path_segment(&mut self, segment: &'a syn::PathSegment) {
            if ["u64", "i64", "u128", "i128", "usize", "isize"]
                .iter()
                .any(|s| segment.ident == s)
            {
                self.0 = Some(err(
                    segment,
                    "use a decimal string newtype for unrestricted wire integers",
                ));
            }
            syn::visit::visit_path_segment(self, segment);
        }
    }
    let mut check = Check(None);
    check.visit_type(ty);
    check.0.map_or(Ok(()), Err)
}

fn expand(
    mut item: ItemTrait,
    name: Option<syn::LitStr>,
    version: Option<syn::LitInt>,
) -> syn::Result<proc_macro2::TokenStream> {
    let rpc_name = match proc_macro_crate::crate_name("gcoms-rpc") {
        Ok(proc_macro_crate::FoundCrate::Name(name)) => name,
        Ok(proc_macro_crate::FoundCrate::Itself) => "gcoms_rpc".into(),
        Err(_) => match proc_macro_crate::crate_name("gcoms") {
            Ok(proc_macro_crate::FoundCrate::Name(name)) => format!("{name}::rpc"),
            Ok(proc_macro_crate::FoundCrate::Itself) => "gcoms::rpc".into(),
            Err(_) => "gcoms_rpc".into(),
        },
    };
    let rpc: syn::Path = syn::parse_str(&format!("::{rpc_name}"))?;
    let serde_crate = format!("{rpc_name}::serde");
    let schema_crate = format!("{rpc_name}::schemars");
    let ts_crate = format!("{rpc_name}::ts_rs");

    let name = name.ok_or_else(|| err(&item, "service requires an explicit name"))?;
    if name.value().is_empty()
        || name.value().len() > 80
        || !name
            .value()
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'-'))
    {
        return Err(err(
            &name,
            "service name must be a short lowercase dotted identifier",
        ));
    }
    let version =
        version.ok_or_else(|| err(&item, "service requires an explicit major version"))?;
    if version.base10_parse::<u16>()? == 0 {
        return Err(err(&version, "service version must be positive"));
    }
    if !item.generics.params.is_empty()
        || item.generics.where_clause.is_some()
        || !item.supertraits.is_empty()
        || item.unsafety.is_some()
    {
        return Err(err(
            &item,
            "service traits cannot be generic, unsafe or have supertraits",
        ));
    }
    let ident = &item.ident;
    let vis = &item.vis;
    let client = format_ident!("{}Client", ident);
    let dispatcher = format_ident!("{}Dispatcher", ident);
    let contract = format_ident!("{}Contract", ident);
    let mut structs = Vec::new();
    let mut methods = Vec::new();
    let mut metadata = Vec::new();
    let mut validate = Vec::new();
    let mut dispatch = Vec::new();
    let mut ids = BTreeSet::new();
    for member in &mut item.items {
        let TraitItem::Fn(method) = member else {
            return Err(err(member, "services contain only async methods"));
        };
        let sig = &method.sig;
        if sig.asyncness.is_none()
            || sig.unsafety.is_some()
            || sig.constness.is_some()
            || sig.abi.is_some()
            || !sig.generics.params.is_empty()
            || sig.generics.where_clause.is_some()
            || method.default.is_some()
            || sig.variadic.is_some()
        {
            return Err(err(
                method,
                "service methods must be plain async declarations without generics or defaults",
            ));
        }
        if !matches!(sig.inputs.first(), Some(FnArg::Receiver(r)) if r.reference.is_some() && r.mutability.is_none())
        {
            return Err(err(sig, "service methods require &self"));
        }
        let mut id = None;
        let mut kind = None;
        for attr in &method.attrs {
            if attr.path().is_ident("rpc") {
                attr.parse_nested_meta(|meta| {
                    if meta.path.is_ident("id") {
                        id = Some(meta.value()?.parse::<syn::LitStr>()?);
                    } else if meta.path.is_ident("kind") {
                        kind = Some(meta.value()?.parse::<syn::LitStr>()?);
                    } else {
                        return Err(meta.error("expected id or kind"));
                    }
                    Ok(())
                })?;
            }
        }
        method.attrs.retain(|a| !a.path().is_ident("rpc"));
        let id = id.ok_or_else(|| err(sig, "each method requires #[rpc(id = ..., kind = ...)]"))?;
        if id.value().is_empty()
            || !id.value().as_bytes()[0].is_ascii_lowercase()
            || id.value().len() > 80
            || !id
                .value()
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
            || !ids.insert(id.value())
        {
            return Err(err(&id, "method IDs must be unique lowercase identifiers"));
        }
        let kind = kind.ok_or_else(|| err(sig, "method kind must be explicit"))?;
        let kind_variant = match kind.value().as_str() {
            "query" => quote!(Query),
            "operation" => quote!(Operation),
            "session" => quote!(Session),
            _ => return Err(err(&kind, "kind must be query, operation or session")),
        };
        let ReturnType::Type(_, result) = &sig.output else {
            return Err(err(sig, "return Result<Output, Error>"));
        };
        let Type::Path(path) = result.as_ref() else {
            return Err(err(result, "return Result<Output, Error>"));
        };
        let segment = path.path.segments.last().unwrap();
        let PathArguments::AngleBracketed(params) = &segment.arguments else {
            return Err(err(result, "return Result<Output, Error>"));
        };
        if segment.ident != "Result" || params.args.len() != 2 {
            return Err(err(result, "return Result<Output, Error>"));
        }
        let (GenericArgument::Type(output), GenericArgument::Type(error)) =
            (&params.args[0], &params.args[1])
        else {
            return Err(err(result, "return Result<Output, Error>"));
        };
        owned(output)?;
        owned(error)?;
        let mut args = Vec::new();
        let mut types = Vec::new();
        let mut invoke_args = Vec::new();
        let mut has_context = false;
        for arg in sig.inputs.iter().skip(1) {
            let FnArg::Typed(arg) = arg else {
                return Err(err(arg, "invalid argument"));
            };
            let Pat::Ident(pat) = arg.pat.as_ref() else {
                return Err(err(arg, "use named arguments"));
            };
            if matches!(arg.ty.as_ref(), Type::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "CallContext"))
            {
                if has_context {
                    return Err(err(arg, "only one invocation context is allowed"));
                }
                has_context = true;
                invoke_args.push(quote!(context));
                continue;
            }
            if pat.by_ref.is_some() || pat.subpat.is_some() {
                return Err(err(arg, "use plain named arguments"));
            }
            owned(&arg.ty)?;
            args.push(pat.ident.clone());
            types.push(arg.ty.clone());
            let field = &pat.ident;
            invoke_args.push(quote!(args.#field));
        }
        let method_name = &sig.ident;
        let arg_name = format_ident!("{}{}Args", ident, pascal(&method_name.to_string()));
        let prep_name = format_ident!("prepare_{}", method_name);
        structs.push(quote! {
            #[derive(Clone, Debug, #rpc::serde::Serialize, #rpc::serde::Deserialize, #rpc::schemars::JsonSchema, #rpc::ts_rs::TS)]
            #[serde(crate = #serde_crate, deny_unknown_fields)]
            #[schemars(crate = #schema_crate)]
            #[ts(crate = #ts_crate)]
            #vis struct #arg_name { #(pub #args: #types),* }
        });
        metadata.push(quote! {
            #rpc::Method {
                id: #id.into(), kind: #rpc::MethodKind::#kind_variant,
                args_schema: #rpc::serde_json::to_value(#rpc::schemars::schema_for!(#arg_name)).expect("schema"),
                output_schema: #rpc::serde_json::to_value(#rpc::schemars::schema_for!(#output)).expect("schema"),
                error_schema: #rpc::serde_json::to_value(#rpc::schemars::schema_for!(#error)).expect("schema"),
                args_typescript: <#arg_name as #rpc::ts_rs::TS>::inline(),
                output_typescript: <#output as #rpc::ts_rs::TS>::inline(),
                error_typescript: <#error as #rpc::ts_rs::TS>::inline(),
            }
        });
        validate.push(quote! { #id => {
            let args: #arg_name = #rpc::serde_json::from_value(args).map_err(|e| #rpc::RpcError::invalid(e.to_string()))?;
            #rpc::serde_json::to_value(args).map_err(|e| #rpc::RpcError::invalid(e.to_string()))
        } });
        dispatch.push(quote! { #id => {
            let args: #arg_name = #rpc::serde_json::from_value(args).map_err(|e| #rpc::RpcError::invalid(e.to_string()))?;
            #rpc::encode_outcome(self.0.#method_name(#(#invoke_args),*).await)
        } });
        if kind.value() == "operation" {
            methods.push(quote! {
                #vis fn #prep_name(&self, #(#args: #types),*) -> Result<#rpc::Prepared<#output, #error>, #rpc::RpcError> {
                    self.inner.prepare(#name, #version, #id, &#arg_name {#(#args),*})
                }
                #vis async fn #method_name(&self, #(#args: #types),*) -> Result<#output, #rpc::CallError<#error>> {
                    let prepared = self.#prep_name(#(#args),*).map_err(#rpc::CallError::Rpc)?;
                    self.inner.start_and_wait(&prepared).await
                }
            });
        } else {
            methods.push(quote! {
                #vis async fn #method_name(&self, #(#args: #types),*) -> Result<#output, #rpc::CallError<#error>> {
                    self.inner.call(#name, #version, #id, &#arg_name {#(#args),*}).await
                }
            });
        }
    }
    if ids.is_empty() {
        return Err(err(&item, "service must have at least one method"));
    }
    Ok(quote! {
        #[cfg_attr(target_arch = "wasm32", #rpc::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), #rpc::async_trait)]
        #item
        #(#structs)*
        #vis struct #contract;
        impl #contract {
            #vis fn descriptor() -> #rpc::Service { #rpc::Service {name: #name.into(), version: #version, methods: vec![#(#metadata),*]} }
        }
        #vis struct #client<T> { pub inner: #rpc::Client<T> }
        impl<T: #rpc::Transport> #client<T> {
            #vis fn new(inner: #rpc::Client<T>) -> Self { Self {inner} }
            #vis fn descriptor() -> #rpc::Service { #contract::descriptor() }
            #(#methods)*
        }
        #vis struct #dispatcher<H>(pub H);
        #[cfg_attr(target_arch = "wasm32", #rpc::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), #rpc::async_trait)]
        impl<H: #ident + Send + Sync> #rpc::Dispatch for #dispatcher<H> {
            fn descriptor(&self) -> #rpc::Service { #contract::descriptor() }
            fn validate(&self, method: &str, args: #rpc::serde_json::Value) -> Result<#rpc::serde_json::Value, #rpc::RpcError> {
                match method { #(#validate,)* _ => Err(#rpc::RpcError::new(#rpc::ErrorCode::Method, "unknown method")) }
            }
            async fn invoke(&self, context: #rpc::CallContext, method: &str, args: #rpc::serde_json::Value) -> Result<#rpc::Outcome, #rpc::RpcError> {
                let _ = &context;
                match method { #(#dispatch,)* _ => Err(#rpc::RpcError::new(#rpc::ErrorCode::Method, "unknown method")) }
            }
        }
    })
}
fn pascal(s: &str) -> String {
    s.split('_')
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn method_ids_must_be_portable_typescript_identifiers() {
        for id in ["1method", "__proto__"] {
            let item = syn::parse_quote! {
                pub trait Example {
                    #[rpc(id = #id, kind = "query")]
                    async fn example(&self) -> Result<String, String>;
                }
            };
            let error = super::expand(
                item,
                Some(syn::parse_quote!("example")),
                Some(syn::parse_quote!(1)),
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                "method IDs must be unique lowercase identifiers"
            );
        }
    }
}
