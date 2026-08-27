//! Plugin SDK - Macros and helpers for plugin development

use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::{format_ident, quote};
use syn::{parse_macro_input, AttributeArgs, DeriveInput, ItemFn, Lit, NestedMeta, Str};

/// Derive macro for PluginManifest
pub fn derive_plugin_manifest(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let expanded = quote! {
        impl openre_plugins::PluginManifest for #name {
            fn metadata() -> openre_plugins::PluginMetadata {
                openre_plugins::PluginMetadata {
                    name: stringify!(#name).to_string(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    description: env!("CARGO_PKG_DESCRIPTION").to_string(),
                    author: env!("CARGO_PKG_AUTHORS").to_string(),
                    license: env!("CARGO_PKG_LICENSE").to_string(),
                    repository: env!("CARGO_PKG_REPOSITORY").to_string(),
                    homepage: None,
                    categories: vec![],
                    keywords: vec![],
                }
            }

            fn required_capabilities() -> openre_plugins::CapabilitySet {
                openre_plugins::CapabilitySet::new()
            }

            fn optional_capabilities() -> openre_plugins::CapabilitySet {
                openre_plugins::CapabilitySet::new()
            }
        }
    };

    TokenStream::from(expanded)
}

/// Attribute macro for plugin commands
#[proc_macro_attribute]
pub fn plugin_command(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let func = parse_macro_input!(input as ItemFn);

    let name = &func.sig.ident;
    let cmd_name = args
        .first()
        .and_then(|arg| match arg {
            NestedMeta::Lit(Lit::Str(s)) => Some(s.value()),
            _ => None,
        })
        .unwrap_or_else(|| name.to_string());

    let register_name = format!("{}_register", name);
    let register_ident = Ident::new(&register_name, name.span());

    let expanded = quote! {
        #func

        /// Plugin command registration
        pub fn #register_ident() -> openre_plugins::sdk::CommandRegistration {
            openre_plugins::sdk::CommandRegistration {
                name: #cmd_name.to_string(),
                description: String::new(),
                handler: #name,
            }
        }
    };

    TokenStream::from(expanded)
}

/// Attribute macro for plugin capabilities
#[proc_macro_attribute]
pub fn plugin_capability(args: TokenStream, input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(args as AttributeArgs);
    let func = parse_macro_input!(input as ItemFn);

    let cap_name = args
        .first()
        .and_then(|arg| match arg {
            NestedMeta::Lit(Lit::Str(s)) => Some(s.value()),
            _ => None,
        })
        .expect("Expected capability name as string argument");

    let capability_name = format!("{}_capability", func.sig.ident);
    let capability_ident = Ident::new(&capability_name, func.sig.ident.span());

    let expanded = quote! {
        #func

        /// Capability registration
        pub fn #capability_ident() -> openre_plugins::Capability {
            openre_plugins::Capability::#cap_name
        }
    };

    TokenStream::from(expanded)
}

/// Plugin initialization function
#[proc_macro]
pub fn plugin_init(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as ItemFn);
    let name = &input.sig.ident;

    let expanded = quote! {
        #input

        #[no_mangle]
        pub extern "C" fn plugin_init() -> *const openre_plugins::sdk::PluginInitInfo {
            static INIT_INFO: openre_plugins::sdk::PluginInitInfo = openre_plugins::sdk::PluginInitInfo {
                name: env!("CARGO_PKG_NAME"),
                version: env!("CARGO_PKG_VERSION"),
                init_fn: #name,
            };
            &INIT_INFO
        }
    };

    TokenStream::from(expanded)
}

/// Helper types for SDK
pub mod sdk {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginInitInfo {
        pub name: &'static str,
        pub version: &'static str,
        pub init_fn: fn() -> PluginInstance,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandRegistration {
        pub name: String,
        pub description: String,
        pub handler: fn(CommandContext) -> anyhow::Result<CommandResult>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandContext {
        pub plugin_id: String,
        pub args: HashMap<String, serde_json::Value>,
        pub capabilities: Vec<super::Capability>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CommandResult {
        pub success: bool,
        pub output: Option<serde_json::Value>,
        pub error: Option<String>,
    }

    pub type PluginInstance = Box<dyn Plugin>;

    pub trait Plugin: Send + Sync {
        fn metadata(&self) -> super::PluginMetadata;
        fn capabilities(&self) -> super::CapabilitySet;
        fn commands(&self) -> Vec<CommandRegistration>;
        fn initialize(&mut self, config: serde_json::Value) -> anyhow::Result<()>;
        fn shutdown(&mut self) -> anyhow::Result<()>;
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct PluginMetadata {
        pub name: String,
        pub version: String,
        pub description: String,
        pub author: String,
        pub license: String,
        pub repository: String,
        pub homepage: Option<String>,
        pub categories: Vec<String>,
        pub keywords: Vec<String>,
    }
}
