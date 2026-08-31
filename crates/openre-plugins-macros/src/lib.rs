//! Procedural macros for openre-plugins

use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, ItemFn};

/// Derive macro for PluginManifest
#[proc_macro_derive(PluginManifest)]
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
    let _args = args; // We don't need to parse args for now
    let func = parse_macro_input!(input as ItemFn);

    let name = &func.sig.ident;
    let cmd_name = name.to_string();

    let register_name = format!("{}_register", name);
    let register_ident = Ident::new(&register_name, name.span());

    let expanded = quote! {
        #func

        /// Plugin command registration
        pub fn #register_ident() -> openre_plugins::sdk::CommandRegistration {
            openre_plugins::sdk::CommandRegistration {
                name: #cmd_name.to_string(),
                description: String::new(),
                handler: Some(#name),
            }
        }
    };

    TokenStream::from(expanded)
}

/// Attribute macro for plugin capabilities
#[proc_macro_attribute]
pub fn plugin_capability(args: TokenStream, input: TokenStream) -> TokenStream {
    let _args = args; // We don't need to parse args for now
    let func = parse_macro_input!(input as ItemFn);

    let name = &func.sig.ident;
    let cap_name = name.to_string();

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
                init_fn: Some(#name),
            };
            &INIT_INFO
        }
    };

    TokenStream::from(expanded)
}
