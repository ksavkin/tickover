// These docs are the app's own internal reference, built with private items
// included; a public item's doc linking a private helper is intended, not a leak.
#![allow(rustdoc::private_intra_doc_links)]

//! Tickover — library surface.
//!
//! The provider plugin system (declarative TOML manifests + generic engines)
//! lives here (no UI deps) so it can be unit- and integration-tested without
//! building the whole Slint/tray binary — see `crate::plugin`'s module docs.

pub mod menubar;
pub mod model;
pub mod plugin;
