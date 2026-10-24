//! The Offshelf Mac app's engine, in Rust: an unlocked shelf served to macOS
//! as a loopback NFS mount, with range reads, a chunk cache, pins, offload,
//! background uploads and host switching. The Swift app drives it through
//! the UniFFI bindings in `ffi`.

pub mod activity;
pub mod cache;
pub mod engine;
pub mod ffi;
pub mod mount;
pub mod nfs;
pub mod settings;
pub mod sync;
pub mod view;
pub mod write;

pub use engine::Engine;

uniffi::setup_scaffolding!();
