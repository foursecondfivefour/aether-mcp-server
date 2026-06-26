//! AETHER_01 — Windows MCP Server library.
//!
//! Re-exports all public modules for use by the binary and integration tests.

pub mod audit;
pub mod command;
pub mod config;
pub mod error;
pub mod server;
pub mod tools;

// Re-export key types for ergonomic test imports
pub use config::FeatureGates;
pub use error::{AetherError, ErrorContext};
pub use server::AetherServer;
