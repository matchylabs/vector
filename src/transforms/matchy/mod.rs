//! Matchy threat intelligence matching transform
//!
//! This transform matches log events against threat intelligence databases
//! for IP addresses, domains, hashes, and patterns.

#[cfg(feature = "transforms-matchy")]
pub mod config;

#[cfg(feature = "transforms-matchy")]
pub mod transform;

#[cfg(all(test, feature = "transforms-matchy"))]
mod tests;

#[cfg(feature = "transforms-matchy")]
pub use config::MatchyConfig;
