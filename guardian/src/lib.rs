//! Guardian — privacy-preserving elderly-care room monitoring.
//!
//! The binary lives in `main.rs`; this library exists so the replay tool and
//! the integration tests can share the wire-format parsers and the alert state
//! machine rather than reimplementing them.

pub mod alerts;
pub mod capture;
pub mod net;
pub mod vitals;
