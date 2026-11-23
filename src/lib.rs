//! agmi: one participation engine, explicit effects, durable outcomes.
//!
//! Harness adapters generate judgments; only the runtime submits MinePOA work.
//!
//! This crate is distributed as a command-line application. Its Rust modules
//! support the CLI and are not a supported SDK. See the
//! [operating guide](https://github.com/tomismeta/agmi/blob/main/docs/OPERATIONS.md)
//! for installation, configuration, and upgrades.

pub mod admin;
pub mod capability;
pub mod config;
pub mod doctor;
pub mod endpoints;
pub mod epoch;
pub mod health;
mod installer;
pub mod journal;
pub mod lifecycle;
pub mod logs;
pub mod protocol;
pub mod registration;
pub mod runtime;
pub mod solver;
pub mod store;
pub mod update;
