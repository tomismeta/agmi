//! agmi: one participation engine, explicit effects, durable outcomes.
//!
//! Harness adapters generate judgments; only the runtime submits MinePOA work.

pub mod admin;
pub mod config;
pub mod doctor;
pub mod endpoints;
pub mod health;
mod installer;
pub mod lifecycle;
pub mod logs;
pub mod protocol;
pub mod registration;
pub mod runtime;
pub mod solver;
pub mod store;
pub mod update;
