//! Deterministic simulation and fault-injection harness for Sneakerdrop.
//!
//! A simulation is a pure function of its [`Config`] (including the seed):
//! the same config always produces the same run, so any failure can be
//! replayed exactly with `sneakerdrop-sim run --scenario NAME --seed N --trace`.
//!
//! The world is a set of villages whose residents meet at random and swap USB
//! ledgers or reconcile; couriers carry records between villages, one-way radio
//! links push records over noisy text channels, and adversaries relay while
//! tampering, forging, replaying, flooding, and lying. Throughout, the harness
//! checks the properties the spec promises (see [`check`]).

pub mod adversary;
pub mod check;
pub mod config;
pub mod net;
pub mod report;
pub mod rng;
pub mod world;

pub use config::{Adversary, Config};
pub use report::Report;

pub fn run(cfg: Config) -> Report {
    world::World::new(cfg).run()
}
