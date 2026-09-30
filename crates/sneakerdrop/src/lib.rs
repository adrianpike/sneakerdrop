//! Reference implementation of the Sneakerdrop v1 protocol.
//!
//! See `docs/SPEC.md` at the repository root. Section references in this crate
//! (e.g. "spec §8") refer to that document.
//!
//! The crate performs no I/O and never reads the system clock: callers supply
//! the current time and a random number generator. This keeps every operation
//! deterministic, which the simulator (`sneakerdrop-sim`) relies on.

pub mod armor;
pub mod bundle;
pub mod codec;
pub mod crypto;
pub mod ledger;
pub mod record;
pub mod sync;

/// Protocol constants (spec §6).
pub mod consts {
    pub const MAX_RECORD_SIZE: usize = 65_536;
    pub const MAX_TTL: u64 = 365 * 86_400;
    pub const MAX_HORIZON: u64 = 372 * 86_400;
    pub const PAD_BLOCK: usize = 64;
    pub const SUMMARY_PREFIX: usize = 8;
    pub const SALT_LEN: usize = 16;
    pub const CHECKSUM_LEN: usize = 4;
}

pub use armor::{Encoding, armor, dearmor};
pub use bundle::{Item, Summary, decode_bundle, encode_bundle, encode_ledger_file, encode_records};
pub use crypto::{Identity, PublicKey};
pub use ledger::{Admitted, Ledger, Policy, Reject};
pub use record::{Message, Opened, Record, RecordId, SealOptions};
