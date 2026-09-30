//! Simulation parameters and named scenarios.

use sneakerdrop::Policy;

/// Behaviour of an adversarial node. Adversaries relay records like anyone
/// else, but also misbehave in the ways described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Adversary {
    /// Drops some records it relays and bit-flips others.
    Tamperer,
    /// Forges broadcasts under honest authors' keys, and sealed messages
    /// whose inner signature claims an honest sender.
    Forger,
    /// Publishes burns with guessed secrets or wrong expiries, and re-stamped
    /// copies of real burns.
    BurnForger,
    /// Hoards every record it sees and replays the hoard forever, including
    /// records that have since expired.
    Replayer,
    /// Injects well-formed junk: random sealed records, reserved kinds, burns
    /// aimed at nothing, and records expiring exactly at the acceptance horizon.
    Flooder,
    /// Lies in reconciliation summaries by echoing the peer's own summary back.
    Liar,
}

#[derive(Debug, Clone)]
pub struct Radio {
    /// Number of one-way radio links (a sender and a listening village).
    pub links: usize,
    /// Transmit every this many steps.
    pub every: u64,
    /// Per-character corruption probability.
    pub char_error: f64,
    /// Per-line loss probability.
    pub line_loss: f64,
    /// Use base32 and upper-case the channel, like Morse.
    pub morse: bool,
    /// Older records to repeat with each transmission, to cover losses.
    pub repeats: usize,
}

#[derive(Debug, Clone, Default)]
pub struct Faults {
    /// Probability that a USB copy is truncated at a random byte.
    pub usb_truncate: f64,
    /// Probability that a USB copy has one random byte corrupted.
    pub usb_bitrot: f64,
    /// Probability that each message of a reconciliation is lost.
    pub reconcile_loss: f64,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub name: String,
    pub seed: u64,
    pub villages: usize,
    pub per_village: usize,
    /// Honest nodes that travel between villages.
    pub couriers: usize,
    pub steps: u64,
    pub step_secs: u64,
    /// Probability that a given honest node composes a message in a step.
    pub p_compose: f64,
    /// Fraction of composed messages that are sealed (vs broadcast).
    pub p_sealed: f64,
    /// TTL range in days for new records; a few use the 365-day maximum.
    pub ttl_days: (u64, u64),
    /// Probability that a recipient burns a message after reading it.
    pub p_burn: f64,
    /// Probability that a sender retracts a message.
    pub p_retract: f64,
    /// Burn delay range, in steps.
    pub burn_delay: (u64, u64),
    /// Per-pair, per-step meeting probability within a village.
    pub p_meet_village: f64,
    /// Per-step probability that a courier meets someone where it is.
    pub p_meet_courier: f64,
    /// Fraction of meetings that reconcile rather than swap USB ledgers.
    pub p_reconcile: f64,
    pub radio: Option<Radio>,
    pub faults: Faults,
    /// Honest clocks are skewed uniformly within ±this many seconds.
    pub max_skew: u64,
    /// One honest node whose clock lags by this many seconds (beyond tolerance).
    pub bad_clock: Option<u64>,
    pub adversaries: Vec<Adversary>,
    pub policy: Policy,
    /// Isolate this village during this step range.
    pub partition: Option<(usize, u64, u64)>,
    pub check_every: u64,
    pub trace: bool,
}

impl Config {
    pub fn baseline(seed: u64) -> Self {
        Self {
            name: "baseline".into(),
            seed,
            villages: 3,
            per_village: 4,
            couriers: 2,
            steps: 24 * 20,
            step_secs: 3600,
            p_compose: 0.01,
            p_sealed: 0.6,
            ttl_days: (2, 30),
            p_burn: 0.5,
            p_retract: 0.05,
            burn_delay: (1, 48),
            p_meet_village: 0.02,
            p_meet_courier: 0.1,
            p_reconcile: 0.5,
            radio: None,
            faults: Faults::default(),
            max_skew: 0,
            bad_clock: None,
            adversaries: vec![],
            policy: Policy::default(),
            partition: None,
            check_every: 6,
            trace: false,
        }
    }

    pub fn radio(seed: u64) -> Self {
        Self {
            name: "radio".into(),
            couriers: 0,
            radio: Some(Radio {
                links: 6,
                every: 6,
                char_error: 0.0005,
                line_loss: 0.01,
                morse: false,
                repeats: 4,
            }),
            ..Self::baseline(seed)
        }
    }

    pub fn morse(seed: u64) -> Self {
        let mut c = Self::radio(seed);
        c.name = "morse".into();
        if let Some(r) = &mut c.radio {
            r.morse = true;
            r.char_error = 0.001;
        }
        c
    }

    pub fn hostile(seed: u64) -> Self {
        Self {
            name: "hostile".into(),
            adversaries: vec![
                Adversary::Tamperer,
                Adversary::Forger,
                Adversary::BurnForger,
                Adversary::Replayer,
                Adversary::Flooder,
                Adversary::Liar,
            ],
            ..Self::baseline(seed)
        }
    }

    pub fn chaos(seed: u64) -> Self {
        Self {
            name: "chaos".into(),
            radio: Self::radio(seed).radio,
            faults: Faults {
                usb_truncate: 0.1,
                usb_bitrot: 0.1,
                reconcile_loss: 0.1,
            },
            max_skew: 3 * 86_400,
            partition: Some((1, 24 * 3, 24 * 10)),
            ..Self::hostile(seed)
        }
    }

    pub fn badclock(seed: u64) -> Self {
        Self {
            name: "badclock".into(),
            ttl_days: (300, 365),
            bad_clock: Some(10 * 86_400),
            ..Self::baseline(seed)
        }
    }

    pub fn pow(seed: u64) -> Self {
        Self {
            name: "pow".into(),
            policy: Policy::uniform(6),
            adversaries: vec![Adversary::Flooder, Adversary::BurnForger],
            ..Self::baseline(seed)
        }
    }

    /// A larger network for soak testing.
    pub fn soak(seed: u64) -> Self {
        Self {
            name: "soak".into(),
            villages: 6,
            per_village: 6,
            couriers: 4,
            steps: 24 * 60,
            check_every: 24,
            ..Self::chaos(seed)
        }
    }

    pub const SCENARIOS: &[&str] = &[
        "baseline", "radio", "morse", "hostile", "chaos", "badclock", "pow", "soak",
    ];

    pub fn scenario(name: &str, seed: u64) -> Option<Self> {
        Some(match name {
            "baseline" => Self::baseline(seed),
            "radio" => Self::radio(seed),
            "morse" => Self::morse(seed),
            "hostile" => Self::hostile(seed),
            "chaos" => Self::chaos(seed),
            "badclock" => Self::badclock(seed),
            "pow" => Self::pow(seed),
            "soak" => Self::soak(seed),
            _ => return None,
        })
    }
}
