//! Metrics and results.

use std::collections::BTreeMap;
use std::fmt;

use sneakerdrop::Reject;

#[derive(Debug, Clone, Default)]
pub struct Metrics {
    pub broadcasts_sent: u64,
    pub sealed_sent: u64,
    pub delivered: u64,
    /// Delivery latency of each delivered sealed message, in hours.
    pub latency_hours: Vec<u64>,
    pub burns_published: u64,
    pub admitted: u64,
    pub duplicates: u64,
    pub burned_on_arrival: u64,
    pub rejected: BTreeMap<&'static str, u64>,
    pub forged_detected: u64,
    pub adversarial_injected: u64,
    pub meetings_usb: u64,
    pub meetings_reconcile: u64,
    pub radio_transmissions: u64,
    pub radio_blocks_lost: u64,
    pub bytes_usb: u64,
    pub bytes_reconcile: u64,
    pub bytes_radio: u64,
    pub checks: u64,
    pub flush_rounds: u64,
    pub final_ledger_records: u64,
    /// Records the badly-clocked node rejected as beyond its horizon.
    pub bad_clock_horizon_rejects: u64,
}

impl Metrics {
    pub fn reject(&mut self, r: &Reject) {
        let key = match r {
            Reject::Malformed(_) => "malformed",
            Reject::Expired => "expired",
            Reject::BeyondHorizon => "beyond_horizon",
            Reject::InsufficientWork { .. } => "insufficient_work",
        };
        *self.rejected.entry(key).or_default() += 1;
    }

    pub fn latency_percentile(&self, p: f64) -> Option<u64> {
        if self.latency_hours.is_empty() {
            return None;
        }
        let mut v = self.latency_hours.clone();
        v.sort_unstable();
        let i = ((v.len() - 1) as f64 * p).round() as usize;
        Some(v[i])
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub step: u64,
    pub check: &'static str,
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "step {}: [{}] {}", self.step, self.check, self.detail)
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub scenario: String,
    pub seed: u64,
    pub metrics: Metrics,
    pub violation: Option<Violation>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violation.is_none()
    }
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.metrics;
        let status = match &self.violation {
            None => "PASS".to_string(),
            Some(v) => format!("FAIL {v}"),
        };
        writeln!(f, "{} seed={} {status}", self.scenario, self.seed)?;
        let pct = |p| {
            m.latency_percentile(p)
                .map_or("-".into(), |h: u64| format!("{h}h"))
        };
        writeln!(
            f,
            "  sent: {} broadcast, {} sealed | delivered {} (latency p50 {} p90 {} max {}) | burns {}",
            m.broadcasts_sent,
            m.sealed_sent,
            m.delivered,
            pct(0.5),
            pct(0.9),
            pct(1.0),
            m.burns_published
        )?;
        writeln!(
            f,
            "  admitted {} dup {} burned-on-arrival {} | rejected {:?} | forged detected {} | adversarial injected {}",
            m.admitted,
            m.duplicates,
            m.burned_on_arrival,
            m.rejected,
            m.forged_detected,
            m.adversarial_injected
        )?;
        writeln!(
            f,
            "  transport: usb {} ({} KiB) reconcile {} ({} KiB) radio {} tx ({} KiB, {} blocks lost)",
            m.meetings_usb,
            m.bytes_usb / 1024,
            m.meetings_reconcile,
            m.bytes_reconcile / 1024,
            m.radio_transmissions,
            m.bytes_radio / 1024,
            m.radio_blocks_lost
        )?;
        write!(
            f,
            "  checks {} | flush rounds {} | final ledger {} records/node",
            m.checks, m.flush_rounds, m.final_ledger_records
        )?;
        if m.bad_clock_horizon_rejects > 0 {
            write!(
                f,
                " | bad-clock horizon rejects {}",
                m.bad_clock_horizon_rejects
            )?;
        }
        Ok(())
    }
}
