//! The simulated world: nodes, ground truth, and the main loop.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use sneakerdrop::consts::MAX_TTL;
use sneakerdrop::record::grind;
use sneakerdrop::{Identity, Ledger, Opened, PublicKey, Record, RecordId, SealOptions};

use crate::config::{Adversary, Config};
use crate::report::{Metrics, Report, Violation};
use crate::rng::Rng;

/// Global simulation start time (2027-01-15).
pub const T0: u64 = 1_800_000_000;

pub type Bytes = Arc<[u8]>;

pub struct Node {
    pub idx: usize,
    pub identity: Identity,
    pub ledger: Ledger,
    pub role: Option<Adversary>,
    pub skew: i64,
    pub courier: bool,
    pub location: usize,
    pub bad_clock: bool,
    /// Every admitted, unexpired record: `R` in spec §8.1. Honest nodes only.
    pub admitted: HashMap<RecordId, Record>,
    /// Records already trial-decrypted.
    pub processed: HashSet<RecordId>,
    /// Everything a replayer has ever seen.
    pub hoard: HashMap<RecordId, Bytes>,
    pub radio_cursor: u64,
}

impl Node {
    pub fn now(&self, global: u64) -> u64 {
        global.saturating_add_signed(self.skew)
    }

    pub fn honest(&self) -> bool {
        self.role.is_none()
    }
}

/// Ground truth about an honest sealed message.
pub struct SentMessage {
    pub sender: usize,
    pub recipient: usize,
    pub content: Vec<u8>,
    pub expires: u64,
    pub sent_step: u64,
    pub delivered_step: Option<u64>,
}

struct PendingBurn {
    due_step: u64,
    node: usize,
    target: RecordId,
    expires: u64,
    secret: [u8; 32],
}

pub struct World {
    pub cfg: Config,
    pub rng: Rng,
    pub nodes: Vec<Node>,
    pub step: u64,
    pub global: u64,
    pub metrics: Metrics,
    /// Honest broadcasts, by ID, with their author.
    pub broadcasts: HashMap<RecordId, usize>,
    pub sealed: HashMap<RecordId, SentMessage>,
    /// Targets of burns published by an authorized party, with the step of first publication.
    pub legit_burns: HashMap<RecordId, u64>,
    /// Nodes that published a legitimate burn, by target.
    pub burn_publishers: HashMap<RecordId, Vec<usize>>,
    pub pk_to_node: HashMap<PublicKey, usize>,
    pub radio_links: Vec<(usize, usize)>,
    pending_burns: Vec<PendingBurn>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Local,
    Usb,
    Reconcile,
    Radio,
}

impl World {
    pub fn new(cfg: Config) -> Self {
        let mut rng = Rng::new(cfg.seed);
        let mut nodes = Vec::new();
        let villagers = cfg.villages * cfg.per_village;
        let total = villagers + cfg.couriers + cfg.adversaries.len();
        for idx in 0..total {
            let identity = Identity::generate(&mut rng);
            let (role, courier) = if idx < villagers {
                (None, false)
            } else if idx < villagers + cfg.couriers {
                (None, true)
            } else {
                (Some(cfg.adversaries[idx - villagers - cfg.couriers]), false)
            };
            let location = if idx < villagers {
                idx / cfg.per_village
            } else {
                rng.index(cfg.villages)
            };
            let skew = if cfg.max_skew > 0 && role.is_none() {
                rng.range(0, 2 * cfg.max_skew + 1) as i64 - cfg.max_skew as i64
            } else {
                0
            };
            nodes.push(Node {
                idx,
                identity,
                ledger: Ledger::new(cfg.policy),
                role,
                skew,
                courier,
                location,
                bad_clock: false,
                admitted: HashMap::new(),
                processed: HashSet::new(),
                hoard: HashMap::new(),
                radio_cursor: 0,
            });
        }
        if let Some(lag) = cfg.bad_clock {
            nodes[0].skew = -(lag as i64);
            nodes[0].bad_clock = true;
        }
        let pk_to_node = nodes.iter().map(|n| (n.identity.public(), n.idx)).collect();
        let radio_links = match &cfg.radio {
            Some(r) if cfg.villages > 1 => (0..r.links)
                .map(|_| {
                    let sender = rng.index(villagers);
                    let from = nodes[sender].location;
                    let to = (from + 1 + rng.index(cfg.villages - 1)) % cfg.villages;
                    (sender, to)
                })
                .collect(),
            _ => vec![],
        };
        Self {
            cfg,
            rng,
            nodes,
            step: 0,
            global: T0,
            metrics: Metrics::default(),
            broadcasts: HashMap::new(),
            sealed: HashMap::new(),
            legit_burns: HashMap::new(),
            burn_publishers: HashMap::new(),
            pk_to_node,
            radio_links,
            pending_burns: Vec::new(),
        }
    }

    pub fn trace(&self, msg: impl FnOnce() -> String) {
        if self.cfg.trace {
            eprintln!("[{:>5}] {}", self.step, msg());
        }
    }

    pub fn honest_nodes(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.honest())
            .map(|n| n.idx)
            .collect()
    }

    /// Honest nodes with clocks within tolerance.
    pub fn good_nodes(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .filter(|n| n.honest() && !n.bad_clock)
            .map(|n| n.idx)
            .collect()
    }

    pub fn is_isolated(&self, village: usize) -> bool {
        matches!(self.cfg.partition, Some((v, a, b)) if v == village && (a..b).contains(&self.step))
    }

    /// Runs the full simulation.
    pub fn run(mut self) -> Report {
        let violation = self.run_inner().err();
        if let Some(v) = &violation {
            self.trace(|| format!("VIOLATION {v}"));
        }
        Report {
            scenario: self.cfg.name.clone(),
            seed: self.cfg.seed,
            metrics: self.metrics,
            violation,
        }
    }

    fn run_inner(&mut self) -> Result<(), Violation> {
        for step in 0..self.cfg.steps {
            self.step = step;
            self.global = T0 + step * self.cfg.step_secs;
            for n in 0..self.nodes.len() {
                self.tick(n)?;
            }
            self.publish_due_burns();
            self.move_couriers();
            self.meetings();
            self.radio()?;
            self.process_inboxes()?;
            if step % self.cfg.check_every == 0 {
                self.check_all()?;
            }
        }
        self.step = self.cfg.steps;
        self.global = T0 + self.cfg.steps * self.cfg.step_secs;
        self.publish_due_burns();
        self.check_all()?;
        self.flush()?;
        self.final_checks()
    }

    // -----------------------------------------------------------------------
    // Receiving

    /// Hands raw records to node `to`, as any transport would.
    pub fn deliver(&mut self, to: usize, records: &[Bytes], channel: Channel) {
        let now = self.nodes[to].now(self.global);
        for bytes in records {
            let node = &mut self.nodes[to];
            let id = RecordId::of(bytes);
            if node.role == Some(Adversary::Replayer) {
                node.hoard.entry(id).or_insert_with(|| bytes.clone());
            }
            if node.ledger.contains(&id) {
                self.metrics.duplicates += 1;
                continue;
            }
            let result = Record::parse(bytes.clone())
                .map_err(sneakerdrop::Reject::from)
                .and_then(|r| {
                    let admitted = node.ledger.insert(r.clone(), now)?;
                    if node.honest() {
                        node.admitted.insert(id, r);
                    }
                    Ok(admitted)
                });
            match result {
                Ok(sneakerdrop::Admitted::New) => self.metrics.admitted += 1,
                Ok(sneakerdrop::Admitted::Duplicate) => self.metrics.duplicates += 1,
                Ok(sneakerdrop::Admitted::Burned) => self.metrics.burned_on_arrival += 1,
                Err(e) => {
                    if channel != Channel::Local {
                        self.metrics.reject(&e);
                    }
                    if node.bad_clock && e == sneakerdrop::Reject::BeyondHorizon {
                        self.metrics.bad_clock_horizon_rejects += 1;
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Honest behaviour

    fn tick(&mut self, n: usize) -> Result<(), Violation> {
        if let Some(role) = self.nodes[n].role {
            if role == Adversary::Flooder && self.rng.chance(0.3) {
                let junk = crate::adversary::junk(self, n);
                self.metrics.adversarial_injected += junk.len() as u64;
                self.deliver(n, &junk, Channel::Local);
            }
            return Ok(());
        }
        if !self.rng.chance(self.cfg.p_compose) {
            return Ok(());
        }
        let now = self.nodes[n].now(self.global);
        let ttl = if self.rng.chance(0.05) {
            MAX_TTL
        } else {
            self.rng.range(self.cfg.ttl_days.0, self.cfg.ttl_days.1 + 1) * 86_400
        };
        let expires = now + ttl;
        let len = self.rng.range(0, 300) as usize;
        let content = self.rng.bytes(len);
        let policy = *self.nodes[n].ledger.policy();

        if self.rng.chance(self.cfg.p_sealed) {
            let honest = self.honest_nodes();
            let Some(&to) = honest
                .iter()
                .filter(|&&i| i != n)
                .nth(self.rng.index(honest.len() - 1))
            else {
                return Ok(());
            };
            let recipient = self.nodes[to].identity.public();
            let sender = self.nodes[n].identity.clone();
            let mut secret = [0; 32];
            let rng = &mut self.rng;
            let rec = grind(policy.min_work_sealed, |stamp| {
                let opts = SealOptions {
                    stamp,
                    ..SealOptions::new(now, expires)
                };
                let s = Record::new_sealed(&sender, &recipient, &opts, &content, rng)?;
                secret = s.burn_secret;
                Ok::<_, sneakerdrop::record::RecordError>(s.record)
            })
            .expect("sealing succeeds");
            self.check_sealed_privacy(&rec)?;
            self.trace(|| format!("node {n} seals {} to node {to}", rec.id().short()));
            self.sealed.insert(
                rec.id(),
                SentMessage {
                    sender: n,
                    recipient: to,
                    content,
                    expires,
                    sent_step: self.step,
                    delivered_step: None,
                },
            );
            self.metrics.sealed_sent += 1;
            if self.rng.chance(self.cfg.p_retract) {
                self.schedule_burn(n, rec.id(), expires, secret);
            }
            self.deliver(n, &[rec.shared_bytes()], Channel::Local);
        } else {
            let author = self.nodes[n].identity.clone();
            let rec = grind(policy.min_work_broadcast, |stamp| {
                Record::new_broadcast(&author, now, expires, stamp, &content)
            })
            .expect("broadcast succeeds");
            self.trace(|| format!("node {n} broadcasts {}", rec.id().short()));
            self.broadcasts.insert(rec.id(), n);
            self.metrics.broadcasts_sent += 1;
            self.deliver(n, &[rec.shared_bytes()], Channel::Local);
        }
        Ok(())
    }

    fn schedule_burn(&mut self, node: usize, target: RecordId, expires: u64, secret: [u8; 32]) {
        let delay = self
            .rng
            .range(self.cfg.burn_delay.0, self.cfg.burn_delay.1 + 1);
        self.pending_burns.push(PendingBurn {
            due_step: self.step + delay,
            node,
            target,
            expires,
            secret,
        });
    }

    fn publish_due_burns(&mut self) {
        let (due, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_burns)
            .into_iter()
            .partition(|b| b.due_step <= self.step);
        self.pending_burns = later;
        for b in due {
            let now = self.nodes[b.node].now(self.global);
            if b.expires <= now {
                continue;
            }
            let min_work = self.nodes[b.node].ledger.policy().min_work_burn;
            let rec = grind(min_work, |stamp| {
                Ok::<_, ()>(Record::new_burn(b.target, b.expires, b.secret, stamp))
            })
            .expect("burns are infallible");
            self.trace(|| format!("node {} burns {}", b.node, b.target.short()));
            self.legit_burns.entry(b.target).or_insert(self.step);
            self.burn_publishers
                .entry(b.target)
                .or_default()
                .push(b.node);
            self.metrics.burns_published += 1;
            self.deliver(b.node, &[rec.shared_bytes()], Channel::Local);
        }
    }

    /// Trial-decrypts new sealed records at every honest node, checking that
    /// what opens is exactly what was sent.
    pub fn process_inboxes(&mut self) -> Result<(), Violation> {
        for n in self.honest_nodes() {
            let fresh: Vec<Record> = self.nodes[n]
                .ledger
                .iter()
                .filter(|r| r.as_sealed().is_some() && !self.nodes[n].processed.contains(&r.id()))
                .cloned()
                .collect();
            for rec in fresh {
                self.nodes[n].processed.insert(rec.id());
                let opened = self.nodes[n].identity.open(&rec);
                let truth = self.sealed.get(&rec.id());
                match opened {
                    Opened::Message(m) => {
                        let Some(truth) = truth else {
                            return self.violation(
                                "authenticity",
                                format!(
                                    "node {n} opened {} which no honest node sent",
                                    rec.id().short()
                                ),
                            );
                        };
                        let sender_idx = self.pk_to_node.get(&m.sender).copied();
                        if truth.recipient != n
                            || Some(truth.sender) != sender_idx
                            || truth.content != m.content
                        {
                            return self.violation(
                                "authenticity",
                                format!(
                                    "node {n} opened {} with wrong sender/content",
                                    rec.id().short()
                                ),
                            );
                        }
                        if truth.delivered_step.is_none() {
                            let latency = (self.step - truth.sent_step) * self.cfg.step_secs / 3600;
                            self.metrics.delivered += 1;
                            self.metrics.latency_hours.push(latency);
                            self.sealed
                                .get_mut(&rec.id())
                                .expect("present")
                                .delivered_step = Some(self.step);
                            self.trace(|| {
                                format!("node {n} reads {} after {latency}h", rec.id().short())
                            });
                            if self.rng.chance(self.cfg.p_burn) {
                                self.schedule_burn(n, m.id, m.expires, m.burn_secret);
                            }
                        }
                    }
                    Opened::Forged => {
                        if truth.is_some() {
                            return self.violation(
                                "authenticity",
                                format!("honest message {} judged forged", rec.id().short()),
                            );
                        }
                        self.metrics.forged_detected += 1;
                    }
                    Opened::NotForUs => {
                        if truth.is_some_and(|t| t.recipient == n) {
                            return self.violation(
                                "authenticity",
                                format!(
                                    "node {n} failed to open {} addressed to it",
                                    rec.id().short()
                                ),
                            );
                        }
                    }
                    Opened::NotSealed => unreachable!("filtered to sealed records"),
                }
            }
        }
        Ok(())
    }

    fn check_sealed_privacy(&self, rec: &Record) -> Result<(), Violation> {
        for node in &self.nodes {
            let pk = node.identity.public();
            let leaked = rec
                .bytes()
                .windows(32)
                .any(|w| w == pk.as_bytes() || w == pk.to_x25519());
            if leaked {
                return self.violation(
                    "privacy",
                    format!("sealed record contains node {}'s key", node.idx),
                );
            }
        }
        Ok(())
    }

    pub fn violation<T>(&self, check: &'static str, detail: String) -> Result<T, Violation> {
        Err(Violation {
            step: self.step,
            check,
            detail,
        })
    }

    // -----------------------------------------------------------------------
    // Movement and meetings

    fn move_couriers(&mut self) {
        let villages = self.cfg.villages;
        for n in 0..self.nodes.len() {
            if !self.nodes[n].courier && self.nodes[n].role.is_none() {
                continue;
            }
            // Couriers and adversaries wander between villages.
            if villages > 1 && self.rng.chance(0.05) {
                let from = self.nodes[n].location;
                let to = (from + 1 + self.rng.index(villages - 1)) % villages;
                if !self.is_isolated(from) && !self.is_isolated(to) {
                    self.nodes[n].location = to;
                }
            }
        }
    }

    fn meetings(&mut self) {
        let mut pairs = Vec::new();
        for v in 0..self.cfg.villages {
            let here: Vec<usize> = self
                .nodes
                .iter()
                .filter(|n| n.location == v)
                .map(|n| n.idx)
                .collect();
            for (i, &a) in here.iter().enumerate() {
                for &b in &here[i + 1..] {
                    let both_residents = !self.nodes[a].courier && !self.nodes[b].courier;
                    if both_residents && self.rng.chance(self.cfg.p_meet_village) {
                        pairs.push((a, b));
                    }
                }
                if (self.nodes[a].courier || !self.nodes[a].honest())
                    && self.rng.chance(self.cfg.p_meet_courier)
                    && let Some(&b) = self.rng.pick(&here)
                    && b != a
                {
                    pairs.push((a, b));
                }
            }
        }
        for (a, b) in pairs {
            if self.rng.chance(self.cfg.p_reconcile) {
                crate::net::reconcile(self, a, b);
            } else {
                crate::net::usb_swap(self, a, b);
            }
        }
    }

    fn radio(&mut self) -> Result<(), Violation> {
        let Some(radio) = self.cfg.radio.clone() else {
            return Ok(());
        };
        if !self.step.is_multiple_of(radio.every) {
            return Ok(());
        }
        for (sender, village) in self.radio_links.clone() {
            if self.is_isolated(village) || self.is_isolated(self.nodes[sender].location) {
                continue;
            }
            let listeners: Vec<usize> = self
                .nodes
                .iter()
                .filter(|n| n.location == village && n.idx != sender)
                .map(|n| n.idx)
                .collect();
            crate::net::radio_transmit(self, sender, &listeners, &radio)?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Invariants

    pub fn check_all(&mut self) -> Result<(), Violation> {
        self.metrics.checks += 1;
        for n in self.honest_nodes() {
            crate::check::node_invariants(self, n)?;
        }
        Ok(())
    }

    /// Syncs all good nodes directly with each other until nothing changes.
    fn flush(&mut self) -> Result<(), Violation> {
        let good = self.good_nodes();
        for round in 0..64 {
            self.metrics.flush_rounds = round + 1;
            let before: usize = good.iter().map(|&n| self.nodes[n].ledger.len()).sum();
            let admitted_before = self.metrics.admitted + self.metrics.burned_on_arrival;
            let mut order = good.clone();
            self.rng.shuffle(&mut order);
            for w in 0..order.len() {
                let (a, b) = (order[w], order[(w + 1) % order.len()]);
                crate::net::clean_sync(self, a, b);
            }
            let after: usize = good.iter().map(|&n| self.nodes[n].ledger.len()).sum();
            if before == after
                && admitted_before == self.metrics.admitted + self.metrics.burned_on_arrival
            {
                break;
            }
        }
        self.process_inboxes()?;
        self.check_all()
    }

    fn final_checks(&mut self) -> Result<(), Violation> {
        let good = self.good_nodes();
        self.metrics.final_ledger_records = good
            .iter()
            .map(|&n| self.nodes[n].ledger.len() as u64)
            .sum::<u64>()
            / good.len().max(1) as u64;
        crate::check::final_invariants(self, &good)
    }
}
