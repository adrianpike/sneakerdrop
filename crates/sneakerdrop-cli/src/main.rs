//! `sneakerdrop`: command-line client for the Sneakerdrop v1 protocol.
//!
//! Following v0, stdout carries only protocol data (armor, message bodies) so
//! it can be piped into radios, netcat, or files. Everything else goes to
//! stderr.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rand_core::OsRng;
use sneakerdrop::bundle::{decode_ledger_file, encode_bundle};
use sneakerdrop::consts::MAX_TTL;
use sneakerdrop::ledger::MergeStats;
use sneakerdrop::record::grind;
use sneakerdrop::sync::{missing, read_any, summarize};
use sneakerdrop::{
    Encoding, Identity, Item, Ledger, Opened, Policy, PublicKey, Record, RecordId, SealOptions,
    armor, encode_ledger_file, encode_records,
};

#[derive(Parser)]
#[command(version, about = "A sneakernet meets a dead drop.")]
struct Cli {
    /// State directory [env: SNEAKERDROP_HOME, default: ~/.sneakerdrop]
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// Minimum proof-of-work (bits) required to admit records
    #[arg(long, global = true, default_value_t = 0)]
    min_work: u32,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args, Clone, Copy)]
struct OutputOpts {
    /// Armor with base32 (for case-insensitive channels such as Morse)
    #[arg(long)]
    b32: bool,
}

#[derive(clap::Args, Clone, Copy)]
struct CreateOpts {
    /// Days until the record expires (max 365)
    #[arg(long, default_value_t = 30)]
    ttl_days: u64,
    /// Proof-of-work bits to grind for
    #[arg(long, default_value_t = 0)]
    work: u32,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new identity
    Init,
    /// Print your address
    Whoami,
    /// Sign a public message from stdin, store it, and print it armored
    Broadcast {
        #[command(flatten)]
        create: CreateOpts,
        #[command(flatten)]
        out: OutputOpts,
    },
    /// Seal a private message from stdin to ADDRESS, store it, and print it armored
    Send {
        address: String,
        #[command(flatten)]
        create: CreateOpts,
        #[command(flatten)]
        out: OutputOpts,
        /// Pad the plaintext to at least this many bytes
        #[arg(long, default_value_t = 0)]
        pad: usize,
    },
    /// Show broadcasts and messages addressed to you
    Show {
        /// Also list records you cannot read
        #[arg(long)]
        all: bool,
    },
    /// Burn a message you received or sent, deleting it network-wide
    Burn {
        /// Record ID or unique hex prefix
        id: String,
        #[arg(long, default_value_t = 0)]
        work: u32,
        #[command(flatten)]
        out: OutputOpts,
    },
    /// Merge records from a ledger file, bundle, or armored text (FILE or stdin)
    Import { file: Option<PathBuf> },
    /// Write records to stdout (armored by default)
    Export {
        /// Only records not yet exported with --new
        #[arg(long)]
        new: bool,
        /// Write a binary ledger file to this path instead
        #[arg(long)]
        file: Option<PathBuf>,
        #[command(flatten)]
        out: OutputOpts,
    },
    /// Two-way merge with a ledger file, e.g. on a USB stick
    Sync { path: PathBuf },
    /// Interactive reconciliation over a two-way text link (spec §10.3)
    Reconcile {
        #[command(subcommand)]
        step: ReconcileStep,
    },
    /// Summarize the ledger
    Stats,
}

#[derive(Subcommand)]
enum ReconcileStep {
    /// Step 1: print a summary of your ledger
    Start {
        #[command(flatten)]
        out: OutputOpts,
    },
    /// Steps 2 and 3: read the peer's message from stdin, merge its records, and
    /// print the records it lacks
    Respond {
        /// Also print your own summary (step 2)
        #[arg(long)]
        with_summary: bool,
        #[command(flatten)]
        out: OutputOpts,
    },
}

struct Node {
    home: PathBuf,
    ledger: Ledger,
    now: u64,
}

impl Node {
    fn open(home: PathBuf, policy: Policy) -> Result<Self> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let mut ledger = Ledger::new(policy);
        let path = home.join("ledger.snk");
        if path.exists() {
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let file = decode_ledger_file(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?;
            if file.truncated {
                eprintln!(
                    "warning: ignoring a truncated final entry in {}",
                    path.display()
                );
            }
            ledger.merge_bytes(file.entries.iter().map(Vec::as_slice), now);
        }
        Ok(Self { home, ledger, now })
    }

    fn save(&self) -> Result<()> {
        write_atomic(
            &self.home.join("ledger.snk"),
            &encode_ledger_file(self.ledger.iter()),
        )
    }

    fn identity(&self) -> Result<Identity> {
        let path = self.home.join("identity");
        let text = fs::read_to_string(&path).with_context(|| {
            format!("no identity at {} (run `sneakerdrop init`)", path.display())
        })?;
        let seed = parse_hex::<32>(text.trim()).context("identity file is corrupt")?;
        Ok(Identity::from_seed(seed))
    }

    fn expires(&self, opts: &CreateOpts) -> Result<u64> {
        let ttl = opts.ttl_days * 86_400;
        if ttl == 0 || ttl > MAX_TTL {
            bail!("--ttl-days must be between 1 and 365");
        }
        Ok(self.now + ttl)
    }

    fn admit(&mut self, record: &Record) -> Result<()> {
        self.ledger.insert(record.clone(), self.now)?;
        self.save()
    }

    fn merge_input(&mut self, input: &[u8]) -> (MergeStats, Vec<sneakerdrop::Summary>) {
        let incoming = read_any(input);
        if incoming.failed > 0 {
            eprintln!("warning: {} block(s) could not be decoded", incoming.failed);
        }
        let stats = self
            .ledger
            .merge_bytes(incoming.records.iter().map(Vec::as_slice), self.now);
        (stats, incoming.summaries)
    }

    /// Records the burn secret of a message we sent, so we can retract it.
    fn remember_sent(&self, id: RecordId, expires: u64, secret: &[u8; 32]) -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.home.join("sent"))?;
        writeln!(f, "{} {} {}", id.to_hex(), expires, to_hex(secret))?;
        Ok(())
    }

    fn sent_secret(&self, id: &RecordId) -> Result<Option<(u64, [u8; 32])>> {
        let Ok(text) = fs::read_to_string(self.home.join("sent")) else {
            return Ok(None);
        };
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let [rid, expires, secret] = parts[..]
                && rid == id.to_hex()
            {
                return Ok(Some((expires.parse()?, parse_hex(secret)?)));
            }
        }
        Ok(None)
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let home = match cli
        .home
        .or_else(|| std::env::var_os("SNEAKERDROP_HOME").map(PathBuf::from))
    {
        Some(h) => h,
        None => {
            PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".sneakerdrop")
        }
    };
    fs::create_dir_all(&home)?;
    let mut node = Node::open(home, Policy::uniform(cli.min_work))?;

    match cli.command {
        Command::Init => {
            let path = node.home.join("identity");
            if path.exists() {
                bail!("{} already exists; refusing to overwrite", path.display());
            }
            let id = Identity::generate(&mut OsRng);
            write_private(&path, format!("{}\n", to_hex(&id.seed())).as_bytes())?;
            eprintln!("Created identity. Your address is:");
            println!("{}", id.public());
        }
        Command::Whoami => println!("{}", node.identity()?.public()),
        Command::Broadcast { create, out } => {
            let id = node.identity()?;
            let content = read_stdin("Type your broadcast, then ^D")?;
            let expires = node.expires(&create)?;
            let rec = grind(create.work, |stamp| {
                Record::new_broadcast(&id, node.now, expires, stamp, &content)
            })?;
            node.admit(&rec)?;
            eprintln!("Broadcast {} stored.", rec.id().short());
            print!("{}", armor(&encode_records([&rec]), encoding(out)));
        }
        Command::Send {
            address,
            create,
            out,
            pad,
        } => {
            let id = node.identity()?;
            let to = PublicKey::from_address(&address).context("invalid address")?;
            let content = read_stdin("Type your message, then ^D")?;
            let opts = SealOptions {
                min_padded_len: pad,
                ..SealOptions::new(node.now, node.expires(&create)?)
            };
            let mut secret = [0; 32];
            let rec = grind(create.work, |stamp| {
                let s = Record::new_sealed(
                    &id,
                    &to,
                    &SealOptions {
                        stamp,
                        ..opts.clone()
                    },
                    &content,
                    &mut OsRng,
                )?;
                secret = s.burn_secret;
                Ok::<_, sneakerdrop::record::RecordError>(s.record)
            })?;
            node.admit(&rec)?;
            node.remember_sent(rec.id(), rec.expires(), &secret)?;
            eprintln!("Sealed message {} stored.", rec.id().short());
            print!("{}", armor(&encode_records([&rec]), encoding(out)));
        }
        Command::Show { all } => show(&node, all)?,
        Command::Burn { id, work, out } => {
            let identity = node.identity()?;
            let target = find_record(&node.ledger, &id)?;
            let (expires, secret) = match identity.open(&target) {
                Opened::Message(m) => (m.expires, m.burn_secret),
                _ => node
                    .sent_secret(&target.id())?
                    .context("that record is neither addressed to you nor sent by you")?,
            };
            let rec = grind(work, |stamp| {
                Ok::<_, anyhow::Error>(Record::new_burn(target.id(), expires, secret, stamp))
            })?;
            node.admit(&rec)?;
            eprintln!("Burned {}.", target.id().short());
            print!("{}", armor(&encode_records([&rec]), encoding(out)));
        }
        Command::Import { file } => {
            let input = match file {
                Some(p) => fs::read(&p).with_context(|| format!("reading {}", p.display()))?,
                None => read_stdin_bytes()?,
            };
            let (stats, _) = node.merge_input(&input);
            node.save()?;
            report(&stats);
        }
        Command::Export { new, file, out } => {
            let cursor_path = node.home.join("export-cursor");
            let cursor = if new {
                fs::read_to_string(&cursor_path)
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0)
            } else {
                0
            };
            let records: Vec<&Record> = node.ledger.since(cursor).map(|(_, r)| r).collect();
            match file {
                Some(path) => write_atomic(&path, &encode_ledger_file(records.iter().copied()))?,
                None => {
                    if !records.is_empty() {
                        print!(
                            "{}",
                            armor(&encode_records(records.iter().copied()), encoding(out))
                        );
                    }
                }
            }
            if new {
                fs::write(&cursor_path, node.ledger.last_seq().to_string())?;
            }
            eprintln!("Exported {} record(s).", records.len());
        }
        Command::Sync { path } => {
            if path.exists() {
                let (stats, _) = node.merge_input(&fs::read(&path)?);
                report(&stats);
            }
            node.save()?;
            write_atomic(&path, &encode_ledger_file(node.ledger.iter()))?;
            eprintln!(
                "{} and your ledger now hold {} record(s).",
                path.display(),
                node.ledger.len()
            );
        }
        Command::Reconcile { step } => match step {
            ReconcileStep::Start { out } => {
                let summary = summarize(&node.ledger, &mut OsRng);
                print!(
                    "{}",
                    armor(&encode_bundle(&[Item::Summary(summary)]), encoding(out))
                );
            }
            ReconcileStep::Respond { with_summary, out } => {
                let (stats, summaries) = node.merge_input(&read_stdin_bytes()?);
                node.save()?;
                report(&stats);
                let Some(peer) = summaries.last() else {
                    bail!("no summary found in input");
                };
                let mut items: Vec<Item> = missing(&node.ledger, peer)
                    .into_iter()
                    .map(|r| Item::Record(r.bytes().to_vec()))
                    .collect();
                eprintln!("Sending {} record(s) the peer lacks.", items.len());
                if with_summary {
                    items.push(Item::Summary(summarize(&node.ledger, &mut OsRng)));
                }
                print!("{}", armor(&encode_bundle(&items), encoding(out)));
            }
        },
        Command::Stats => {
            let (mut b, mut s, mut burns, mut other) = (0, 0, 0, 0);
            for r in node.ledger.iter() {
                match r.body() {
                    sneakerdrop::record::Body::Broadcast(_) => b += 1,
                    sneakerdrop::record::Body::Sealed(_) => s += 1,
                    sneakerdrop::record::Body::Burn(_) => burns += 1,
                    sneakerdrop::record::Body::Unknown(_) => other += 1,
                }
            }
            let bytes: usize = node.ledger.iter().map(Record::len).sum();
            println!(
                "records: {}  broadcasts: {b}  sealed: {s}  burns: {burns}  other: {other}  bytes: {bytes}",
                node.ledger.len()
            );
        }
    }
    Ok(())
}

fn show(node: &Node, all: bool) -> Result<()> {
    let me = node.identity().ok();
    let mut rows: Vec<(u64, String)> = Vec::new();
    for r in node.ledger.iter() {
        let id = r.id().short();
        if let Some(b) = r.as_broadcast() {
            rows.push((
                b.created,
                format!(
                    "--- broadcast {id} from {} at {}\n{}",
                    b.author,
                    b.created,
                    String::from_utf8_lossy(&b.content)
                ),
            ));
        } else if r.as_sealed().is_some() {
            match me.as_ref().map(|me| me.open(r)) {
                Some(Opened::Message(m)) => rows.push((
                    m.created,
                    format!(
                        "--- message {id} to you from {} at {}\n{}",
                        m.sender,
                        m.created,
                        String::from_utf8_lossy(&m.content)
                    ),
                )),
                Some(Opened::Forged) => rows.push((
                    0,
                    format!("--- FORGED message {id} (addressed to you, bad signature)"),
                )),
                _ if all => rows.push((0, format!("--- sealed {id} (not for you)"))),
                _ => {}
            }
        } else if all {
            rows.push((0, format!("--- {r:?}")));
        }
    }
    rows.sort_by_key(|(t, _)| *t);
    let mut stdout = io::stdout().lock();
    for (_, row) in &rows {
        writeln!(stdout, "{}\n", row.trim_end())?;
    }
    eprintln!(
        "{} item(s) shown, {} record(s) in ledger.",
        rows.len(),
        node.ledger.len()
    );
    Ok(())
}

fn find_record(ledger: &Ledger, prefix: &str) -> Result<Record> {
    let prefix = prefix.to_ascii_lowercase();
    let matches: Vec<&Record> = ledger
        .iter()
        .filter(|r| r.id().to_hex().starts_with(&prefix))
        .collect();
    match matches[..] {
        [r] => Ok(r.clone()),
        [] => bail!("no record matches {prefix}"),
        _ => bail!("{prefix} is ambiguous ({} matches)", matches.len()),
    }
}

fn report(stats: &MergeStats) {
    eprintln!(
        "{} new, {} duplicate, {} already burned, {} rejected.",
        stats.new, stats.duplicate, stats.burned, stats.rejected
    );
}

fn encoding(out: OutputOpts) -> Encoding {
    if out.b32 {
        Encoding::Base32
    } else {
        Encoding::Base64
    }
}

fn read_stdin(prompt: &str) -> Result<Vec<u8>> {
    if io::IsTerminal::is_terminal(&io::stdin()) {
        eprintln!("{prompt}");
    }
    read_stdin_bytes()
}

fn read_stdin_bytes() -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    io::stdin().read_to_end(&mut buf)?;
    Ok(buf)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)?.write_all(bytes)?;
    Ok(())
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2 || !s.is_ascii() {
        bail!("expected {} hex digits", N * 2);
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
    }
    Ok(out)
}
