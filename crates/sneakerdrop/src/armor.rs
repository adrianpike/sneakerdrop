//! Text armor (spec §9.3).

use data_encoding::{BASE32_NOPAD, BASE64_NOPAD};

pub const END_MARKER: &str = "== PORDREKAENS ==";
const LINE_WIDTH: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Encoding {
    #[default]
    Base64,
    /// For case-insensitive channels such as Morse.
    Base32,
}

impl Encoding {
    fn tag(self) -> &'static str {
        match self {
            Encoding::Base64 => "B64",
            Encoding::Base32 => "B32",
        }
    }
}

/// Wraps bundle bytes in armor.
pub fn armor(bundle: &[u8], encoding: Encoding) -> String {
    let body = match encoding {
        Encoding::Base64 => BASE64_NOPAD.encode(bundle),
        Encoding::Base32 => BASE32_NOPAD.encode(bundle).to_ascii_lowercase(),
    };
    let mut out = format!("== SNEAKERDROP 1 {} ==\n", encoding.tag());
    for chunk in body.as_bytes().chunks(LINE_WIDTH) {
        out.push_str(std::str::from_utf8(chunk).expect("base encodings are ASCII"));
        out.push('\n');
    }
    out.push_str(END_MARKER);
    out.push('\n');
    out
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dearmored {
    /// Decoded block contents, in order of appearance.
    pub blocks: Vec<Vec<u8>>,
    /// Blocks that were abandoned, unterminated, or failed to decode.
    pub failed: usize,
    /// Blocks of a protocol version other than 1 (e.g. v0 ledgers), skipped.
    pub other_versions: usize,
}

enum Marker {
    Begin(Option<Encoding>),
    BeginOtherVersion,
    End,
}

fn classify(line: &str) -> Option<Marker> {
    let norm = line
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    if norm == END_MARKER {
        return Some(Marker::End);
    }
    let inner = norm.strip_prefix("== SNEAKERDROP ")?.strip_suffix(" ==")?;
    let mut parts = inner.split(' ');
    match parts.next()? {
        "1" => Some(Marker::Begin(match (parts.next(), parts.next()) {
            (Some("B64"), None) => Some(Encoding::Base64),
            (Some("B32"), None) => Some(Encoding::Base32),
            _ => None,
        })),
        _ => Some(Marker::BeginOtherVersion),
    }
}

fn decode_body(encoding: Encoding, body: &str) -> Option<Vec<u8>> {
    let trimmed = body.trim_end_matches('=');
    match encoding {
        Encoding::Base64 => BASE64_NOPAD.decode(trimmed.as_bytes()).ok(),
        Encoding::Base32 => BASE32_NOPAD
            .decode(trimmed.to_ascii_uppercase().as_bytes())
            .ok(),
    }
}

/// Extracts every armored block from `text`, ignoring surrounding noise.
pub fn dearmor(text: &str) -> Dearmored {
    enum State {
        Outside,
        Inside(Option<Encoding>, String),
        OtherVersion,
    }
    let mut out = Dearmored::default();
    let mut state = State::Outside;
    for line in text.lines() {
        match classify(line) {
            Some(Marker::Begin(enc)) => {
                if matches!(state, State::Inside(..)) {
                    out.failed += 1;
                }
                state = State::Inside(enc, String::new());
            }
            Some(Marker::BeginOtherVersion) => {
                if matches!(state, State::Inside(..)) {
                    out.failed += 1;
                }
                out.other_versions += 1;
                state = State::OtherVersion;
            }
            Some(Marker::End) => {
                if let State::Inside(enc, body) = &state {
                    match enc.and_then(|e| decode_body(e, body)) {
                        Some(bytes) => out.blocks.push(bytes),
                        None => out.failed += 1,
                    }
                }
                state = State::Outside;
            }
            None => {
                if let State::Inside(_, body) = &mut state {
                    body.extend(line.chars().filter(|c| !c.is_whitespace()));
                }
            }
        }
    }
    if matches!(state, State::Inside(..)) {
        out.failed += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_both_encodings() {
        let data: Vec<u8> = (0..=255).collect();
        for enc in [Encoding::Base64, Encoding::Base32] {
            let text = armor(&data, enc);
            assert!(
                text.lines()
                    .all(|l| l.len() <= LINE_WIDTH || l.starts_with("=="))
            );
            assert_eq!(dearmor(&text).blocks, vec![data.clone()]);
        }
    }

    #[test]
    fn tolerates_noise_case_and_spacing() {
        let data = b"the quick brown fox".to_vec();
        let text = armor(&data, Encoding::Base32).to_uppercase();
        let text = text.replace(
            "== SNEAKERDROP 1 B32 ==",
            "  ==   sneakerdrop  1   b32 ==  ",
        );
        let noisy = format!("CQ CQ de N0CALL\nrandom chatter == \n{text}\n73 and good night\n");
        assert_eq!(dearmor(&noisy).blocks, vec![data]);
    }

    #[test]
    fn restarts_on_new_begin_and_skips_bad_blocks() {
        let a = armor(b"first", Encoding::Base64);
        let b = armor(b"second", Encoding::Base64);
        let broken = a.lines().take(2).collect::<Vec<_>>().join("\n");
        let garbage = "== SNEAKERDROP 1 B64 ==\n!!!!\n== PORDREKAENS ==\n";
        let v0 = "== SNEAKERDROP 0 ==\n{\"v\":0}\n== PORDREKAENS ==\n";
        let text = format!("{broken}\n{garbage}{v0}{b}");
        let d = dearmor(&text);
        assert_eq!(d.blocks, vec![b"second".to_vec()]);
        assert_eq!(d.failed, 2);
        assert_eq!(d.other_versions, 1);
    }

    #[test]
    fn accepts_padding() {
        let text = "== SNEAKERDROP 1 B64 ==\naGk=\n== PORDREKAENS ==\n";
        assert_eq!(dearmor(text).blocks, vec![b"hi".to_vec()]);
    }

    proptest! {
        #[test]
        fn dearmor_never_panics(text in "\\PC{0,400}") {
            let _ = dearmor(&text);
        }

        #[test]
        fn roundtrip_amid_noise(data in proptest::collection::vec(any::<u8>(), 0..200),
                                pre in "[a-z ]{0,40}", post in "[a-z ]{0,40}", b32: bool) {
            let enc = if b32 { Encoding::Base32 } else { Encoding::Base64 };
            let text = format!("{pre}\n{}{post}\n", armor(&data, enc));
            prop_assert_eq!(dearmor(&text).blocks, vec![data]);
        }
    }
}
