//! Strict primitive encodings (spec §2).

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("unexpected end of input")]
    Truncated,
    #[error("non-minimal varint")]
    NonMinimalVarint,
    #[error("varint exceeds 64 bits")]
    VarintOverflow,
    #[error("trailing bytes after structure")]
    TrailingBytes,
}

/// Appends `v` as a minimal unsigned LEB128 varint.
pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Number of bytes `put_varint` would write for `v`.
pub fn varint_len(v: u64) -> usize {
    (64 - v.max(1).leading_zeros() as usize).div_ceil(7)
}

/// A cursor over a byte slice that rejects anything non-canonical.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(DecodeError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        Ok(self.bytes(N)?.try_into().expect("length checked"))
    }

    pub fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    pub fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value: u64 = 0;
        for i in 0..10 {
            let byte = self.u8()?;
            let bits = u64::from(byte & 0x7f);
            if i == 9 && bits > 1 {
                return Err(DecodeError::VarintOverflow);
            }
            value |= bits << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && bits == 0 {
                    return Err(DecodeError::NonMinimalVarint);
                }
                return Ok(value);
            }
        }
        Err(DecodeError::VarintOverflow)
    }

    /// Reads a varint length and then that many bytes.
    pub fn len_prefixed(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.varint()?;
        if len > self.remaining() as u64 {
            return Err(DecodeError::Truncated);
        }
        self.bytes(len as usize)
    }

    pub fn rest(&mut self) -> &'a [u8] {
        let out = &self.buf[self.pos..];
        self.pos = self.buf.len();
        out
    }

    pub fn finish(&self) -> Result<(), DecodeError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::TrailingBytes)
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn varint_known_values() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (300, &[0xac, 0x02]),
            (
                u64::MAX,
                &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01],
            ),
        ];
        for (v, enc) in cases {
            let mut out = Vec::new();
            put_varint(&mut out, *v);
            assert_eq!(&out, enc);
            assert_eq!(varint_len(*v), enc.len());
            assert_eq!(Reader::new(enc).varint(), Ok(*v));
        }
    }

    #[test]
    fn varint_rejects_non_canonical() {
        assert_eq!(
            Reader::new(&[0x80, 0x00]).varint(),
            Err(DecodeError::NonMinimalVarint)
        );
        assert_eq!(
            Reader::new(&[0x81, 0x80, 0x00]).varint(),
            Err(DecodeError::NonMinimalVarint)
        );
        assert_eq!(Reader::new(&[0x80]).varint(), Err(DecodeError::Truncated));
        let overflow = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(
            Reader::new(&overflow).varint(),
            Err(DecodeError::VarintOverflow)
        );
        let eleven = [0xff; 11];
        assert!(Reader::new(&eleven).varint().is_err());
    }

    proptest! {
        #[test]
        fn varint_roundtrip(v: u64) {
            let mut out = Vec::new();
            put_varint(&mut out, v);
            let mut r = Reader::new(&out);
            prop_assert_eq!(r.varint(), Ok(v));
            prop_assert!(r.finish().is_ok());
        }

        #[test]
        fn varint_decode_is_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..12)) {
            // Anything that decodes must re-encode to exactly the bytes consumed.
            let mut r = Reader::new(&bytes);
            if let Ok(v) = r.varint() {
                let mut out = Vec::new();
                put_varint(&mut out, v);
                prop_assert_eq!(&out[..], &bytes[..r.position()]);
            }
        }
    }
}
