//! The simulation's single source of randomness.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};

pub struct Rng(ChaCha20Rng);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(ChaCha20Rng::seed_from_u64(seed))
    }

    pub fn chance(&mut self, p: f64) -> bool {
        let unit = (self.0.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
        p > 0.0 && unit < p
    }

    /// Uniform in `lo..hi`. Returns `lo` if the range is empty.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            lo
        } else {
            lo + self.0.next_u64() % (hi - lo)
        }
    }

    pub fn index(&mut self, len: usize) -> usize {
        self.range(0, len as u64) as usize
    }

    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T> {
        if items.is_empty() {
            None
        } else {
            Some(&items[self.index(items.len())])
        }
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut v = vec![0; n];
        self.0.fill_bytes(&mut v);
        v
    }

    pub fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut a = [0; N];
        self.0.fill_bytes(&mut a);
        a
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            items.swap(i, self.index(i + 1));
        }
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for Rng {}
