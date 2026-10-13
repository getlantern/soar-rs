/// The half-open interval `[lo, hi)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub lo: u64,
    pub hi: u64,
}

/// A sorted set of disjoint, non-adjacent spans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet(pub Vec<Span>);

impl RangeSet {
    pub fn add(&mut self, mut lo: u64, mut hi: u64) {
        if lo >= hi {
            return;
        }
        let rs = &mut self.0;
        // The first span that could touch [lo, hi).
        let i = rs.iter().position(|r| r.hi >= lo).unwrap_or(rs.len());
        let mut j = i;
        while j < rs.len() && rs[j].lo <= hi {
            lo = lo.min(rs[j].lo);
            hi = hi.max(rs[j].hi);
            j += 1;
        }
        rs.splice(i..j, [Span { lo, hi }]);
    }

    pub fn remove(&mut self, lo: u64, hi: u64) {
        if lo >= hi {
            return;
        }
        let mut out = Vec::with_capacity(self.0.len() + 1);
        for &r in &self.0 {
            if r.hi <= lo || r.lo >= hi {
                out.push(r);
                continue;
            }
            if r.lo < lo {
                out.push(Span { lo: r.lo, hi: lo });
            }
            if r.hi > hi {
                out.push(Span { lo: hi, hi: r.hi });
            }
        }
        self.0 = out;
    }

    pub fn contains(&self, v: u64) -> bool {
        self.0.iter().take_while(|r| v >= r.lo).any(|r| v < r.hi)
    }

    /// The end of the span containing v, or v if none does.
    pub fn covered_from(&self, v: u64) -> u64 {
        self.0
            .iter()
            .find(|r| r.lo <= v && v < r.hi)
            .map_or(v, |r| r.hi)
    }

    /// Drops everything below v.
    pub fn trim_below(&mut self, v: u64) {
        if v > 0 {
            self.remove(0, v);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_remove_contains() {
        let mut s = RangeSet::default();
        s.add(5, 10);
        s.add(0, 3);
        s.add(3, 5);
        assert_eq!(s.0, [Span { lo: 0, hi: 10 }]);
        s.add(20, 30);
        s.remove(2, 25);
        assert_eq!(s.0, [Span { lo: 0, hi: 2 }, Span { lo: 25, hi: 30 }]);
        assert!(s.contains(1) && !s.contains(2) && s.contains(29));
        assert_eq!(s.covered_from(0), 2);
    }
}
