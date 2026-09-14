//! Short handles for model-visible identifiers: `db1`, `r17`, …
//! Small integers only — no UUIDs ever reach the model.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Opaque numeric handle with a kind prefix (`db`, `r`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Handle {
    prefix: &'static str,
    n: u64,
}

impl Handle {
    pub fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            n: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    /// Rebuild from a string (e.g. parsed from a tool call).
    pub fn parse(s: &str, expected_prefix: &str) -> Option<Self> {
        let rest = s.strip_prefix(expected_prefix)?;
        if rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u64 = rest.parse().ok()?;
        // Leading zeros are not canonical but harmless; accept them.
        Some(Self {
            prefix: expected_prefix_leak(expected_prefix),
            n,
        })
    }

    pub fn n(&self) -> u64 {
        self.n
    }
}

fn expected_prefix_leak(p: &str) -> &'static str {
    match p {
        "db" => "db",
        "r" => "r",
        _ => "x",
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.prefix, self.n)
    }
}

/// Allocates db handles in order of open; `db1` is the first.
#[derive(Debug, Default)]
pub struct HandleAllocator {
    next: u64,
}

impl HandleAllocator {
    pub fn new() -> Self {
        Self { next: 1 }
    }

    pub fn alloc_db(&mut self) -> Handle {
        let h = Handle {
            prefix: "db",
            n: self.next,
        };
        self.next += 1;
        h
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_sequential() {
        let mut a = HandleAllocator::new();
        assert_eq!(a.alloc_db().to_string(), "db1");
        assert_eq!(a.alloc_db().to_string(), "db2");
        assert_eq!(a.alloc_db().to_string(), "db3");
    }

    #[test]
    fn parse_roundtrip() {
        let h = Handle::parse("db17", "db").unwrap();
        assert_eq!(h.n(), 17);
        assert_eq!(h.to_string(), "db17");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(Handle::parse("db", "db").is_none());
        assert!(Handle::parse("dbx1", "db").is_none());
        assert!(Handle::parse("r12", "db").is_none());
        assert!(Handle::parse("db-1", "db").is_none());
    }
}
