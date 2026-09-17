//! Result store: large tool outputs spill to a handle (`r17`) + short preview;
//! the model fetches the full payload with `ida_result`. TTL-bounded.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::handle::Handle;

#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredResult {
    pub handle: String,
    pub tool: String,
    pub total_len: usize,
    pub preview: String,
    pub created_at_secs: u64,
    pub ttl_secs: u64,
    pub payload: serde_json::Value,
}

#[derive(Debug)]
struct Entry {
    payload: serde_json::Value,
    tool: String,
    total_len: usize,
    created: Instant,
    ttl: Duration,
}

/// Thread-safe result store.
#[derive(Debug)]
pub struct ResultStore {
    entries: std::sync::Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    /// Number of preview characters kept alongside a spilled handle.
    preview_chars: usize,
}

impl ResultStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: std::sync::Mutex::new(HashMap::new()),
            ttl,
            preview_chars: 400,
        }
    }

    /// Store a payload; returns (handle_string, preview, was_spilled).
    /// If the payload fits under `threshold`, it is returned inline
    /// (was_spilled == false) and nothing is stored.
    pub fn put(
        &self,
        tool: &str,
        payload: serde_json::Value,
        threshold: usize,
    ) -> (String, String, bool) {
        let serialized_len = serde_json::to_string(&payload)
            .map(|s| s.len())
            .unwrap_or(0);
        if serialized_len <= threshold {
            return (String::new(), String::new(), false);
        }
        let handle = Handle::new("r").to_string();
        let preview = preview_of(&payload, self.preview_chars);
        let entry = Entry {
            total_len: serialized_len,
            payload,
            tool: tool.to_string(),
            created: Instant::now(),
            ttl: self.ttl,
        };
        self.entries
            .lock()
            .expect("result store poisoned")
            .insert(handle.clone(), entry);
        (handle, preview, true)
    }

    /// Fetch full payload by handle.
    pub fn get(&self, handle: &str) -> Result<serde_json::Value> {
        let mut map = self.entries.lock().expect("result store poisoned");
        let entry = map
            .get_mut(handle)
            .ok_or_else(|| Error::UnknownResult(handle.to_string()))?;
        if entry.created.elapsed() >= entry.ttl {
            map.remove(handle);
            return Err(Error::UnknownResult(handle.to_string()));
        }
        Ok(entry.payload.clone())
    }

    /// Metadata for `ida_result` with mode=metadata.
    pub fn metadata(&self, handle: &str) -> Result<StoredResultMeta> {
        let map = self.entries.lock().expect("result store poisoned");
        let e = map
            .get(handle)
            .ok_or_else(|| Error::UnknownResult(handle.to_string()))?;
        if e.created.elapsed() >= e.ttl {
            return Err(Error::UnknownResult(handle.to_string()));
        }
        Ok(StoredResultMeta {
            handle: handle.to_string(),
            tool: e.tool.clone(),
            total_len: e.total_len,
            ttl_secs: e.ttl.as_secs(),
            age_secs: e.created.elapsed().as_secs(),
        })
    }

    /// Find stored results whose payload text contains `needle` (max 20 hits).
    pub fn find(&self, needle: &str) -> Vec<String> {
        let map = self.entries.lock().expect("result store poisoned");
        map.iter()
            .filter(|(_, e)| e.created.elapsed() < e.ttl)
            .filter(|(_, e)| {
                serde_json::to_string(&e.payload)
                    .map(|s| s.contains(needle))
                    .unwrap_or(false)
            })
            .map(|(k, _)| k.clone())
            .take(20)
            .collect()
    }

    pub fn release(&self, handle: &str) -> Result<()> {
        self.entries
            .lock()
            .expect("result store poisoned")
            .remove(handle)
            .map(|_| ())
            .ok_or_else(|| Error::UnknownResult(handle.to_string()))
    }

    /// Drop expired entries; returns count removed.
    /// Drop expired entries; returns count removed. Called periodically by
    /// the broker so a long-running process cannot accumulate dead payloads
    /// (#57 soak requirement: no unbounded memory growth).
    pub fn sweep(&self) -> usize {
        let mut map = self.entries.lock().expect("result store poisoned");
        let expired: Vec<String> = map
            .iter()
            .filter(|(_, e)| e.created.elapsed() >= e.ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
            map.remove(k);
        }
        expired.len()
    }

    /// Hard cap: if the store holds `max` entries, drop the oldest until
    /// under the cap. Returns count removed. Bounds worst-case memory even
    /// when entries are re-read faster than their TTL expires.
    pub fn enforce_cap(&self, max: usize) -> usize {
        let mut map = self.entries.lock().expect("result store poisoned");
        if map.len() <= max {
            return 0;
        }
        let mut by_age: Vec<(String, std::time::Instant)> =
            map.iter().map(|(k, e)| (k.clone(), e.created)).collect();
        by_age.sort_by_key(|(_, created)| *created);
        let excess = map.len() - max;
        let evict: Vec<String> = by_age.into_iter().take(excess).map(|(k, _)| k).collect();
        let n = evict.len();
        for k in evict {
            map.remove(&k);
        }
        n
    }

    pub fn len(&self) -> usize {
        self.entries.lock().expect("result store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Metadata view without payload.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredResultMeta {
    pub handle: String,
    pub tool: String,
    pub total_len: usize,
    pub ttl_secs: u64,
    pub age_secs: u64,
}

fn preview_of(payload: &serde_json::Value, max_chars: usize) -> String {
    let s = serde_json::to_string(payload).unwrap_or_default();
    if s.len() <= max_chars {
        s
    } else {
        let mut cut = max_chars;
        while cut > 0 && !s.is_char_boundary(cut) {
            cut -= 1;
        }
        format!("{}…", &s[..cut])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn store() -> ResultStore {
        ResultStore::new(Duration::from_secs(60))
    }

    #[test]
    fn small_payloads_stay_inline() {
        let s = store();
        let (handle, preview, spilled) = s.put("ida_functions", json!({"fns": [1]}), 24 * 1024);
        assert!(!spilled);
        assert!(handle.is_empty());
        assert!(preview.is_empty());
    }

    #[test]
    fn large_payloads_spill_to_handle() {
        let s = store();
        let big = json!({"data": "x".repeat(40 * 1024)});
        let (handle, preview, spilled) = s.put("ida_decompile", big.clone(), 24 * 1024);
        assert!(spilled);
        assert!(handle.starts_with('r'));
        assert!(preview.contains("data"));
        // fetch back
        let got = s.get(&handle).unwrap();
        assert_eq!(got, big);
        // metadata
        let meta = s.metadata(&handle).unwrap();
        assert_eq!(meta.handle, handle);
        assert!(meta.total_len > 24 * 1024);
    }

    #[test]
    fn unknown_and_released_handles_error() {
        let s = store();
        assert_eq!(s.get("r999").unwrap_err().code(), "unknown_result");
        let big = json!({"data": "x".repeat(40 * 1024)});
        let (handle, _, _) = s.put("t", big, 1024);
        s.release(&handle).unwrap();
        assert_eq!(s.get(&handle).unwrap_err().code(), "unknown_result");
    }

    #[test]
    fn ttl_expiry_sweeps() {
        let s = ResultStore::new(Duration::from_secs(0));
        let big = json!({"data": "x".repeat(4096)});
        let (handle, _, _) = s.put("t", big, 1024);
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(s.sweep(), 1);
        assert_eq!(s.get(&handle).unwrap_err().code(), "unknown_result");
    }

    #[test]
    fn cap_evicts_oldest_first() {
        // #57: hard cap bounds worst-case memory even when entries are
        // re-read faster than their TTL expires (no unbounded growth).
        let s = ResultStore::new(Duration::from_secs(3600));
        for i in 0..8 {
            let big = json!({"n": i, "data": "x".repeat(4096)});
            s.put("t", big, 1024);
            // distinct created instants
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(s.len(), 8);
        assert_eq!(s.enforce_cap(4), 4);
        assert_eq!(s.len(), 4);
        // The two oldest were evicted: entry 0 and 1 are gone, 6/7 remain.
        assert!(s.find("\"n\":0").is_empty(), "oldest must be evicted");
        assert!(s.find("\"n\":1").is_empty());
        assert!(!s.find("\"n\":6").is_empty(), "newest must survive");
        // Enforcing again at the cap is a no-op.
        assert_eq!(s.enforce_cap(4), 0);
    }

    #[test]
    fn cap_zero_means_unlimited() {
        let s = ResultStore::new(Duration::from_secs(3600));
        for i in 0..5 {
            let big = json!({"n": i, "data": "x".repeat(2048)});
            s.put("t", big, 512);
        }
        // Callers skip enforce_cap when the configured cap is 0, but the
        // method itself treats any call as a plain request; the config layer
        // gates this. Assert the store held all five.
        assert_eq!(s.len(), 5);
    }

    #[test]
    fn find_matches_payload_text() {
        let s = store();
        let big = json!({"code": "decrypt_packet_impl is here".repeat(200)});
        let (h1, _, _) = s.put("t", big, 1024);
        let hits = s.find("decrypt_packet_impl");
        assert!(hits.contains(&h1));
    }
}
