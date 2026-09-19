use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Per-IP Token-Bucket Request Rate Limiter to protect against bot DDoS floods and CPU exhaustion
#[derive(Clone)]
pub struct RequestRateLimiter {
    inner: Arc<Mutex<HashMap<IpAddr, TokenBucket>>>,
    burst_capacity: f64,
    refill_rate_per_sec: f64,
    enabled: bool,
}

struct TokenBucket {
    tokens: f64,
    last_update: Instant,
}

impl Default for RequestRateLimiter {
    fn default() -> Self {
        // Default: 120 requests per minute (2.0 req/sec) with a burst capacity of 30 requests.
        // Can be customized via environment variables:
        // AGENTGATE_RATE_LIMIT_RPM (requests per minute, 0 = disabled)
        // AGENTGATE_RATE_LIMIT_BURST (maximum burst capacity)
        let rpm: f64 = std::env::var("AGENTGATE_RATE_LIMIT_RPM")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(120.0);

        let burst: f64 = std::env::var("AGENTGATE_RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30.0);

        if rpm <= 0.0 {
            Self::disabled()
        } else {
            Self::new(burst, rpm / 60.0)
        }
    }
}

impl RequestRateLimiter {
    pub fn new(burst_capacity: f64, refill_rate_per_sec: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            burst_capacity,
            refill_rate_per_sec,
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            burst_capacity: 0.0,
            refill_rate_per_sec: 0.0,
            enabled: false,
        }
    }

    /// Check if a request from this IP is allowed.
    /// Returns Ok(()) if allowed, or Err(retry_after_secs) if rate limit is exceeded.
    pub fn check_rate_limit(&self, ip: &IpAddr) -> Result<(), u64> {
        if !self.enabled {
            return Ok(());
        }

        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Memory exhaustion defense: prune stale records when map grows large
        if map.len() > 2000 {
            let stale_threshold = Duration::from_secs(300); // 5 minutes
            map.retain(|_, bucket| now.duration_since(bucket.last_update) < stale_threshold);
        }

        let bucket = map.entry(*ip).or_insert(TokenBucket {
            tokens: self.burst_capacity,
            last_update: now,
        });

        // Calculate token refill since last request
        let elapsed = now.duration_since(bucket.last_update).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_rate_per_sec).min(self.burst_capacity);
        bucket.last_update = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let needed = 1.0 - bucket.tokens;
            let retry_after = (needed / self.refill_rate_per_sec).ceil() as u64;
            Err(retry_after.max(1))
        }
    }

    /// Reset rate limit for a specific IP (e.g. in test suites or admin actions)
    pub fn reset(&self, ip: &IpAddr) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(ip);
    }
}
