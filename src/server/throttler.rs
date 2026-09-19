use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AuthThrottler {
    inner: Arc<Mutex<HashMap<IpAddr, AuthFailureState>>>,
    max_failures: u32,
    lockout_duration: Duration,
    window_duration: Duration,
}

struct AuthFailureState {
    count: u32,
    first_failure_at: Instant,
    locked_until: Option<Instant>,
}

impl Default for AuthThrottler {
    fn default() -> Self {
        // Default: 5 failures within 60 seconds triggers a 60 second lockout
        Self::new(5, Duration::from_secs(60), Duration::from_secs(60))
    }
}

impl AuthThrottler {
    pub fn new(max_failures: u32, lockout_duration: Duration, window_duration: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            max_failures,
            lockout_duration,
            window_duration,
        }
    }

    /// Check if an IP is locked out. If locked out, returns the remaining duration.
    pub fn check_lockout(&self, ip: &IpAddr) -> Option<Duration> {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Prevent memory exhaustion by periodically pruning stale entries
        if map.len() > 1000 {
            map.retain(|_, state| {
                if let Some(locked_until) = state.locked_until {
                    locked_until > now
                } else {
                    now.duration_since(state.first_failure_at) < self.window_duration
                }
            });
        }

        if let Some(state) = map.get_mut(ip)
            && let Some(locked_until) = state.locked_until
        {
            if now < locked_until {
                return Some(locked_until - now);
            } else {
                // Lockout has expired, reset state
                map.remove(ip);
                return None;
            }
        }
        None
    }

    /// Record an authentication failure. Returns true if this failure caused the IP to be locked out.
    pub fn record_failure(&self, ip: IpAddr) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        let state = map.entry(ip).or_insert(AuthFailureState {
            count: 0,
            first_failure_at: now,
            locked_until: None,
        });

        if now.duration_since(state.first_failure_at) > self.window_duration {
            state.count = 1;
            state.first_failure_at = now;
            state.locked_until = None;
            false
        } else {
            state.count += 1;
            if state.count >= self.max_failures {
                state.locked_until = Some(now + self.lockout_duration);
                true
            } else {
                false
            }
        }
    }

    /// Reset failure count on successful authentication
    pub fn record_success(&self, ip: &IpAddr) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.remove(ip);
    }
}
