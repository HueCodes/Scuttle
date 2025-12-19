//! Rate limiting for network scans.
//!
//! Provides token bucket rate limiting to control the pace of scanning
//! and prevent network flooding.

use governor::{Quota, RateLimiter as GovLimiter};
use std::num::NonZeroU32;
use std::sync::Arc;

/// A rate limiter for controlling scan speed.
///
/// Uses a token bucket algorithm to enforce a maximum packets-per-second limit.
/// This is important for:
/// - Avoiding network congestion
/// - Evading intrusion detection systems
/// - Being a good network citizen
pub struct RateLimiter {
    limiter: Arc<GovLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>,
}

impl RateLimiter {
    /// Create a new rate limiter with the specified packets-per-second limit.
    ///
    /// # Arguments
    /// * `rate` - Maximum number of operations per second
    ///
    /// # Panics
    /// Panics if rate is 0. Use Option<RateLimiter> for optional rate limiting.
    pub fn new(rate: u32) -> Self {
        let rate = NonZeroU32::new(rate).expect("rate must be > 0");
        let quota = Quota::per_second(rate);
        let limiter = GovLimiter::direct(quota);

        Self {
            limiter: Arc::new(limiter),
        }
    }

    /// Wait until a token is available.
    ///
    /// This method blocks (async) until the rate limit allows another operation.
    pub async fn wait(&self) {
        // Wait until we can proceed
        self.limiter.until_ready().await;
    }

    /// Try to acquire a token without waiting.
    ///
    /// Returns `true` if a token was available, `false` otherwise.
    pub fn try_acquire(&self) -> bool {
        self.limiter.check().is_ok()
    }

    /// Create a rate limiter with burst capacity.
    ///
    /// Allows a burst of operations up to `burst` before rate limiting kicks in.
    pub fn with_burst(rate: u32, burst: u32) -> Self {
        let rate = NonZeroU32::new(rate).expect("rate must be > 0");
        let burst = NonZeroU32::new(burst).expect("burst must be > 0");
        let quota = Quota::per_second(rate).allow_burst(burst);
        let limiter = GovLimiter::direct(quota);

        Self {
            limiter: Arc::new(limiter),
        }
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            limiter: Arc::clone(&self.limiter),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(100);
        // Should be able to acquire immediately
        assert!(limiter.try_acquire());
    }

    #[tokio::test]
    async fn test_rate_limiter_wait() {
        let limiter = RateLimiter::new(1000);
        // Wait should complete quickly with high rate
        limiter.wait().await;
    }

    #[test]
    fn test_rate_limiter_clone() {
        let limiter1 = RateLimiter::new(100);
        let limiter2 = limiter1.clone();

        // Both should share the same internal state
        assert!(limiter1.try_acquire());
        // The second try might fail because they share state
        // (depends on timing, so we just verify it doesn't panic)
        let _ = limiter2.try_acquire();
    }
}
