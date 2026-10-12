//! When to bring a dropped session back: what a session end means for the
//! window, and how long to wait between attempts.

use std::time::Duration;

const FIRST_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(30);

/// Doubling delay between reconnect attempts, capped at [`MAX_DELAY`].
#[derive(Debug)]
pub struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Backoff { next: FIRST_DELAY }
    }
}

impl Backoff {
    /// Delay before the next attempt.
    pub fn next_delay(&mut self) -> Duration {
        let d = self.next;
        self.next = (d * 2).min(MAX_DELAY);
        d
    }

    /// A session came up; the next drop starts again from the first delay.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// What the window does when a session ends.
#[derive(Debug, PartialEq, Eq)]
pub enum OnEnd {
    Exit,
    Retry(Duration),
}

/// Session lifecycle as the window sees it.
#[derive(Debug, Default)]
pub struct Reconnector {
    enabled: bool,
    /// A session reached `Connected` at least once. Until then failures are
    /// reported and end the program, as without reconnecting.
    connected_once: bool,
    reconnecting: bool,
    backoff: Backoff,
}

impl Reconnector {
    pub fn new(enabled: bool) -> Self {
        Reconnector { enabled, ..Default::default() }
    }

    pub fn reconnecting(&self) -> bool {
        self.reconnecting
    }

    /// The session finished its handshake. That alone doesn't prove the
    /// host is healthy (it may accept and then send nothing), so the
    /// backoff keeps growing until [`Self::video`].
    pub fn connected(&mut self) {
        self.connected_once = true;
        self.reconnecting = false;
    }

    /// A picture arrived: the session really works, so the next drop
    /// starts again from the first delay.
    pub fn video(&mut self) {
        self.backoff.reset();
    }

    /// The session ended; `retryable` is false for failures another attempt
    /// can't fix, such as rejected credentials.
    pub fn ended(&mut self, retryable: bool) -> OnEnd {
        if !(self.enabled && self.connected_once && retryable) {
            return OnEnd::Exit;
        }
        self.reconnecting = true;
        OnEnd::Retry(self.backoff.next_delay())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(s: u64) -> OnEnd {
        OnEnd::Retry(Duration::from_secs(s))
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::default();
        let got: Vec<u64> = (0..8).map(|_| b.next_delay().as_secs()).collect();
        assert_eq!(got, [1, 2, 4, 8, 16, 30, 30, 30]);
        b.reset();
        assert_eq!(b.next_delay(), FIRST_DELAY);
    }

    #[test]
    fn initial_failure_exits() {
        let mut r = Reconnector::new(true);
        assert_eq!(r.ended(true), OnEnd::Exit);
        assert!(!r.reconnecting());
    }

    #[test]
    fn drop_after_connect_retries_until_connected() {
        let mut r = Reconnector::new(true);
        r.connected();
        assert_eq!(r.ended(true), secs(1));
        assert!(r.reconnecting());
        // Failed attempts keep backing off.
        assert_eq!(r.ended(true), secs(2));
        assert_eq!(r.ended(true), secs(4));
        r.connected();
        r.video();
        assert!(!r.reconnecting());
        assert_eq!(r.ended(true), secs(1));
    }

    #[test]
    fn backoff_resets_only_after_video() {
        let mut r = Reconnector::new(true);
        r.connected();
        r.video();
        assert_eq!(r.ended(true), secs(1));
        // Handshakes that succeed but never deliver video keep backing off.
        r.connected();
        assert_eq!(r.ended(true), secs(2));
        r.connected();
        assert_eq!(r.ended(true), secs(4));
        r.connected();
        r.video();
        assert_eq!(r.ended(true), secs(1));
    }

    #[test]
    fn auth_rejection_exits_even_while_reconnecting() {
        let mut r = Reconnector::new(true);
        r.connected();
        assert_eq!(r.ended(true), secs(1));
        assert_eq!(r.ended(false), OnEnd::Exit);
    }

    #[test]
    fn disabled_never_retries() {
        let mut r = Reconnector::new(false);
        r.connected();
        assert_eq!(r.ended(true), OnEnd::Exit);
    }
}
