//! The relying party's clock: the one place webauthn-rs-core reads the
//! current time, for an attestation certificate chain's validity window.
//!
//! `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`, which
//! has no clock of its own (kanidm/webauthn-rs issue 447). There the time is
//! read from JavaScript's `Date.now()`, the clock a Cloudflare Worker or a
//! browser gives. A reading that is not a number of milliseconds since the
//! epoch, or that falls before [`EARLIEST`], is refused with
//! [`WebauthnError::ClockUnavailable`] rather than read as 1970, so a broken
//! clock fails the ceremony instead of verifying certificates against the
//! wrong day.
//!
//! An interim for kanidm/webauthn-rs PR 607, which moves this to
//! `crypto_glue::time` once kanidm/crypto-glue PR 48 is released.

use crate::error::{WebauthnError, WebauthnResult};
use std::time::{SystemTime, UNIX_EPOCH};

/// The earliest time accepted: 2025-01-01T00:00:00Z, in seconds since the
/// epoch. This release was made after it, so any earlier reading is a clock
/// that is unset or broken.
const EARLIEST: u64 = 1_735_689_600;

/// The largest number of milliseconds `Date.now()` can return exactly:
/// JavaScript's `Number.MAX_SAFE_INTEGER`, 2^53 - 1.
#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
const MAX_SAFE_MILLIS: f64 = 9_007_199_254_740_991.0;

/// The current time, or [`WebauthnError::ClockUnavailable`].
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn now() -> WebauthnResult<SystemTime> {
    after_earliest(SystemTime::now())
}

/// The current time from `Date.now()`, or
/// [`WebauthnError::ClockUnavailable`].
#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn now() -> WebauthnResult<SystemTime> {
    after_earliest(from_unix_millis(js_sys::Date::now())?)
}

/// A `Date.now()` reading as a time: a whole, finite, non-negative number
/// of milliseconds no larger than JavaScript represents exactly.
#[cfg(any(test, all(target_arch = "wasm32", target_os = "unknown")))]
fn from_unix_millis(millis: f64) -> WebauthnResult<SystemTime> {
    if !millis.is_finite() || !(0.0..=MAX_SAFE_MILLIS).contains(&millis) {
        return Err(WebauthnError::ClockUnavailable);
    }
    // In range, so the cast neither wraps nor saturates; any fraction of a
    // millisecond is dropped.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let whole = millis as u64;
    UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(whole))
        .ok_or(WebauthnError::ClockUnavailable)
}

/// `time`, unless it falls before [`EARLIEST`].
fn after_earliest(time: SystemTime) -> WebauthnResult<SystemTime> {
    match time.duration_since(UNIX_EPOCH) {
        Ok(since) if since.as_secs() >= EARLIEST => Ok(time),
        _ => Err(WebauthnError::ClockUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    use wasm_bindgen_test::wasm_bindgen_test as test;

    #[test]
    fn now_reads_a_time_after_the_earliest() {
        let now = now().expect("the clock reads");
        let since = now.duration_since(UNIX_EPOCH).expect("after the epoch");
        assert!(since.as_secs() >= EARLIEST);
    }

    #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
    #[test]
    fn now_is_date_now() {
        let before = js_sys::Date::now();
        let now = now().expect("the clock reads");
        let after = js_sys::Date::now();
        let millis = now
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_millis() as f64;
        assert!(
            before.floor() <= millis && millis <= after,
            "{before} {millis} {after}"
        );
    }

    #[test]
    fn a_reading_of_1970_is_refused_not_used() {
        assert_eq!(
            from_unix_millis(0.0).and_then(after_earliest),
            Err(WebauthnError::ClockUnavailable)
        );
        assert_eq!(
            after_earliest(UNIX_EPOCH),
            Err(WebauthnError::ClockUnavailable)
        );
        let just_before = UNIX_EPOCH + Duration::from_secs(EARLIEST - 1);
        assert_eq!(
            after_earliest(just_before),
            Err(WebauthnError::ClockUnavailable)
        );
    }

    #[test]
    fn a_reading_that_is_not_a_time_is_refused() {
        for millis in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -1.0, 1.0e300] {
            assert_eq!(
                from_unix_millis(millis),
                Err(WebauthnError::ClockUnavailable),
                "{millis}"
            );
        }
    }

    #[test]
    fn a_reading_in_range_is_that_many_milliseconds() {
        let earliest = UNIX_EPOCH + Duration::from_secs(EARLIEST);
        assert_eq!(
            from_unix_millis(EARLIEST as f64 * 1000.0).and_then(after_earliest),
            Ok(earliest)
        );
        assert_eq!(
            from_unix_millis(EARLIEST as f64 * 1000.0 + 1.75),
            Ok(earliest + Duration::from_millis(1))
        );
        // 2100-01-01T00:00:00Z, inside every platform's SystemTime.
        assert_eq!(
            from_unix_millis(4_102_444_800_000.0),
            Ok(UNIX_EPOCH + Duration::from_secs(4_102_444_800))
        );
        // The largest reading is taken where SystemTime can hold it and
        // refused where it cannot (Windows stops near the year 30828), and
        // never panics.
        match from_unix_millis(MAX_SAFE_MILLIS) {
            Ok(time) => assert!(time > earliest),
            Err(e) => assert_eq!(e, WebauthnError::ClockUnavailable),
        }
    }
}
