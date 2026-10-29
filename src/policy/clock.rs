//! Operation time. Only `std` builds read the host clock; without it the
//! caller's verification time is the only time an operation knows.

pub use structured_pkix::temporal::Instant;

use super::PolicyViolation;

/// Converts a host clock reading to the label policy and path validation use.
///
/// Returns `None` outside the range of whole `i64` seconds around the epoch.
#[cfg(any(feature = "std", test))]
#[must_use]
pub fn instant_from_system_time(time: std::time::SystemTime) -> Option<Instant> {
    let nanos = match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).ok()?,
        Err(error) => -i128::try_from(error.duration().as_nanos()).ok()?,
    };
    let seconds = i64::try_from(nanos.div_euclid(1_000_000_000)).ok()?;
    let fraction = u32::try_from(nanos.rem_euclid(1_000_000_000)).ok()?;
    Instant::new(seconds, fraction)
}

/// The host clock, or `None` without `std` or outside the representable range.
pub(crate) fn host_now() -> Option<Instant> {
    #[cfg(feature = "std")]
    return instant_from_system_time(std::time::SystemTime::now());
    #[cfg(not(feature = "std"))]
    return None;
}

/// The time at which an operation checks authorization windows: the host
/// clock with `std`; otherwise the caller's verification time.
#[cfg(feature = "std")]
pub(crate) fn authorization_time(_caller: Option<Instant>) -> Result<Instant, PolicyViolation> {
    host_now().ok_or(PolicyViolation::Configuration {
        reason: "host clock is outside the representable time range",
    })
}

/// The time at which an operation checks authorization windows: the host
/// clock with `std`; otherwise the caller's verification time.
#[cfg(not(feature = "std"))]
pub(crate) fn authorization_time(caller: Option<Instant>) -> Result<Instant, PolicyViolation> {
    caller.ok_or(PolicyViolation::Configuration {
        reason: "without a host clock an authorized exception requires the caller's verification time",
    })
}
