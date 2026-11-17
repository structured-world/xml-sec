//! Caller-supplied UTC history read from the IERS/IANA `leap-seconds.list`
//! format, the [`LeapTable`] CRL checking needs. Reading authenticates no
//! source: the caller decides which list it trusts.

use alloc::sync::Arc;

use structured_asn1::memory::{Memory, MemoryAccount, OwnedVec};
use structured_pkix::temporal::{LeapTable, Transition};

use crate::policy::ResourcePolicy;

/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const NTP_UNIX_OFFSET: i64 = 2_208_988_800;

/// Why a `leap-seconds.list` was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum LeapSecondsError {
    /// The list is longer than the policy's per-resource byte limit.
    #[error("the leap-seconds list exceeds {maximum} bytes")]
    TooLarge {
        /// The policy's `max_external_resource_bytes`.
        maximum: usize,
    },
    /// The list is not a complete `leap-seconds.list` with an expiration.
    #[error("invalid leap-seconds list")]
    Malformed,
    /// Reading it exceeds the policy's X.509 workspace or work limit.
    #[error("the leap-seconds list exceeds the X.509 resource limits")]
    ResourceLimit,
}

/// UTC history covering the interval from a `leap-seconds.list`'s first
/// entry to its expiration, owned so it can be held across operations.
#[derive(Debug)]
pub struct LeapSecondsList {
    start: i64,
    end: i64,
    changes: OwnedVec<Transition>,
}

impl LeapSecondsList {
    /// Reads `input` in the published `leap-seconds.list` format: lines of
    /// NTP seconds and the absolute TAI-UTC offset, and one `#@` line with
    /// the list's expiration, beyond which it predicts nothing.
    ///
    /// The input is bounded by `resources.max_external_resource_bytes`;
    /// parsing and the retained transitions are charged to an account of
    /// `max_x509_workspace_bytes` and `max_x509_work`.
    ///
    /// # Errors
    ///
    /// [`LeapSecondsError`] when the list is too large, malformed (no
    /// expiration, repeated dates, a correction that is not one second) or
    /// exceeds the resource limits.
    ///
    /// # Examples
    ///
    /// ```
    /// use xml_sec::policy::ResourcePolicy;
    /// use xml_sec::xmldsig::LeapSecondsList;
    ///
    /// let list = b"#@ 2303683201\n2272060800 10\n2287785600 11\n";
    /// let facts = LeapSecondsList::parse(list, &ResourcePolicy::default())?;
    /// assert_eq!(facts.table().transitions().len(), 1);
    /// # Ok::<(), xml_sec::xmldsig::LeapSecondsError>(())
    /// ```
    pub fn parse(input: &[u8], resources: &ResourcePolicy) -> Result<Self, LeapSecondsError> {
        if input.len() > resources.max_external_resource_bytes {
            return Err(LeapSecondsError::TooLarge {
                maximum: resources.max_external_resource_bytes,
            });
        }
        let memory = Memory::new(Arc::new(MemoryAccount::new(
            resources.max_x509_workspace_bytes,
            resources.max_x509_work,
        )));
        let charge = (input.len() as u64)
            .checked_mul(8)
            .ok_or(LeapSecondsError::Malformed)?;
        memory
            .charge_work(charge)
            .map_err(|_| LeapSecondsError::ResourceLimit)?;
        let text = core::str::from_utf8(input).map_err(|_| LeapSecondsError::Malformed)?;
        let mut start = None;
        let mut end = None;
        let mut baseline = 0i32;
        let mut changes = memory.vector();
        for line in text.lines() {
            let line = line.trim();
            if let Some(expiration) = line.strip_prefix("#@") {
                if end.is_some() {
                    return Err(LeapSecondsError::Malformed);
                }
                let mut fields = expiration.split_whitespace();
                end = Some(ntp(fields.next())?);
                if fields.next().is_some() {
                    return Err(LeapSecondsError::Malformed);
                }
                continue;
            }
            let data = line.split_once('#').map_or(line, |(data, _)| data);
            let mut fields = data.split_whitespace();
            let Some(time) = fields.next() else { continue };
            let at = ntp(Some(time))?;
            let offset: i32 = fields
                .next()
                .ok_or(LeapSecondsError::Malformed)?
                .parse()
                .map_err(|_| LeapSecondsError::Malformed)?;
            if fields.next().is_some() {
                return Err(LeapSecondsError::Malformed);
            }
            if start.is_none() {
                // The first offset is the baseline, not a correction.
                start = Some(at);
                baseline = offset;
            } else {
                let correction = offset
                    .checked_sub(baseline)
                    .ok_or(LeapSecondsError::Malformed)?;
                changes
                    .try_push(Transition::new(at, correction))
                    .map_err(|_| LeapSecondsError::ResourceLimit)?;
            }
        }
        let list = Self {
            start: start.ok_or(LeapSecondsError::Malformed)?,
            end: end.ok_or(LeapSecondsError::Malformed)?,
            changes,
        };
        LeapTable::new(list.start, list.end, &list.changes)
            .map_err(|_| LeapSecondsError::Malformed)?;
        Ok(list)
    }

    /// The table [`X509ChainOptions::utc_facts`](super::X509ChainOptions)
    /// and `VerifyContext::utc_facts` take.
    ///
    /// # Panics
    ///
    /// Never: [`parse`](Self::parse) admits only a list whose table is valid.
    #[must_use]
    pub fn table(&self) -> LeapTable<'_> {
        LeapTable::new(self.start, self.end, &self.changes)
            .expect("the table was validated when the list was read")
    }
}

/// Unix seconds of the NTP seconds `value`, plain decimal digits only.
fn ntp(value: Option<&str>) -> Result<i64, LeapSecondsError> {
    let value = value.ok_or(LeapSecondsError::Malformed)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LeapSecondsError::Malformed);
    }
    value
        .parse::<i64>()
        .map_err(|_| LeapSecondsError::Malformed)?
        .checked_sub(NTP_UNIX_OFFSET)
        .ok_or(LeapSecondsError::Malformed)
}

#[cfg(test)]
mod tests;
