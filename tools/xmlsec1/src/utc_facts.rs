//! Explicit caller-supplied UTC facts. Loading authenticates no source.

use std::{fs::File, io::Read, path::PathBuf, sync::Arc};

use structured_asn1::memory::{Memory, MemoryAccount, MemoryError, OwnedVec};
use structured_pkix::temporal::{LeapTable, Transition};
use xml_sec::policy::ResourcePolicy;

use crate::{Invocation, commands::CommandError};

const NTP_UNIX_OFFSET: i64 = 2_208_988_800;

pub(super) struct UtcFacts {
    start: i64,
    end: i64,
    changes: OwnedVec<Transition>,
}

fn invalid() -> CommandError {
    CommandError::Usage("invalid --utc-facts leap-seconds.list".into())
}

fn resource(error: MemoryError) -> CommandError {
    CommandError::Usage(format!("--utc-facts resource limit: {error:?}"))
}

impl UtcFacts {
    pub(super) fn load(
        invocation: &Invocation,
        limits: &ResourcePolicy,
    ) -> Result<Option<Self>, CommandError> {
        let Some(path) = invocation.last_value("utc-facts") else {
            return Ok(None);
        };
        let memory = Memory::new(Arc::new(MemoryAccount::new(
            limits.max_x509_workspace_bytes,
            limits.max_x509_work,
        )));
        let mut input = memory.vector();
        let mut file = File::open(path).map_err(|source| CommandError::Io {
            path: PathBuf::from(path),
            source,
        })?;
        let mut buffer = [0; 4096];
        loop {
            let count = file.read(&mut buffer).map_err(|source| CommandError::Io {
                path: PathBuf::from(path),
                source,
            })?;
            if count == 0 {
                break;
            }
            memory.charge_work(count as u64).map_err(resource)?;
            input
                .try_extend_from_slice(&buffer[..count])
                .map_err(resource)?;
        }
        Self::parse(&input, &memory).map(Some)
    }

    fn parse(input: &[u8], memory: &Memory) -> Result<Self, CommandError> {
        // Published IERS/IANA format: NTP seconds and absolute TAI-UTC;
        // #@ is expiration, not a prediction beyond that instant.
        // https://data.iana.org/time-zones/tzdb/leap-seconds.list
        memory
            .charge_work((input.len() as u64).checked_mul(8).ok_or_else(invalid)?)
            .map_err(resource)?;
        let text = std::str::from_utf8(input).map_err(|_| invalid())?;
        let mut start = None;
        let mut end = None;
        let mut baseline = 0i32;
        let mut changes = memory.vector();
        for line in text.lines() {
            let line = line.trim();
            if let Some(expiration) = line.strip_prefix("#@") {
                if end.is_some() {
                    return Err(invalid());
                }
                let mut fields = expiration.split_whitespace();
                end = Some(ntp(fields.next())?);
                if fields.next().is_some() {
                    return Err(invalid());
                }
                continue;
            }
            let data = line
                .split('#')
                .next()
                .expect("split always has a first item");
            let mut fields = data.split_whitespace();
            let Some(time) = fields.next() else { continue };
            let at = ntp(Some(time))?;
            let offset: i32 = fields
                .next()
                .ok_or_else(invalid)?
                .parse()
                .map_err(|_| invalid())?;
            if fields.next().is_some() {
                return Err(invalid());
            }
            if start.is_none() {
                start = Some(at);
                baseline = offset;
            } else {
                let correction = offset.checked_sub(baseline).ok_or_else(invalid)?;
                changes
                    .try_push(Transition::new(at, correction))
                    .map_err(resource)?;
            }
        }
        let facts = Self {
            start: start.ok_or_else(invalid)?,
            end: end.ok_or_else(invalid)?,
            changes,
        };
        // Charges include table validation here and the borrowed view at use.
        facts.table()?;
        Ok(facts)
    }

    pub(super) fn table(&self) -> Result<LeapTable<'_>, CommandError> {
        LeapTable::new(self.start, self.end, &self.changes).map_err(|_| invalid())
    }
}

fn ntp(value: Option<&str>) -> Result<i64, CommandError> {
    let value = value.ok_or_else(invalid)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    value
        .parse::<i64>()
        .map_err(|_| invalid())?
        .checked_sub(NTP_UNIX_OFFSET)
        .ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory(bytes: usize, work: usize) -> Memory {
        Memory::new(Arc::new(MemoryAccount::new(bytes, work)))
    }

    #[test]
    fn corrections_are_relative_and_coverage_is_explicit() {
        // The first offset is a baseline, not a correction at coverage start.
        let facts = UtcFacts::parse(
            b"#@ 2303683201\n2272060800 10\n2287785600 11\n2303683200 10\n",
            &memory(4096, 4096),
        )
        .unwrap();
        assert_eq!(
            facts.table().unwrap().transitions(),
            &[
                Transition::new(78_796_800, 1),
                Transition::new(94_694_400, 0)
            ]
        );
    }

    #[test]
    fn malformed_or_incomplete_facts_never_become_a_default_table() {
        // Missing expiry, duplicate dates, non-unit corrections and invalid
        // numeric spellings must not silently claim a covered UTC interval.
        for input in [
            "2272060800 10\n",
            "#@ 2303683201\n#@ 2303683201\n2272060800 10\n",
            "#@ 2303683201\n2272060800 10\n2272060800 11\n",
            "#@ 2303683201\n2272060800 10\n2287785600 12\n",
            "#@ 2303683201\n+2272060800 10\n",
        ] {
            assert!(
                UtcFacts::parse(input.as_bytes(), &memory(4096, 4096)).is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn fact_loading_preserves_work_and_capacity_limits() {
        // Parsing and retained transitions must both be admitted before work.
        let input = b"#@ 2303683201\n2272060800 10\n2287785600 11\n";
        assert!(UtcFacts::parse(input, &memory(4096, 0)).is_err());
        assert!(UtcFacts::parse(input, &memory(0, 4096)).is_err());
    }
}
