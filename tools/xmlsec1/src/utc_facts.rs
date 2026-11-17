//! Explicit caller-supplied UTC facts. Loading authenticates no source.

use std::{fs::File, io::Read, path::PathBuf};

use xml_sec::policy::ResourcePolicy;
use xml_sec::xmldsig::{LeapSecondsError, LeapSecondsList};

use crate::{
    Invocation,
    commands::{CommandError, ExternalMaterialBudget},
};

/// The `--utc-facts` file, read by the core's `leap-seconds.list` reader.
pub(super) struct UtcFacts(LeapSecondsList);

fn refused(error: LeapSecondsError) -> CommandError {
    match error {
        LeapSecondsError::TooLarge { maximum } => {
            CommandError::ExternalMaterialTooLarge { maximum }
        }
        LeapSecondsError::ResourceLimit => CommandError::Usage("--utc-facts resource limit".into()),
        _ => CommandError::Usage("invalid --utc-facts leap-seconds.list".into()),
    }
}

impl UtcFacts {
    pub(super) fn load(
        invocation: &Invocation,
        limits: &ResourcePolicy,
        budget: &mut ExternalMaterialBudget,
    ) -> Result<Option<Self>, CommandError> {
        let Some(path) = invocation.last_value("utc-facts") else {
            return Ok(None);
        };
        let mut input = Vec::new();
        let mut file = File::open(path).map_err(|source| CommandError::Io {
            path: PathBuf::from(path),
            source,
        })?;
        let mut buffer = [0; 4096];
        loop {
            let remaining =
                (limits.max_external_resource_bytes - input.len()).min(budget.remaining());
            // Probe one extra byte on the stack to detect a growing/nonregular
            // file. No unadmitted bytes are retained in the heap buffer.
            let probe = if remaining < buffer.len() {
                remaining + 1
            } else {
                buffer.len()
            };
            let count = file
                .read(&mut buffer[..probe])
                .map_err(|source| CommandError::Io {
                    path: PathBuf::from(path),
                    source,
                })?;
            if count == 0 {
                break;
            }
            if count > remaining {
                return Err(CommandError::ExternalMaterialTooLarge {
                    maximum: limits.max_external_resource_bytes.min(budget.maximum()),
                });
            }
            budget.charge(count)?;
            input.extend_from_slice(&buffer[..count]);
        }
        LeapSecondsList::parse(&input, limits)
            .map(|list| Some(Self(list)))
            .map_err(refused)
    }

    pub(super) fn table(&self) -> structured_pkix::temporal::LeapTable<'_> {
        self.0.table()
    }
}

#[cfg(test)]
mod tests;
