use std::sync::Arc;

use time::OffsetDateTime;

use crate::{Resolver, Result};

/// Time source used by zero-argument EXSLT date functions during one execution.
pub trait Clock: Send + Sync {
    fn now_local(&self) -> Result<OffsetDateTime>;
}

/// Host local time, matching conventional EXSLT compatibility behavior.
///
/// On platforms where the process-local offset cannot be read soundly after threads start,
/// compatibility mode uses UTC rather than making zero-argument EXSLT functions unavailable.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_local(&self) -> Result<OffsetDateTime> {
        match OffsetDateTime::now_local() {
            Ok(now) => Ok(now),
            Err(time::error::IndeterminateOffset) => Ok(OffsetDateTime::now_utc()),
        }
    }
}

/// Immutable operation time for deterministic transformations and tests.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(OffsetDateTime);

impl FixedClock {
    #[must_use]
    pub const fn new(value: OffsetDateTime) -> Self {
        Self(value)
    }
}

impl Clock for FixedClock {
    fn now_local(&self) -> Result<OffsetDateTime> {
        Ok(self.0)
    }
}

/// Permission boundary for extension behavior that can make output nondeterministic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExtensionPolicy {
    /// Enable all implemented compatibility extensions.
    #[default]
    Compatible,
    /// Reject extension calls whose result depends on ambient operation state.
    Deterministic,
}

/// Explicit capabilities supplied to one transformation execution.
///
/// Embedding security protocols must derive extension permission from their operation's compiled
/// policy snapshot. Keeping that translation at the adapter boundary lets this crate remain
/// reusable without making these engine-level values an independent security-policy source.
pub struct ExecutionEnvironment<R: Resolver + 'static> {
    pub(crate) resolver: Arc<R>,
    pub(crate) clock: Arc<dyn Clock>,
    pub(crate) extension_policy: ExtensionPolicy,
}

impl<R: Resolver + 'static> ExecutionEnvironment<R> {
    #[must_use]
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            clock: Arc::new(SystemClock),
            extension_policy: ExtensionPolicy::Compatible,
        }
    }

    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    #[must_use]
    pub const fn with_extension_policy(mut self, policy: ExtensionPolicy) -> Self {
        self.extension_policy = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{Clock, SystemClock};

    #[test]
    fn system_clock_remains_available_after_threads_start() {
        // Unix local-offset discovery may become indeterminate once the process is multithreaded;
        // compatibility mode must still provide an operation time.
        std::thread::spawn(|| SystemClock.now_local())
            .join()
            .expect("clock thread does not panic")
            .expect("system clock falls back to UTC when local offset is unavailable");
    }
}
