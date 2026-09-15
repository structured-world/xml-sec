use std::sync::Arc;

use time::OffsetDateTime;

use crate::{Resolver, Result};

/// Time source used by zero-argument EXSLT date functions during one execution.
///
/// The engine snapshots the first successful value for the execution. This keeps all date
/// functions deterministic across lazy document-loading retries without repeatedly consulting an
/// ambient clock.
pub trait Clock: Send + Sync {
    fn now_local(&self) -> Result<OffsetDateTime>;
}

/// Host local time for callers that explicitly request conventional EXSLT compatibility behavior.
///
/// On platforms where the process-local offset cannot be read soundly after threads start,
/// this clock uses UTC rather than making zero-argument EXSLT functions unavailable.
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

/// Explicit capabilities supplied to one transformation execution.
///
/// The default environment grants neither ambient clock access nor XInclude processing. Embedding
/// security protocols derive each capability from their operation's compiled policy snapshot and
/// then supply only the corresponding mechanism capability here.
pub struct ExecutionEnvironment<R: Resolver + 'static> {
    pub(crate) resolver: Arc<R>,
    pub(crate) clock: Option<Arc<dyn Clock>>,
    pub(crate) process_xinclude: bool,
}

impl<R: Resolver + 'static> ExecutionEnvironment<R> {
    #[must_use]
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            clock: None,
            process_xinclude: false,
        }
    }

    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// Grant XInclude processing for the principal source and `document()` resources.
    ///
    /// A security-protocol adapter must call this only when its compiled operation policy permits
    /// XInclude. Resolver access alone does not grant same-document XInclude processing.
    #[must_use]
    pub const fn with_xinclude(mut self) -> Self {
        self.process_xinclude = true;
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
