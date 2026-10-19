use std::sync::Arc;

use time::OffsetDateTime;

use super::{Resolver, Result};

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
    pub(crate) work_ceiling: usize,
}

impl<R: Resolver + 'static> ExecutionEnvironment<R> {
    #[must_use]
    pub fn new(resolver: Arc<R>) -> Self {
        Self {
            resolver,
            clock: None,
            process_xinclude: false,
            work_ceiling: usize::MAX,
        }
    }

    /// Bound every kind of execution work together, on top of each kind's own limit.
    ///
    /// The caller's operation may admit less aggregate work than the budget grants per
    /// kind; that remainder is the ceiling, so the execution is refused before it does
    /// work the operation cannot pay for.
    #[must_use]
    pub const fn with_work_ceiling(mut self, work: usize) -> Self {
        self.work_ceiling = work;
        self
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

#[cfg(all(test, not(feature = "embedded")))]
mod tests;
