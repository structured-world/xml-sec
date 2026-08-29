use std::sync::Arc;

use time::OffsetDateTime;

use crate::{Error, Resolver, Result};

/// Time source used by zero-argument EXSLT date functions during one execution.
pub trait Clock: Send + Sync {
    fn now_local(&self) -> Result<OffsetDateTime>;
}

/// Host local time, matching conventional EXSLT compatibility behavior.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_local(&self) -> Result<OffsetDateTime> {
        OffsetDateTime::now_local().map_err(|error| {
            Error::Dynamic(format!(
                "EXSLT current local datetime is unavailable: {error}"
            ))
        })
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

/// Explicit capabilities and permissions shared by one transformation execution.
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
