use crate::{Error, Result};

pub(crate) const ENTITY_EXPANSION_DEPTH_CEILING: usize = 10;
pub(crate) const ENTITY_REFERENCE_CEILING: usize = 255;
// This is an absolute parser safety ceiling, not a deployment policy default.
// Caller budgets may reject smaller documents at the compile/execution boundary.
pub(crate) const ENTITY_EXPANSION_BYTE_CEILING: usize = 16 * 1024 * 1024;
// This bounds cumulative namespace-scope copies made while projecting an XML document.
// Shared scopes avoid the charge until a descendant introduces a local declaration.
pub(crate) const NAMESPACE_SCOPE_BYTE_CEILING: usize = 16 * 1024 * 1024;
// Compilation still uses bounded native recursion while borrowing frontend nodes. This absolute
// process-safety ceiling only tightens caller policy until module and instruction traversal are
// represented entirely by explicit work stacks.
pub(crate) const COMPILE_RECURSION_DEPTH_CEILING: usize = 256;
// XInclude resolution currently retains one small native frame per nested acquired document.
// This absolute process-safety ceiling only tightens the caller's execution policy.
pub(crate) const XINCLUDE_RECURSION_DEPTH_CEILING: usize = 256;
// Global initialization, attribute-set expansion, and stylesheet-defined functions retain native
// Rust frames. This process-safety ceiling only tightens the caller's execution policy.
pub(crate) const EXECUTION_RECURSION_DEPTH_CEILING: usize = 256;

/// Independently metered XSLT resource dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BudgetKind {
    StylesheetBytes,
    SourceBytes,
    SourceNodes,
    ImportedModules,
    ExternalDocuments,
    RecursionDepth,
    XPathEvaluations,
    PatternEvaluations,
    TemplateApplications,
    SortComparisons,
    KeyEntries,
    ResultNodes,
    SerializedBytes,
    Messages,
    OwnedBytes,
}

/// Policy-neutral enforcement limits for parsing one caller-supplied XML document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseBudget {
    pub source_bytes: usize,
    pub source_nodes: usize,
    pub recursion_depth: usize,
}

impl ParseBudget {
    #[must_use]
    pub const fn new(source_bytes: usize, source_nodes: usize, recursion_depth: usize) -> Self {
        Self {
            source_bytes,
            source_nodes,
            recursion_depth,
        }
    }

    pub(crate) const UNBOUNDED: Self = Self::new(usize::MAX, usize::MAX, usize::MAX);
}

/// Policy-neutral immutable enforcement limits for compiling a stylesheet graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileBudget {
    pub stylesheet_bytes: usize,
    pub imported_modules: usize,
    pub recursion_depth: usize,
    pub owned_bytes: usize,
}

impl CompileBudget {
    #[must_use]
    pub const fn new(
        stylesheet_bytes: usize,
        imported_modules: usize,
        recursion_depth: usize,
        owned_bytes: usize,
    ) -> Self {
        Self {
            stylesheet_bytes,
            imported_modules,
            recursion_depth,
            owned_bytes,
        }
    }
}

/// Policy-neutral immutable enforcement limits shared by one transformation execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub source_bytes: usize,
    pub external_documents: usize,
    pub recursion_depth: usize,
    pub xpath_evaluations: usize,
    pub pattern_evaluations: usize,
    pub template_applications: usize,
    pub sort_comparisons: usize,
    pub key_entries: usize,
    pub result_nodes: usize,
    pub serialized_bytes: usize,
    pub messages: usize,
    pub owned_bytes: usize,
}

#[derive(Debug)]
pub(crate) struct Meter {
    limits: ExecutionBudget,
    xpath_evaluations: usize,
    pattern_evaluations: usize,
    template_applications: usize,
    sort_comparisons: usize,
    key_entries: usize,
    result_nodes: usize,
    serialized_bytes: usize,
    messages: usize,
    owned_bytes: usize,
    external_documents: usize,
}

impl Meter {
    pub(crate) fn new(limits: ExecutionBudget, source_bytes: usize) -> Result<Self> {
        ensure(BudgetKind::SourceBytes, limits.source_bytes, source_bytes)?;
        ensure(BudgetKind::OwnedBytes, limits.owned_bytes, source_bytes)?;
        Ok(Self {
            limits,
            xpath_evaluations: 0,
            pattern_evaluations: 0,
            template_applications: 0,
            sort_comparisons: 0,
            key_entries: 0,
            result_nodes: 0,
            serialized_bytes: 0,
            messages: 0,
            owned_bytes: source_bytes,
            external_documents: 0,
        })
    }

    pub(crate) fn recursion(&self, depth: usize) -> Result<()> {
        ensure(
            BudgetKind::RecursionDepth,
            self.limits.recursion_depth,
            depth,
        )
    }

    pub(crate) fn recursion_with_ceiling(&self, depth: usize, ceiling: usize) -> Result<()> {
        ensure(
            BudgetKind::RecursionDepth,
            self.limits.recursion_depth.min(ceiling),
            depth,
        )
    }

    pub(crate) fn charge(&mut self, kind: BudgetKind, amount: usize) -> Result<()> {
        let (used, limit) = match kind {
            BudgetKind::ExternalDocuments => {
                (&mut self.external_documents, self.limits.external_documents)
            }
            BudgetKind::XPathEvaluations => {
                (&mut self.xpath_evaluations, self.limits.xpath_evaluations)
            }
            BudgetKind::PatternEvaluations => (
                &mut self.pattern_evaluations,
                self.limits.pattern_evaluations,
            ),
            BudgetKind::TemplateApplications => (
                &mut self.template_applications,
                self.limits.template_applications,
            ),
            BudgetKind::SortComparisons => {
                (&mut self.sort_comparisons, self.limits.sort_comparisons)
            }
            BudgetKind::KeyEntries => (&mut self.key_entries, self.limits.key_entries),
            BudgetKind::ResultNodes => (&mut self.result_nodes, self.limits.result_nodes),
            BudgetKind::SerializedBytes => {
                (&mut self.serialized_bytes, self.limits.serialized_bytes)
            }
            BudgetKind::Messages => (&mut self.messages, self.limits.messages),
            BudgetKind::OwnedBytes => (&mut self.owned_bytes, self.limits.owned_bytes),
            other => {
                return Err(Error::Dynamic(format!(
                    "{other:?} cannot be charged during execution"
                )));
            }
        };
        let Some(actual) = used.checked_add(amount) else {
            *used = usize::MAX;
            return Err(Error::Budget {
                kind,
                limit,
                actual: usize::MAX,
            });
        };
        ensure(kind, limit, actual)?;
        *used = actual;
        Ok(())
    }

    pub(crate) fn check_additional(&self, kind: BudgetKind, amount: usize) -> Result<()> {
        let (used, limit) = self.usage(kind)?;
        ensure(kind, limit, used.saturating_add(amount))
    }

    fn record_owned_allocation(&mut self, amount: usize) -> Result<()> {
        let Some(actual) = self.owned_bytes.checked_add(amount) else {
            self.owned_bytes = usize::MAX;
            return Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: self.limits.owned_bytes,
                actual: usize::MAX,
            });
        };
        self.owned_bytes = actual;
        ensure(BudgetKind::OwnedBytes, self.limits.owned_bytes, actual)
    }

    pub(crate) fn release_owned_bytes(&mut self, amount: usize) {
        self.owned_bytes = self
            .owned_bytes
            .checked_sub(amount)
            .expect("released owned-byte reservation was previously charged");
    }

    pub(crate) fn usage(&self, kind: BudgetKind) -> Result<(usize, usize)> {
        match kind {
            BudgetKind::ExternalDocuments => {
                Ok((self.external_documents, self.limits.external_documents))
            }
            BudgetKind::XPathEvaluations => {
                Ok((self.xpath_evaluations, self.limits.xpath_evaluations))
            }
            BudgetKind::PatternEvaluations => {
                Ok((self.pattern_evaluations, self.limits.pattern_evaluations))
            }
            BudgetKind::TemplateApplications => Ok((
                self.template_applications,
                self.limits.template_applications,
            )),
            BudgetKind::SortComparisons => {
                Ok((self.sort_comparisons, self.limits.sort_comparisons))
            }
            BudgetKind::KeyEntries => Ok((self.key_entries, self.limits.key_entries)),
            BudgetKind::ResultNodes => Ok((self.result_nodes, self.limits.result_nodes)),
            BudgetKind::SerializedBytes => {
                Ok((self.serialized_bytes, self.limits.serialized_bytes))
            }
            BudgetKind::Messages => Ok((self.messages, self.limits.messages)),
            BudgetKind::OwnedBytes => Ok((self.owned_bytes, self.limits.owned_bytes)),
            other => Err(Error::Dynamic(format!(
                "{other:?} cannot be checked during execution"
            ))),
        }
    }

    pub(crate) fn remaining_owned_bytes(&self) -> usize {
        self.limits.owned_bytes.saturating_sub(self.owned_bytes)
    }

    pub(crate) const fn recursion_limit(&self) -> usize {
        self.limits.recursion_depth
    }
}

pub(crate) fn reserve_temporary_vec_slot<T>(
    items: &mut Vec<T>,
    meter: &mut Meter,
    reserved_owned_bytes: &mut usize,
) -> Result<()> {
    if std::mem::size_of::<T>() == 0 || items.len() < items.capacity() {
        return Ok(());
    }
    let old_capacity = items.capacity();
    let requested_slots = old_capacity.max(4);
    let requested_bytes = requested_slots.saturating_mul(std::mem::size_of::<T>());
    meter.charge(BudgetKind::OwnedBytes, requested_bytes)?;
    if let Err(error) = items.try_reserve_exact(requested_slots) {
        meter.release_owned_bytes(requested_bytes);
        return Err(Error::Dynamic(format!(
            "failed to reserve temporary execution storage: {error}"
        )));
    }
    let actual_bytes = items
        .capacity()
        .saturating_sub(old_capacity)
        .saturating_mul(std::mem::size_of::<T>());
    reconcile_temporary_vec_growth(meter, reserved_owned_bytes, requested_bytes, actual_bytes)
}

fn reconcile_temporary_vec_growth(
    meter: &mut Meter,
    reserved_owned_bytes: &mut usize,
    requested_bytes: usize,
    actual_bytes: usize,
) -> Result<()> {
    if actual_bytes < requested_bytes {
        meter.release_owned_bytes(requested_bytes - actual_bytes);
    } else if actual_bytes > requested_bytes {
        *reserved_owned_bytes = reserved_owned_bytes.saturating_add(actual_bytes);
        // Vec may retain allocator-granted excess capacity and offers no guaranteed rollback.
        // Record it even when it crosses the limit so a caller that catches the error cannot
        // reuse unmetered storage; the over-limit meter then remains fail-closed.
        meter.record_owned_allocation(actual_bytes - requested_bytes)?;
        return Ok(());
    }
    *reserved_owned_bytes = reserved_owned_bytes.saturating_add(actual_bytes);
    Ok(())
}

pub(crate) fn ensure(kind: BudgetKind, limit: usize, actual: usize) -> Result<()> {
    if actual > limit {
        return Err(Error::Budget {
            kind,
            limit,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution_budget(owned_bytes: usize) -> ExecutionBudget {
        ExecutionBudget {
            source_bytes: 64,
            external_documents: 0,
            recursion_depth: 1,
            xpath_evaluations: 0,
            pattern_evaluations: 0,
            template_applications: 0,
            sort_comparisons: 0,
            key_entries: 0,
            result_nodes: 0,
            serialized_bytes: 0,
            messages: 0,
            owned_bytes,
        }
    }

    #[test]
    fn meter_rejects_initial_source_ownership_above_its_limit() {
        assert!(Meter::new(execution_budget(8), 8).is_ok());
        assert!(matches!(
            Meter::new(execution_budget(7), 8),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: 7,
                actual: 8,
            })
        ));
    }

    #[test]
    fn failed_vec_growth_shortfall_remains_accounted() {
        // An allocator may grant more capacity than Vec::try_reserve_exact requests. Once that
        // allocation exists, a failed shortfall charge must leave the meter fail-closed rather
        // than making the retained capacity reusable without accounting.
        let mut meter = Meter::new(execution_budget(10), 0).expect("meter initializes");
        meter
            .charge(BudgetKind::OwnedBytes, 8)
            .expect("requested growth fits");
        let mut reserved = 0;

        assert!(matches!(
            reconcile_temporary_vec_growth(&mut meter, &mut reserved, 8, 12),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: 10,
                actual: 12,
            })
        ));
        assert_eq!(
            meter
                .usage(BudgetKind::OwnedBytes)
                .expect("owned-byte usage is available"),
            (12, 10)
        );
        assert_eq!(reserved, 12);
        assert!(meter.charge(BudgetKind::OwnedBytes, 1).is_err());
    }

    #[test]
    fn overflowing_owned_allocation_leaves_the_meter_fail_closed() {
        let mut meter = Meter::new(execution_budget(usize::MAX), 1).expect("meter initializes");

        assert!(matches!(
            meter.record_owned_allocation(usize::MAX),
            Err(Error::Budget {
                kind: BudgetKind::OwnedBytes,
                limit: usize::MAX,
                actual: usize::MAX,
            })
        ));
        assert_eq!(
            meter
                .usage(BudgetKind::OwnedBytes)
                .expect("owned-byte usage is available"),
            (usize::MAX, usize::MAX)
        );
        assert!(meter.charge(BudgetKind::OwnedBytes, 1).is_err());
    }
}
