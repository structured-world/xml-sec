use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash};

use crate::{Error, Result};

pub(crate) const ENTITY_EXPANSION_DEPTH_CEILING: usize = 256;
// This is an absolute parser safety ceiling, not a deployment policy default.
// Caller budgets may reject smaller documents at the compile/execution boundary.
pub(crate) const ENTITY_EXPANSION_BYTE_CEILING: usize = 16 * 1024 * 1024;
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
    EntityReferences,
    NamespaceScopeBytes,
    ImportedModules,
    ExternalDocuments,
    RecursionDepth,
    XPathEvaluations,
    ExtensionOperations,
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
    /// Maximum decoded XML bytes accepted for one document.
    pub source_bytes: usize,
    /// Maximum semantic nodes, including the synthetic document root.
    pub source_nodes: usize,
    /// Maximum element nesting depth.
    pub recursion_depth: usize,
    /// Maximum declared general and parameter entity-reference occurrences expanded.
    pub entity_references: usize,
    /// Maximum peak bytes used to materialize inherited namespace scopes and their indexes.
    pub namespace_scope_bytes: usize,
}

impl ParseBudget {
    #[must_use]
    pub const fn new(
        source_bytes: usize,
        source_nodes: usize,
        recursion_depth: usize,
        entity_references: usize,
        namespace_scope_bytes: usize,
    ) -> Self {
        Self {
            source_bytes,
            source_nodes,
            recursion_depth,
            entity_references,
            namespace_scope_bytes,
        }
    }

    pub(crate) const UNBOUNDED: Self =
        Self::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX);
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
    /// Internal work performed by extension functions after one XPath call is dispatched.
    pub extension_operations: usize,
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
    extension_operations: usize,
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
            extension_operations: 0,
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
            BudgetKind::ExtensionOperations => (
                &mut self.extension_operations,
                self.limits.extension_operations,
            ),
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
            BudgetKind::ExtensionOperations => {
                Ok((self.extension_operations, self.limits.extension_operations))
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
    let target_capacity = old_capacity.saturating_add(requested_slots);
    let requested_bytes = target_capacity.saturating_mul(std::mem::size_of::<T>());
    meter.charge(BudgetKind::OwnedBytes, requested_bytes)?;
    let mut replacement = Vec::new();
    if let Err(error) = replacement.try_reserve_exact(target_capacity) {
        meter.release_owned_bytes(requested_bytes);
        return Err(Error::Dynamic(format!(
            "failed to reserve temporary execution storage: {error}"
        )));
    }
    let actual_bytes = replacement
        .capacity()
        .saturating_mul(std::mem::size_of::<T>());
    reconcile_replacement_growth(meter, requested_bytes, actual_bytes)?;

    replacement.append(items);
    std::mem::swap(items, &mut replacement);
    let old_bytes = replacement
        .capacity()
        .saturating_mul(std::mem::size_of::<T>());
    *reserved_owned_bytes = reserved_owned_bytes
        .checked_sub(old_bytes)
        .expect("temporary vector capacity was previously charged")
        .saturating_add(actual_bytes);
    meter.release_owned_bytes(old_bytes);
    Ok(())
}

fn reconcile_replacement_growth(
    meter: &mut Meter,
    requested_bytes: usize,
    actual_bytes: usize,
) -> Result<()> {
    if actual_bytes < requested_bytes {
        meter.release_owned_bytes(requested_bytes - actual_bytes);
    } else if actual_bytes > requested_bytes {
        let shortfall = actual_bytes - requested_bytes;
        if let Err(error) = meter.check_additional(BudgetKind::OwnedBytes, shortfall) {
            meter.release_owned_bytes(requested_bytes);
            return Err(error);
        }
        let charged_before_shortfall = meter.owned_bytes;
        if let Err(error) = meter.charge(BudgetKind::OwnedBytes, shortfall) {
            meter.owned_bytes = charged_before_shortfall;
            meter.release_owned_bytes(requested_bytes);
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn retained_hash_storage<T>(capacity: usize) -> usize {
    capacity
        .saturating_mul(std::mem::size_of::<T>())
        .saturating_mul(2)
}

pub(crate) fn reserve_retained_hash_set_slot<T, S>(
    items: &mut HashSet<T, S>,
    meter: &mut Meter,
    reserved_owned_bytes: &mut usize,
) -> Result<()>
where
    T: Eq + Hash,
    S: BuildHasher + Clone,
{
    if items.len() < items.capacity() {
        return Ok(());
    }
    let old_capacity = items.capacity();
    let target_capacity = old_capacity.saturating_add(old_capacity.max(4));
    let requested_bytes = retained_hash_storage::<T>(target_capacity);
    meter.charge(BudgetKind::OwnedBytes, requested_bytes)?;
    let mut replacement = HashSet::with_hasher(items.hasher().clone());
    if let Err(error) = replacement.try_reserve(target_capacity) {
        meter.release_owned_bytes(requested_bytes);
        return Err(Error::Dynamic(format!(
            "failed to reserve retained hash-set storage: {error}"
        )));
    }
    let actual_bytes = retained_hash_storage::<T>(replacement.capacity());
    reconcile_replacement_growth(meter, requested_bytes, actual_bytes)?;
    replacement.extend(items.drain());
    std::mem::swap(items, &mut replacement);
    let old_bytes = retained_hash_storage::<T>(replacement.capacity());
    *reserved_owned_bytes = reserved_owned_bytes
        .checked_sub(old_bytes)
        .expect("retained hash-set capacity was previously charged")
        .saturating_add(actual_bytes);
    meter.release_owned_bytes(old_bytes);
    Ok(())
}

pub(crate) fn reserve_retained_hash_map_slot<K, V, S>(
    items: &mut HashMap<K, V, S>,
    meter: &mut Meter,
    reserved_owned_bytes: &mut usize,
) -> Result<()>
where
    K: Eq + Hash,
    S: BuildHasher + Clone,
{
    if items.len() < items.capacity() {
        return Ok(());
    }
    let old_capacity = items.capacity();
    let target_capacity = old_capacity.saturating_add(old_capacity.max(4));
    let requested_bytes = retained_hash_storage::<(K, V)>(target_capacity);
    meter.charge(BudgetKind::OwnedBytes, requested_bytes)?;
    let mut replacement = HashMap::with_hasher(items.hasher().clone());
    if let Err(error) = replacement.try_reserve(target_capacity) {
        meter.release_owned_bytes(requested_bytes);
        return Err(Error::Dynamic(format!(
            "failed to reserve retained hash-map storage: {error}"
        )));
    }
    let actual_bytes = retained_hash_storage::<(K, V)>(replacement.capacity());
    reconcile_replacement_growth(meter, requested_bytes, actual_bytes)?;
    replacement.extend(items.drain());
    std::mem::swap(items, &mut replacement);
    let old_bytes = retained_hash_storage::<(K, V)>(replacement.capacity());
    *reserved_owned_bytes = reserved_owned_bytes
        .checked_sub(old_bytes)
        .expect("retained hash-map capacity was previously charged")
        .saturating_add(actual_bytes);
    meter.release_owned_bytes(old_bytes);
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
            extension_operations: 0,
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
    fn failed_vec_replacement_shortfall_rolls_back_accounting() {
        // An allocator may grant more capacity than Vec::try_reserve_exact requests. Rejecting
        // that temporary replacement must restore the meter before the replacement is dropped.
        let mut meter = Meter::new(execution_budget(10), 0).expect("meter initializes");
        meter
            .charge(BudgetKind::OwnedBytes, 8)
            .expect("requested growth fits");
        assert!(matches!(
            reconcile_replacement_growth(&mut meter, 8, 12),
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
            (0, 10)
        );
        meter
            .charge(BudgetKind::OwnedBytes, 10)
            .expect("failed replacement leaves the original allowance available");
    }

    #[test]
    fn overflowing_replacement_shortfall_releases_the_provisional_charge() {
        // check_additional saturates at usize::MAX, while charge detects the arithmetic overflow.
        // The replacement's provisional reservation must still be released on that error path.
        let mut meter = Meter::new(execution_budget(usize::MAX), 0).expect("meter initializes");
        meter
            .charge(BudgetKind::OwnedBytes, usize::MAX - 2)
            .expect("baseline fits");
        meter
            .charge(BudgetKind::OwnedBytes, 1)
            .expect("provisional replacement charge fits");

        assert!(matches!(
            reconcile_replacement_growth(&mut meter, 1, 3),
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
            (usize::MAX - 2, usize::MAX)
        );
    }

    #[test]
    fn overflowing_owned_charge_leaves_the_meter_fail_closed() {
        let mut meter = Meter::new(execution_budget(usize::MAX), 1).expect("meter initializes");

        assert!(matches!(
            meter.charge(BudgetKind::OwnedBytes, usize::MAX),
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
