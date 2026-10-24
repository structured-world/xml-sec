use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hash};

use super::{Error, Result};

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
// Global initialization, capture constructors, attribute-set expansion, and stylesheet-defined
// functions retain native Rust frames. This process-safety ceiling only tightens caller policy;
// iterative template depth is independent of the count of live native sequence frames.
pub(crate) const EXECUTION_RECURSION_DEPTH_CEILING: usize = 256;

/// Independently metered XSLT resource dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BudgetKind {
    StylesheetBytes,
    SourceBytes,
    SourceNodes,
    EntityReferences,
    EntityExpansionBytes,
    NamespaceScopeBytes,
    ImportedModules,
    ExternalDocuments,
    RecursionDepth,
    XPathEvaluations,
    XPathOperations,
    ExtensionOperations,
    PatternEvaluations,
    TemplateApplications,
    SortComparisons,
    KeyEntries,
    ResultNodes,
    SerializedBytes,
    Messages,
    OwnedBytes,
    /// XML text scanned by parser passes, one charge per pass over a text.
    ParseWorkBytes,
    /// Every kind of execution work together, against the caller's work ceiling.
    AggregateWork,
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
    /// Maximum aggregate bytes materialized while expanding entities.
    pub entity_expansion_bytes: usize,
    /// Maximum peak bytes used to materialize inherited namespace scopes and their indexes.
    pub namespace_scope_bytes: usize,
    /// Maximum live bytes of the tree and parser staging, including namespace scopes.
    pub owned_bytes: usize,
    /// Maximum XML text scanned, one charge per parser pass.
    pub parse_work_bytes: usize,
}

impl ParseBudget {
    /// Limits without a tree-size or parser-work ceiling; see [`Self::with_owned_bytes`]
    /// and [`Self::with_parse_work_bytes`].
    #[must_use]
    pub const fn new(
        source_bytes: usize,
        source_nodes: usize,
        recursion_depth: usize,
        entity_references: usize,
        entity_expansion_bytes: usize,
        namespace_scope_bytes: usize,
    ) -> Self {
        Self {
            source_bytes,
            source_nodes,
            recursion_depth,
            entity_references,
            entity_expansion_bytes,
            namespace_scope_bytes,
            owned_bytes: usize::MAX,
            parse_work_bytes: usize::MAX,
        }
    }

    /// Bound live tree and parser staging bytes.
    #[must_use]
    pub const fn with_owned_bytes(mut self, owned_bytes: usize) -> Self {
        self.owned_bytes = owned_bytes;
        self
    }

    /// Bound the XML text scanned by every parser pass together.
    #[must_use]
    pub const fn with_parse_work_bytes(mut self, parse_work_bytes: usize) -> Self {
        self.parse_work_bytes = parse_work_bytes;
        self
    }

    pub(crate) const UNBOUNDED: Self = Self::new(
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
        usize::MAX,
    );
}

/// Policy-neutral immutable enforcement limits for compiling a stylesheet graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompileBudget {
    pub stylesheet_bytes: usize,
    pub imported_modules: usize,
    pub recursion_depth: usize,
    pub owned_bytes: usize,
    /// Maximum stylesheet text scanned, one charge per parser pass.
    pub parse_work_bytes: usize,
}

impl CompileBudget {
    /// Limits without a parser-work ceiling; see [`Self::with_parse_work_bytes`].
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
            parse_work_bytes: usize::MAX,
        }
    }

    /// Bound the stylesheet text scanned by every parser pass together.
    #[must_use]
    pub const fn with_parse_work_bytes(mut self, parse_work_bytes: usize) -> Self {
        self.parse_work_bytes = parse_work_bytes;
        self
    }
}

/// The outcome of a budgeted operation and what it consumed, reported whether
/// it succeeded or failed, so a caller sharing one allowance across operations
/// can debit failed work too.
#[derive(Debug)]
pub struct Reported<T, U> {
    pub outcome: Result<T>,
    pub usage: U,
}

/// Parser work one compilation or parse admitted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseUsage {
    /// Text bytes charged, one charge per parser pass.
    pub parse_work_bytes: usize,
}

/// A parser-work meter: each pass is charged before it scans.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParseWork {
    limit: usize,
    used: usize,
}

impl ParseWork {
    pub(crate) const fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    pub(crate) fn charge(&mut self, bytes: usize) -> Result<()> {
        let actual = self.used.checked_add(bytes).ok_or(Error::Budget {
            kind: BudgetKind::ParseWorkBytes,
            limit: self.limit,
            actual: usize::MAX,
        })?;
        ensure(BudgetKind::ParseWorkBytes, self.limit, actual)?;
        self.used = actual;
        Ok(())
    }

    pub(crate) const fn usage(&self) -> ParseUsage {
        ParseUsage {
            parse_work_bytes: self.used,
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
    /// Maximum primitive traversal, predicate, comparison, and node-set insertion operations.
    pub xpath_operations: usize,
    /// Internal work performed by extension functions after one `XPath` call is dispatched.
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

/// Work admitted by one execution, whether it succeeded or failed.
///
/// Each counter is the amount the corresponding [`ExecutionBudget`] limit admitted, never more
/// than that limit, so a caller sharing one allowance across executions can pass the remainder
/// as the next budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExecutionUsage {
    pub external_documents: usize,
    pub xpath_evaluations: usize,
    pub xpath_operations: usize,
    pub extension_operations: usize,
    pub pattern_evaluations: usize,
    pub template_applications: usize,
    pub sort_comparisons: usize,
    pub key_entries: usize,
    pub result_nodes: usize,
    pub serialized_bytes: usize,
    pub messages: usize,
}

#[derive(Debug)]
pub(crate) struct Meter {
    limits: ExecutionBudget,
    xpath_evaluations: usize,
    xpath_operations: usize,
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
    work: usize,
    work_ceiling: usize,
}

impl BudgetKind {
    /// Whether the kind counts toward an execution's aggregate work ceiling.
    #[must_use]
    pub const fn is_execution_work(self) -> bool {
        matches!(
            self,
            Self::XPathEvaluations
                | Self::XPathOperations
                | Self::ExtensionOperations
                | Self::PatternEvaluations
                | Self::TemplateApplications
                | Self::SortComparisons
                | Self::KeyEntries
                | Self::ResultNodes
                | Self::Messages
                | Self::SerializedBytes
        )
    }
}

impl Meter {
    pub(crate) fn new(limits: ExecutionBudget, source_bytes: usize) -> Result<Self> {
        ensure(BudgetKind::SourceBytes, limits.source_bytes, source_bytes)?;
        ensure(BudgetKind::OwnedBytes, limits.owned_bytes, source_bytes)?;
        Ok(Self {
            limits,
            xpath_evaluations: 0,
            xpath_operations: 0,
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
            work: 0,
            work_ceiling: usize::MAX,
        })
    }

    /// Bound the kinds of [`BudgetKind::is_execution_work`] together.
    pub(crate) const fn with_work_ceiling(mut self, ceiling: usize) -> Self {
        self.work_ceiling = ceiling;
        self
    }

    /// Work the ceiling still admits, across every kind it bounds.
    pub(crate) const fn work_remaining(&self) -> usize {
        // Every admitted total stayed within the ceiling.
        self.work_ceiling - self.work
    }

    /// The ceiling over every kind of execution work together.
    pub(crate) const fn work_ceiling(&self) -> usize {
        self.work_ceiling
    }

    /// The aggregate work total after `amount` more, if the ceiling admits it.
    fn admit_work(&self, kind: BudgetKind, amount: usize) -> Result<usize> {
        if !kind.is_execution_work() {
            return Ok(self.work);
        }
        let actual = self.work.checked_add(amount).ok_or(Error::Budget {
            kind: BudgetKind::AggregateWork,
            limit: self.work_ceiling,
            actual: usize::MAX,
        })?;
        ensure(BudgetKind::AggregateWork, self.work_ceiling, actual)?;
        Ok(actual)
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
        let work = self.admit_work(kind, amount)?;
        let (used, limit) = match kind {
            BudgetKind::ExternalDocuments => {
                (&mut self.external_documents, self.limits.external_documents)
            }
            BudgetKind::XPathEvaluations => {
                (&mut self.xpath_evaluations, self.limits.xpath_evaluations)
            }
            BudgetKind::XPathOperations => {
                (&mut self.xpath_operations, self.limits.xpath_operations)
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
        self.work = work;
        Ok(())
    }

    pub(crate) fn check_additional(&self, kind: BudgetKind, amount: usize) -> Result<()> {
        self.admit_work(kind, amount)?;
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
            BudgetKind::XPathOperations => {
                Ok((self.xpath_operations, self.limits.xpath_operations))
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

    pub(crate) const fn admitted_work(&self) -> ExecutionUsage {
        // A counter exceeds its limit only after an overflowing charge poisons it; that
        // refusal admitted the whole limit and nothing beyond it.
        const fn admitted(used: usize, limit: usize) -> usize {
            if used > limit { limit } else { used }
        }
        let limits = &self.limits;
        ExecutionUsage {
            external_documents: admitted(self.external_documents, limits.external_documents),
            xpath_evaluations: admitted(self.xpath_evaluations, limits.xpath_evaluations),
            xpath_operations: admitted(self.xpath_operations, limits.xpath_operations),
            extension_operations: admitted(self.extension_operations, limits.extension_operations),
            pattern_evaluations: admitted(self.pattern_evaluations, limits.pattern_evaluations),
            template_applications: admitted(
                self.template_applications,
                limits.template_applications,
            ),
            sort_comparisons: admitted(self.sort_comparisons, limits.sort_comparisons),
            key_entries: admitted(self.key_entries, limits.key_entries),
            result_nodes: admitted(self.result_nodes, limits.result_nodes),
            serialized_bytes: admitted(self.serialized_bytes, limits.serialized_bytes),
            messages: admitted(self.messages, limits.messages),
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

pub(crate) fn append_metered_string(
    current: &mut String,
    suffix: &str,
    meter: &mut Meter,
) -> Result<()> {
    reserve_metered_string(current, suffix.len(), meter)?;
    current.push_str(suffix);
    Ok(())
}

pub(crate) fn reserve_metered_string(
    current: &mut String,
    additional: usize,
    meter: &mut Meter,
) -> Result<()> {
    let required = current
        .len()
        .checked_add(additional)
        .filter(|length| isize::try_from(*length).is_ok())
        .ok_or_else(|| Error::Dynamic("text value is too large".into()))?;
    if required <= current.capacity() {
        return Ok(());
    }

    meter.check_additional(BudgetKind::OwnedBytes, required)?;
    debug_assert!(isize::try_from(current.capacity()).is_ok());
    let target_capacity = (current.capacity() * 2)
        .max(required)
        .min(isize::MAX as usize)
        .min(meter.remaining_owned_bytes());
    meter.charge(BudgetKind::OwnedBytes, target_capacity)?;
    let mut replacement = String::new();
    if let Err(error) = replacement.try_reserve_exact(target_capacity) {
        meter.release_owned_bytes(target_capacity);
        return Err(Error::Dynamic(format!(
            "failed to reserve metered text storage: {error}"
        )));
    }
    let actual_capacity = replacement.capacity();
    reconcile_replacement_growth(meter, target_capacity, actual_capacity)?;
    replacement.push_str(current);
    let old_capacity = current.capacity();
    *current = replacement;
    meter.release_owned_bytes(old_capacity);
    Ok(())
}

pub(crate) fn reconcile_replacement_growth(
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

/// Grow retained vector storage through the same peak-allocation gate as temporary vectors.
pub(crate) fn reserve_retained_vec_slot<T>(items: &mut Vec<T>, meter: &mut Meter) -> Result<()> {
    let mut reserved_owned_bytes = items.capacity().saturating_mul(std::mem::size_of::<T>());
    reserve_temporary_vec_slot(items, meter, &mut reserved_owned_bytes)
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

#[cfg(all(test, not(feature = "embedded")))]
mod tests;
