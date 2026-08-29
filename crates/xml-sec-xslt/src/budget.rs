use crate::{Error, Result};

/// Independently metered XSLT resource dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BudgetKind {
    StylesheetBytes,
    SourceBytes,
    ImportedModules,
    ExternalDocuments,
    RecursionDepth,
    XPathEvaluations,
    TemplateApplications,
    SortComparisons,
    KeyEntries,
    ResultNodes,
    SerializedBytes,
    Messages,
    OwnedBytes,
}

/// Explicit immutable limits used while compiling a stylesheet graph.
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

/// Explicit immutable limits shared by one transformation execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub source_bytes: usize,
    pub external_documents: usize,
    pub recursion_depth: usize,
    pub xpath_evaluations: usize,
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
        Ok(Self {
            limits,
            xpath_evaluations: 0,
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

    pub(crate) fn charge(&mut self, kind: BudgetKind, amount: usize) -> Result<()> {
        let (used, limit) = match kind {
            BudgetKind::ExternalDocuments => {
                (&mut self.external_documents, self.limits.external_documents)
            }
            BudgetKind::XPathEvaluations => {
                (&mut self.xpath_evaluations, self.limits.xpath_evaluations)
            }
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
        let actual = used.checked_add(amount).unwrap_or(usize::MAX);
        ensure(kind, limit, actual)?;
        *used = actual;
        Ok(())
    }

    pub(crate) fn check_additional(&self, kind: BudgetKind, amount: usize) -> Result<()> {
        let (used, limit) = self.usage(kind)?;
        ensure(kind, limit, used.saturating_add(amount))
    }

    pub(crate) fn usage(&self, kind: BudgetKind) -> Result<(usize, usize)> {
        match kind {
            BudgetKind::ExternalDocuments => {
                Ok((self.external_documents, self.limits.external_documents))
            }
            BudgetKind::XPathEvaluations => {
                Ok((self.xpath_evaluations, self.limits.xpath_evaluations))
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
