//! Stack-safety ceiling shared by embedded and standalone `XPath` kernels.

/// Maximum grammar nesting and evaluator call depth. This is an absolute
/// implementation ceiling, not a deployment-selectable policy default.
pub(crate) const MAX_DEPTH: usize = 256;
