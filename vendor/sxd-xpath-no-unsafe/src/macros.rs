/// Convenience constructor for a nodeset.
///
/// ```
/// use sxd_document_no_unsafe::Package;
///
/// let package = Package::new();
/// let root = package.as_document().root();
/// let nodes = sxd_xpath_no_unsafe::nodeset![root,];
/// assert_eq!(nodes.size(), 1);
/// ```
#[macro_export]
macro_rules! nodeset(
    ($($e:expr),*) => ({
        // leading _ to allow empty construction without a warning.
        let mut _temp = $crate::nodeset::Nodeset::new();
        $(_temp.add($e);)*
        _temp
    });
    ($($e:expr),+,) => ($crate::nodeset!($($e),+))
);

/// Convenience constructor for an OrderedNodes
#[cfg(test)]
macro_rules! ordered_nodes {
    ( $($val:expr,)* ) => {
        $crate::nodeset::OrderedNodes::from(vec![
            $( $crate::nodeset::Node::from($val), )*
        ])
    };
    ( $($val:expr),* ) => {
        ordered_nodes![$($val, )*]
    };
}
