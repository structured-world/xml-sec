//! Helpers shared by the tests that inspect repository files.

/// Reads a repository file as text.
pub(crate) fn read(path: &str) -> String {
    std::fs::read_to_string(crate::repo::root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

/// The body of a top-level workflow job: up to the next `  name:` line.
pub(crate) fn section<'a>(workflow: &'a str, job: &str) -> &'a str {
    let marker = format!("\n  {job}:\n");
    let start = workflow
        .find(&marker)
        .unwrap_or_else(|| panic!("job {job}"))
        + marker.len();
    let rest = &workflow[start..];
    let mut offset = 0;
    for (index, line) in rest.split_inclusive('\n').enumerate() {
        let header = line
            .strip_prefix("  ")
            .and_then(|line| line.strip_suffix(":\n"))
            .is_some_and(|name| {
                !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            });
        if index > 0 && header {
            return &rest[..offset - 1];
        }
        offset += line.len();
    }
    rest
}
