//! Helpers shared by the tests that inspect repository files.

/// Reads a repository file as text.
pub(crate) fn read(path: &str) -> String {
    std::fs::read_to_string(crate::repo::root().join(path))
        .unwrap_or_else(|error| panic!("read {path}: {error}"))
}

/// Every job of `workflow` as `(name, body)`, in order.
pub(crate) fn jobs(workflow: &str) -> Vec<(String, String)> {
    let start = workflow.find("\njobs:\n").expect("a jobs table") + "\njobs:\n".len();
    let mut jobs: Vec<(String, String)> = Vec::new();
    for line in workflow[start..].split_inclusive('\n') {
        let header = line
            .strip_prefix("  ")
            .and_then(|line| line.strip_suffix(":\n"))
            .filter(|name| {
                name.starts_with(|c: char| c.is_ascii_lowercase())
                    && name
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            });
        if let Some(name) = header {
            jobs.push((name.to_owned(), String::new()));
        } else if let Some((_, body)) = jobs.last_mut() {
            body.push_str(line);
        }
    }
    jobs
}

/// The literal block that follows `marker`: the next lines indented by at
/// least `indent` spaces, with that indentation removed.
pub(crate) fn literal_block(text: &str, marker: &str, indent: usize) -> String {
    let start = text.find(marker).unwrap_or_else(|| panic!("{marker}")) + marker.len();
    let prefix = " ".repeat(indent);
    text[start..]
        .split_inclusive('\n')
        .map_while(|line| line.strip_prefix(&prefix))
        .collect()
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
