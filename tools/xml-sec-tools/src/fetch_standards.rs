//! `fetch-standards`: downloads the publisher texts listed in
//! `docs/standards-sources.tsv`, with RFC status metadata, into the local
//! reference corpus `.refs/standards`, which stays out of source control.

use crate::repo::{Failure, Run, Step, System, require, root};
use std::path::Path;

#[cfg(test)]
mod tests;

/// One listed source: the local file name and its official URL.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Source {
    pub(crate) name: String,
    pub(crate) url: String,
}

/// The tab-separated sources; blank and `#` lines are skipped.
pub(crate) fn sources(text: &str) -> Result<Vec<Source>, String> {
    text.lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, url) = line
                .split_once('\t')
                .ok_or_else(|| format!("not a name<TAB>url line: {line}"))?;
            Ok(Source {
                name: name.to_owned(),
                url: url.to_owned(),
            })
        })
        .collect()
}

fn download(url: &str, output: &Path, connect_timeout: bool) -> Step {
    let output = output.display().to_string();
    let mut args = vec!["--fail", "--location", "--retry", "2"];
    if connect_timeout {
        args.extend(["--connect-timeout", "20"]);
    }
    args.extend([
        "--max-time",
        "120",
        "--silent",
        "--show-error",
        url,
        "-o",
        &output,
    ]);
    Step::new(format!("fetch {url}"), "curl", &args)
}

fn rename(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::rename(from, to).map_err(|error| format!("{}: {error}", to.display()))
}

/// Downloads every source into `destination`, then records its digests and time.
pub(crate) fn execute(
    run: &mut impl Run,
    sources: &[Source],
    destination: &Path,
    now: &str,
) -> Result<(), Failure> {
    std::fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    for Source { name, url } in sources {
        println!("Fetching {name}");
        let partial = destination.join(format!("{name}.part"));
        require(run.status(&download(url, &partial, true))?)?;
        let is_pdf = Path::new(name)
            .extension()
            .is_some_and(|extension| extension == "pdf");
        if is_pdf
            && !std::fs::read(&partial)
                .map_err(|error| error.to_string())?
                .starts_with(b"%PDF-")
        {
            return Err(format!("Expected PDF, received another payload: {url}").into());
        }
        rename(&partial, &destination.join(name))?;
        if let Some(rfc) = name
            .strip_suffix(".txt")
            .filter(|stem| stem.starts_with("rfc"))
        {
            let metadata = destination.join(format!("{rfc}.json"));
            let partial = destination.join(format!("{rfc}.json.part"));
            require(run.status(&download(
                &format!("https://www.rfc-editor.org/rfc/{rfc}.json"),
                &partial,
                false,
            ))?)?;
            rename(&partial, &metadata)?;
        }
    }
    let mut names: Vec<String> = std::fs::read_dir(destination)
        .map_err(|error| error.to_string())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| {
            let partial = Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "part");
            let record = name == "SHA256SUMS" || name == "retrieved-at.txt";
            !partial && !record
        })
        .collect();
    names.sort();
    let mut sums = String::new();
    for name in names {
        let data = std::fs::read(destination.join(&name)).map_err(|error| error.to_string())?;
        sums.push_str(&crate::security_corpus::sha256(&data));
        sums.push_str("  ./");
        sums.push_str(&name);
        sums.push('\n');
    }
    std::fs::write(destination.join("SHA256SUMS"), sums).map_err(|error| error.to_string())?;
    std::fs::write(destination.join("retrieved-at.txt"), format!("{now}\n"))
        .map_err(|error| error.to_string())?;
    println!("Reference corpus: {}", destination.display());
    Ok(())
}

pub(crate) fn run(mut args: impl Iterator<Item = String>) -> Result<(), Failure> {
    if args.next().is_some() {
        return Err("usage: fetch-standards".into());
    }
    let root = root();
    let list = root.join("docs/standards-sources.tsv");
    let text =
        std::fs::read_to_string(&list).map_err(|error| format!("{}: {error}", list.display()))?;
    // Seconds precision, as the corpus has always recorded its retrieval time.
    let stamp = crate::bench::timestamp();
    let now = format!("{}Z", stamp.get(..19).unwrap_or(&stamp));
    execute(
        &mut System,
        &sources(&text)?,
        &root.join(".refs/standards"),
        &now,
    )
}
