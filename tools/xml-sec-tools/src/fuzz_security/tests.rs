use super::{ASAN, Fuzzer, Request, execute, parse, seeds, shell_quote};
use crate::repo::Step;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

/// Plays cargo-fuzz: lists the targets, and a run resolves the lock, logs
/// mutations and, when failing, leaves a reproducer.
struct Fake {
    fail: bool,
    calls: Vec<Vec<String>>,
}

impl Fuzzer for Fake {
    fn status(&mut self, _: &Path, step: &Step) -> Result<ExitStatus, String> {
        self.calls.push(step.args.clone());
        Ok(ExitStatus::from_raw(0))
    }

    fn stdout(&mut self, _: &Path, step: &Step) -> Result<(ExitStatus, Vec<u8>), String> {
        self.calls.push(step.args.clone());
        let listed = if step.args.get(1).is_some_and(|arg| arg == "fuzz") {
            let mut targets = vec!["test_target"];
            targets.extend(ASAN);
            targets.join("\n")
        } else {
            "test metadata".into()
        };
        Ok((ExitStatus::from_raw(0), listed.into_bytes()))
    }

    fn tee(&mut self, root: &Path, step: &Step, log: &Path) -> Result<ExitStatus, String> {
        self.calls.push(step.args.clone());
        std::fs::write(root.join("fuzz/Cargo.lock"), "test lock").unwrap();
        std::fs::write(log, "mutation execution\n").unwrap();
        if self.fail {
            std::fs::write(
                root.join("fuzz/artifacts")
                    .join(&step.args[3])
                    .join("crash-input"),
                "reproducer",
            )
            .unwrap();
            return Ok(ExitStatus::from_raw(77 << 8));
        }
        Ok(ExitStatus::from_raw(0))
    }
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new(corpus_size: usize) -> Self {
        let root = tempfile::tempdir().unwrap();
        for directory in ["fuzz/seeds", "fuzz/corpus/test_target"] {
            std::fs::create_dir_all(root.path().join(directory)).unwrap();
        }
        std::fs::write(root.path().join("fuzz/seeds/input"), "seed").unwrap();
        std::fs::write(
            root.path().join("fuzz/seeds.tsv"),
            "test_target\tfuzz/seeds/input\n",
        )
        .unwrap();
        for index in 0..corpus_size {
            std::fs::write(
                root.path()
                    .join(format!("fuzz/corpus/test_target/input-{index}")),
                format!("input {index}"),
            )
            .unwrap();
        }
        Self { root }
    }

    fn path(&self, path: &str) -> PathBuf {
        self.root.path().join(path)
    }

    fn request(&self, args: &[&str], fips: bool) -> Request {
        let args: Vec<String> = args.iter().map(|&arg| arg.to_owned()).collect();
        parse(&args, fips, Some(self.path("evidence"))).unwrap()
    }

    fn run(&self, request: &Request, fail: bool) -> (Result<(), crate::repo::Failure>, Fake) {
        let mut fake = Fake {
            fail,
            calls: Vec::new(),
        };
        let result = execute(request, self.root.path(), &mut fake);
        (result, fake)
    }
}

fn runs(fake: &Fake) -> Vec<&Vec<String>> {
    fake.calls
        .iter()
        .filter(|args| args.get(2).is_some_and(|arg| arg == "run"))
        .collect()
}

fn cleans(fake: &Fake) -> usize {
    fake.calls
        .iter()
        .filter(|args| args.get(1).is_some_and(|arg| arg == "clean"))
        .count()
}

fn listing(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn asan_block_executes_every_target_and_cleans_only_after_the_complete_block() {
    // Shared compilation must not remove any target or collapse target-specific evidence.
    let fixture = Fixture::new(0);
    let (result, fake) = fixture.run(&fixture.request(&["asan", "smoke"], false), false);
    result.unwrap();
    let ran: Vec<&str> = runs(&fake).iter().map(|args| args[3].as_str()).collect();
    assert_eq!(ran, ASAN);
    assert_eq!(cleans(&fake), 1);
    assert_eq!(fake.calls.last().unwrap()[1], "clean");
    for target in ASAN {
        assert!(
            fixture
                .path(&format!("evidence/{target}/run.log"))
                .is_file(),
            "{target}"
        );
    }
}

#[test]
fn a_failed_block_stops_immediately_and_preserves_the_build() {
    // A later target must never hide a crash from an earlier one.
    let fixture = Fixture::new(0);
    let (result, fake) = fixture.run(&fixture.request(&["asan", "smoke"], false), true);
    assert_eq!(result.unwrap_err().code, 77);
    assert_eq!(runs(&fake).len(), 1);
    assert_eq!(cleans(&fake), 0);
}

#[test]
fn cache_managed_execution_leaves_cleanup_to_the_registered_post_action() {
    // Saving compiled dependencies must precede successful CI cleanup.
    let fixture = Fixture::new(0);
    let (result, fake) = fixture.run(
        &fixture.request(&["test_target", "smoke", "--cache-managed"], false),
        false,
    );
    result.unwrap();
    assert_eq!(cleans(&fake), 0);
}

#[test]
fn smoke_admits_new_mutations_after_replaying_a_growing_corpus() {
    // libFuzzer counts seed execution against -runs; 300 restored entries must
    // not turn the mutation smoke gate into a replay-only pass.
    let fixture = Fixture::new(300);
    let (result, fake) = fixture.run(&fixture.request(&["test_target"], false), false);
    result.unwrap();
    let corpus = listing(&fixture.path("fuzz/corpus/test_target")).len();
    assert_eq!(corpus, 301);
    let runs = runs(&fake);
    let budget = runs[0]
        .iter()
        .find_map(|arg| arg.strip_prefix("-runs="))
        .unwrap();
    assert!(budget.parse::<usize>().unwrap() >= corpus + 257);
    assert_eq!(cleans(&fake), 1);
    assert!(fixture.path("evidence/run.log").is_file());
    assert_eq!(
        listing(&fixture.path("fuzz/artifacts/test_target")),
        Vec::<String>::new()
    );
}

#[test]
fn crashes_retain_evidence_without_cleaning_the_failed_build() {
    // A failing process must stay red and retain its lock, input and log.
    let fixture = Fixture::new(0);
    let (result, fake) = fixture.run(&fixture.request(&["test_target"], false), true);
    assert_eq!(result.unwrap_err().code, 77);
    assert_eq!(cleans(&fake), 0);
    assert_eq!(
        listing(&fixture.path("fuzz/artifacts/test_target")),
        ["crash-input"]
    );
    assert_eq!(
        std::fs::read_to_string(fixture.path("evidence/Cargo.lock")).unwrap(),
        "test lock"
    );
    assert!(
        std::fs::read_to_string(fixture.path("evidence/run.log"))
            .unwrap()
            .contains("mutation execution")
    );
}

#[test]
fn replay_is_finite_and_retains_the_full_corpus() {
    // Replay-only execution never invents an unbounded campaign or removes inputs.
    let fixture = Fixture::new(3);
    let (result, fake) = fixture.run(&fixture.request(&["test_target", "replay"], false), false);
    result.unwrap();
    assert!(runs(&fake)[0].iter().any(|arg| arg == "-runs=0"));
    assert_eq!(listing(&fixture.path("fuzz/corpus/test_target")).len(), 4);
}

#[test]
fn fips_runs_without_a_sanitizer_and_records_its_command() {
    // The FIPS module keeps its integrity checks; the evidence names the exact command.
    for fips in [false, true] {
        let fixture = Fixture::new(0);
        let (result, fake) = fixture.run(&fixture.request(&["test_target"], fips), false);
        result.unwrap();
        let run = runs(&fake)[0].clone();
        assert_eq!(run.iter().any(|arg| arg == "--features"), fips);
        assert_eq!(run.iter().any(|arg| arg == "aws-lc-fips"), fips);
        let sanitizer = run.iter().position(|arg| arg == "--sanitizer").unwrap();
        assert_eq!(run[sanitizer + 1], if fips { "none" } else { "address" });
        let command = std::fs::read_to_string(fixture.path("evidence/command.txt")).unwrap();
        assert_eq!(command.contains("--features aws-lc-fips"), fips);
        assert!(command.contains(if fips {
            "--sanitizer none"
        } else {
            "--sanitizer address"
        }));
    }
}

#[test]
fn unknown_targets_modes_options_and_seeds_are_refused() {
    // A typo must not run a different campaign or silently skip a seed.
    let fixture = Fixture::new(0);
    let (result, fake) = fixture.run(&fixture.request(&["missing_target"], false), false);
    assert_eq!(result.unwrap_err().code, 2);
    assert_eq!(runs(&fake).len(), 0);
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|&value| value.to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        parse(&args(&["t", "typo"]), false, None).unwrap_err().code,
        2
    );
    assert_eq!(
        parse(&args(&["t", "smoke", "--other"]), false, None)
            .unwrap_err()
            .code,
        2
    );
    std::fs::write(
        fixture.path("fuzz/seeds.tsv"),
        "test_target\tfuzz/seeds/absent\n",
    )
    .unwrap();
    let (result, _) = fixture.run(&fixture.request(&["test_target"], false), false);
    assert_eq!(
        result.unwrap_err().message,
        "Missing seed: fuzz/seeds/absent"
    );
}

#[test]
fn seed_selection_skips_comments_and_other_targets() {
    // Selection metadata names exact targets; comments never select seeds.
    let listing = "# comment\nother\ta\ntarget\tb\n#target\tc\ntarget\n";
    assert_eq!(seeds(listing, "target"), ["b", ""]);
}

#[test]
fn recorded_commands_quote_only_what_a_shell_would_split() {
    // The command evidence can be pasted into a shell unchanged.
    assert_eq!(
        shell_quote("-artifact_prefix=/a/b/"),
        "-artifact_prefix=/a/b/"
    );
    assert_eq!(shell_quote("a b"), "'a b'");
    assert_eq!(shell_quote("it's"), r"'it'\''s'");
}
