//! Logged child processes with a deadline. Arguments are recorded before
//! launch and both streams are written to files as they arrive, so a timeout
//! or an enclosing cancellation keeps the diagnostics read so far.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

/// The default deadline of one command.
pub(crate) const DEADLINE: Duration = Duration::from_mins(15);

/// A finished command: its exit code (none when a signal ended it) and streams.
#[derive(Debug)]
pub(crate) struct Logged {
    pub(crate) code: Option<i32>,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

impl Logged {
    pub(crate) fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// `log` with `suffix` appended to its file name.
pub(crate) fn sibling(log: &Path, suffix: &str) -> PathBuf {
    let mut name = log.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Copies one stream into its log file and reports the end of the stream.
fn stream(
    mut reader: impl Read + Send + 'static,
    mut file: std::fs::File,
    done: mpsc::Sender<Result<(), String>>,
) {
    std::thread::spawn(move || {
        let mut buffer = vec![0; 65536];
        let outcome = loop {
            match reader.read(&mut buffer) {
                Ok(0) => break Ok(()),
                // Each chunk is flushed, so a cancelled run keeps what it printed.
                Ok(read) => {
                    if let Err(error) = file.write_all(&buffer[..read]).and_then(|()| file.flush())
                    {
                        break Err(error.to_string());
                    }
                }
                Err(error) => break Err(error.to_string()),
            }
        };
        // The receiver is gone only after the command already failed.
        if done.send(outcome).is_err() {
            eprintln!("stream finished after its command was abandoned");
        }
    });
}

/// Stops the command and every process of its group.
fn terminate(child: &mut Child) {
    #[cfg(unix)]
    {
        match i32::try_from(child.id()) {
            // SAFETY: killpg only sends a signal; the group is the one this
            // child leads, created at spawn.
            Ok(group) => {
                if unsafe { libc::killpg(group, libc::SIGKILL) } != 0 {
                    // The group can already be gone; the child is reaped below.
                    eprintln!(
                        "stopping process group {group}: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }
            Err(_) => eprintln!("process id {} is not a process group", child.id()),
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = child.kill() {
        eprintln!("stopping process {}: {error}", child.id());
    }
    if let Err(error) = child.wait() {
        eprintln!("reaping process {}: {error}", child.id());
    }
}

/// Runs `args` from `directory` with extra `env`, logging to `log.command.json`,
/// `log.stdout` and `log.stderr`. A command still running, or holding its
/// output open, at `limit` is stopped with its process group.
pub(crate) fn run(
    args: &[OsString],
    log: &Path,
    directory: &Path,
    env: &[(String, String)],
    limit: Duration,
) -> Result<Logged, String> {
    if let Some(parent) = log.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("create {}: {error}", parent.display()))?;
    }
    let printable: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    let paths = [".command.json", ".stdout", ".stderr"].map(|suffix| sibling(log, suffix));
    let pretty = serde_json::to_string_pretty(&printable).map_err(|error| error.to_string())?;
    std::fs::write(&paths[0], pretty)
        .map_err(|error| format!("write {}: {error}", paths[0].display()))?;
    let create = |path: &Path| {
        std::fs::File::create(path).map_err(|error| format!("create {}: {error}", path.display()))
    };
    let (stdout_file, stderr_file) = (create(&paths[1])?, create(&paths[2])?);
    let (program, rest) = args.split_first().ok_or("empty command")?;
    let mut command = Command::new(program);
    command
        .args(rest)
        .current_dir(directory)
        .envs(env.iter().map(|(key, value)| (key, value)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command
        .spawn()
        .map_err(|error| format!("{}: {error}", printable[0]))?;
    let (sender, receiver) = mpsc::channel();
    let output = child.stdout.take().ok_or("stdout was not captured")?;
    stream(output, stdout_file, sender.clone());
    let errors = child.stderr.take().ok_or("stderr was not captured")?;
    stream(errors, stderr_file, sender);
    let deadline = Instant::now() + limit;
    let timed_out = || {
        format!(
            "command timed out after {}s; inspect {}, {} and {}",
            limit.as_secs(),
            paths[0].display(),
            paths[1].display(),
            paths[2].display()
        )
    };
    // Both streams end before the exit status counts: a descendant that keeps
    // them open is still part of the command.
    for _ in 0..2 {
        let remaining = deadline.checked_duration_since(Instant::now());
        match remaining.map(|remaining| receiver.recv_timeout(remaining)) {
            Some(Ok(Ok(()))) => {}
            Some(Ok(Err(error))) => {
                terminate(&mut child);
                return Err(format!("capturing {}: {error}", printable[0]));
            }
            // Output read before the deadline is already in the log files.
            None | Some(Err(_)) => {
                terminate(&mut child);
                return Err(timed_out());
            }
        }
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                terminate(&mut child);
                return Err(timed_out());
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                terminate(&mut child);
                return Err(format!("waiting for {}: {error}", printable[0]));
            }
        }
    };
    let read = |path: &Path| {
        std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
    };
    Ok(Logged {
        code: status.code(),
        stdout: read(&paths[1])?,
        stderr: read(&paths[2])?,
    })
}
