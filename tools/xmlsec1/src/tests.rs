use std::io;

use super::*;

struct FlushFailure {
    bytes: Vec<u8>,
}

impl Write for FlushFailure {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed output"))
    }
}

#[test]
fn reports_stdout_flush_failures_as_process_failures() {
    // A successful command is not successful at the process boundary until
    // its buffered output has reached the sink.
    let mut stdout = FlushFailure { bytes: Vec::new() };
    let mut stderr = Vec::new();

    let status = run(
        [OsString::from("xmlsec1"), OsString::from("version")],
        &mut stdout,
        &mut stderr,
    );

    assert_eq!(status, ExitCode::FAILURE);
    assert!(String::from_utf8(stderr).unwrap().contains("closed output"));
}
