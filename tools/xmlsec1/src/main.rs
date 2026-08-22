use std::process::ExitCode;

fn main() -> ExitCode {
    xmlsec1_cli::run(
        std::env::args_os(),
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    )
}
