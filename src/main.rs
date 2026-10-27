use std::process::ExitCode;

fn main() -> ExitCode {
    match envaudit::cli::run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}
