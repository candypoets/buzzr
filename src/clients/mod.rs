//! Subprocess clients and native Nostr publishing.

pub mod admin;
pub mod buzz;
pub mod herdr;
pub mod nostr;

use std::fmt;
use std::io::Read;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use wait_timeout::ChildExt;

pub use admin::LocalBuzzAdmin;
pub use buzz::BuzzClient;
pub use herdr::HerdrClient;
pub use nostr::NostrTools;

/// Raised when an external command or relay interaction fails.
#[derive(Debug)]
pub struct CommandError(pub String);

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CommandError {}

pub(crate) fn err<T>(message: impl Into<String>) -> Result<T, CommandError> {
    Err(CommandError(message.into()))
}

/// Decode JSON command output, mirroring `_decode_json`.
pub(crate) fn decode_json(output: &str, label: &str) -> Result<serde_json::Value, CommandError> {
    serde_json::from_str(output)
        .map_err(|error| CommandError(format!("{label} returned invalid JSON: {error}")))
}

/// Captured output of a finished child process.
#[derive(Debug)]
pub(crate) struct CommandOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandOutput {
    /// `result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"`.
    pub fn failure_message(&self) -> String {
        let stderr = self.stderr.trim();
        if !stderr.is_empty() {
            return stderr.to_string();
        }
        let stdout = self.stdout.trim();
        if !stdout.is_empty() {
            return stdout.to_string();
        }
        format!("exit {}", self.code)
    }
}

/// Run a command to completion with a timeout, capturing text output.
///
/// `std::process::Command` has no timeout, so this wraps `wait-timeout` and
/// pumps stdin/stdout/stderr on threads to avoid pipe deadlocks. The returned
/// error is the bare failure description; callers add their own prefix.
pub(crate) fn run_with_timeout(
    command: &mut Command,
    input: Option<&str>,
    timeout: Duration,
) -> Result<CommandOutput, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;

    let stdin_handle = if let Some(text) = input {
        let mut stdin = child.stdin.take();
        let text = text.to_string();
        Some(std::thread::spawn(move || {
            if let Some(mut pipe) = stdin.take() {
                // A closed pipe just means the child finished early.
                let _ = pipe.write_all(text.as_bytes());
            }
        }))
    } else {
        None
    };

    let mut stdout_pipe = child.stdout.take();
    let stdout_handle = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = stdout_pipe.take() {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    });
    let mut stderr_pipe = child.stderr.take();
    let stderr_handle = std::thread::spawn(move || {
        let mut buffer = Vec::new();
        if let Some(mut pipe) = stderr_pipe.take() {
            let _ = pipe.read_to_end(&mut buffer);
        }
        buffer
    });

    let status = match child.wait_timeout(timeout) {
        Ok(Some(status)) => status,
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "command timed out after {} seconds",
                timeout.as_secs()
            ));
        }
        Err(error) => return Err(error.to_string()),
    };

    let stdout = stdout_handle.join().unwrap_or_default();
    let stderr = stderr_handle.join().unwrap_or_default();
    if let Some(handle) = stdin_handle {
        let _ = handle.join();
    }

    Ok(CommandOutput {
        code: status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Publishes Nostr profile events; implemented by [`NostrTools`].
///
/// Injection point for profile publishing tests and alternate implementations.
pub trait ProfilePublisher {
    fn publish_profile(
        &self,
        relay_url: &str,
        private_key: &str,
        name: &str,
        about: &str,
        picture: Option<&str>,
    ) -> Result<(), CommandError>;

    fn publish_agent_profile(
        &self,
        relay_url: &str,
        private_key: &str,
        content: &serde_json::Value,
    ) -> Result<(), CommandError>;
}

/// Uploads files to the relay; implemented by [`BuzzClient`].
///
/// Injection point for file upload tests and alternate implementations.
pub trait FileUploader {
    fn upload_file(&self, path: &std::path::Path) -> Result<serde_json::Value, CommandError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_with_timeout_captures_output_and_feeds_stdin() {
        let mut command = Command::new("sh");
        command.args(["-c", "cat; echo oops >&2"]);
        let output = run_with_timeout(&mut command, Some("hello"), Duration::from_secs(5))
            .expect("command runs");
        assert_eq!(output.code, 0);
        assert_eq!(output.stdout, "hello");
        assert_eq!(output.stderr.trim(), "oops");
    }

    #[test]
    fn run_with_timeout_kills_overrunning_commands() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 30"]);
        let error = run_with_timeout(&mut command, None, Duration::from_millis(200))
            .expect_err("command times out");
        assert!(error.contains("timed out"));
    }

    #[test]
    fn failure_message_prefers_stderr() {
        let output = CommandOutput {
            code: 3,
            stdout: " out \n".to_string(),
            stderr: " err \n".to_string(),
        };
        assert_eq!(output.failure_message(), "err");
        let output = CommandOutput {
            code: 3,
            stdout: " out \n".to_string(),
            stderr: String::new(),
        };
        assert_eq!(output.failure_message(), "out");
        let output = CommandOutput {
            code: 3,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert_eq!(output.failure_message(), "exit 3");
    }
}
