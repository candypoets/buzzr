//! Herdr CLI subprocess client.

use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use super::{decode_json, err, run_with_timeout, CommandError};

/// Thin wrapper around the Herdr command line interface.
#[derive(Debug, Clone)]
pub struct HerdrClient {
    pub binary: String,
}

impl HerdrClient {
    pub fn new(binary: impl Into<String>) -> Self {
        HerdrClient {
            binary: binary.into(),
        }
    }

    fn run(&self, args: &[&str], timeout: u64) -> Result<Value, CommandError> {
        let mut command = Command::new(&self.binary);
        command.args(args);
        let output = run_with_timeout(&mut command, None, Duration::from_secs(timeout))
            .map_err(|error| CommandError(format!("failed to run Herdr: {error}")))?;
        if output.code != 0 {
            return err(format!(
                "Herdr command failed: {}",
                output.failure_message()
            ));
        }
        decode_json(&output.stdout, "Herdr")
    }

    /// Fetch the full workspace/tab/agent snapshot.
    pub fn snapshot(&self) -> Result<Value, CommandError> {
        let response = self.run(&["api", "snapshot"], 30)?;
        match response
            .get("result")
            .and_then(|result| result.get("snapshot"))
        {
            Some(snapshot) => Ok(snapshot.clone()),
            None => err("Herdr snapshot response is missing result.snapshot"),
        }
    }

    /// Send a prompt to an agent pane.
    pub fn prompt(&self, pane_id: &str, text: &str) -> Result<(), CommandError> {
        self.run(&["agent", "prompt", pane_id, text], 15)?;
        Ok(())
    }

    /// Interrupt an agent pane with ctrl+c.
    pub fn interrupt(&self, pane_id: &str) -> Result<(), CommandError> {
        self.run(&["agent", "send-keys", pane_id, "ctrl+c"], 10)?;
        Ok(())
    }

    /// Start a manifest-declared plugin action through Herdr.
    pub fn invoke_plugin_action(
        &self,
        plugin_id: &str,
        action_id: &str,
    ) -> Result<(), CommandError> {
        self.run(
            &[
                "plugin", "action", "invoke", action_id, "--plugin", plugin_id,
            ],
            15,
        )?;
        Ok(())
    }
}
