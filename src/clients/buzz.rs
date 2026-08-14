//! Buzz CLI subprocess client.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use super::{decode_json, err, run_with_timeout, CommandError, FileUploader};

const BUZZ_ROLES: [&str; 5] = ["owner", "admin", "member", "guest", "bot"];

/// Truthiness for JSON values returned by Buzz.
fn json_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|number| number != 0.0).unwrap_or(false),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Thin wrapper around the Buzz command line interface.
#[derive(Debug, Clone)]
pub struct BuzzClient {
    pub binary: String,
    pub relay_url: String,
    pub private_key: String,
    pub auth_tag: Option<String>,
}

impl BuzzClient {
    pub fn new(
        binary: impl Into<String>,
        relay_url: impl Into<String>,
        private_key: impl Into<String>,
        auth_tag: Option<String>,
    ) -> Self {
        BuzzClient {
            binary: binary.into(),
            relay_url: relay_url.into(),
            private_key: private_key.into(),
            auth_tag,
        }
    }

    /// Environment variables the child process needs, plus variables to drop.
    ///
    /// The private key only ever travels here, never in argv.
    fn env_updates(&self) -> (Vec<(String, String)>, Vec<String>) {
        let mut sets = vec![
            ("BUZZ_RELAY_URL".to_string(), self.relay_url.clone()),
            ("BUZZ_PRIVATE_KEY".to_string(), self.private_key.clone()),
        ];
        let mut removals = Vec::new();
        match &self.auth_tag {
            Some(auth_tag) if !auth_tag.is_empty() => {
                sets.push(("BUZZ_AUTH_TAG".to_string(), auth_tag.clone()));
            }
            _ => removals.push("BUZZ_AUTH_TAG".to_string()),
        }
        (sets, removals)
    }

    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(&self.binary);
        command.args(args);
        let (sets, removals) = self.env_updates();
        for (key, value) in sets {
            command.env(key, value);
        }
        for key in removals {
            command.env_remove(key);
        }
        command
    }

    fn run(
        &self,
        args: &[String],
        input_text: Option<&str>,
        timeout: u64,
    ) -> Result<Value, CommandError> {
        let mut command = self.command(args);
        let output = run_with_timeout(&mut command, input_text, Duration::from_secs(timeout))
            .map_err(|error| CommandError(format!("failed to run Buzz CLI: {error}")))?;
        if output.code != 0 {
            let mut message = output.failure_message();
            // Buzz reports structured errors on stderr; lift the message out.
            if let Ok(parsed) = serde_json::from_str::<Value>(&message) {
                if parsed.is_object() {
                    // `parsed.get("message") or parsed.get("error") or message`
                    let lifted = ["message", "error"]
                        .iter()
                        .filter_map(|key| parsed.get(key))
                        .find(|value| json_truthy(value));
                    if let Some(value) = lifted {
                        message = match value {
                            Value::String(text) => text.clone(),
                            other => other.to_string(),
                        };
                    }
                }
            }
            return err(format!("Buzz command failed: {message}"));
        }
        decode_json(&output.stdout, "Buzz")
    }

    /// Pure argv/env for `upload file` (test hook for secret-safety checks).
    pub fn build_upload_command(&self, path: &Path) -> (Vec<String>, Vec<(String, String)>) {
        let args = vec![
            self.binary.clone(),
            "upload".to_string(),
            "file".to_string(),
            "--file".to_string(),
            path.to_string_lossy().into_owned(),
        ];
        let (sets, _removals) = self.env_updates();
        (args, sets)
    }

    fn as_object(result: Value) -> Value {
        if result.is_object() {
            result
        } else {
            Value::Object(Default::default())
        }
    }

    fn as_array(result: Value) -> Vec<Value> {
        match result {
            Value::Array(items) => items,
            _ => Vec::new(),
        }
    }

    pub fn list_channels(&self) -> Result<Vec<Value>, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "list".to_string(),
                "--limit".to_string(),
                "500".to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_array(result))
    }

    pub fn create_channel(
        &self,
        name: &str,
        channel_type: &str,
        visibility: &str,
        description: &str,
    ) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "create".to_string(),
                "--name".to_string(),
                name.to_string(),
                "--type".to_string(),
                channel_type.to_string(),
                "--visibility".to_string(),
                visibility.to_string(),
                "--description".to_string(),
                description.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    pub fn get_channel(&self, channel_id: &str) -> Result<Value, CommandError> {
        self.run(
            &[
                "channels".to_string(),
                "get".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
            ],
            None,
            30,
        )
    }

    pub fn update_channel(
        &self,
        channel_id: &str,
        name: &str,
        description: &str,
    ) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "update".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
                "--name".to_string(),
                name.to_string(),
                "--description".to_string(),
                description.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    pub fn archive_channel(&self, channel_id: &str) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "archive".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    /// Archive once, treating Buzz's explicit retry response as success. The
    /// current channel projection does not expose archival state, so checking
    /// `channels get` cannot make this operation idempotent.
    pub fn archive_channel_idempotent(&self, channel_id: &str) -> Result<(), CommandError> {
        match self.archive_channel(channel_id) {
            Ok(_) => Ok(()),
            Err(error) if error.0.to_lowercase().contains("already archived") => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub fn unarchive_channel(&self, channel_id: &str) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "unarchive".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    /// Retry-safe counterpart to [`Self::archive_channel_idempotent`].
    pub fn unarchive_channel_idempotent(&self, channel_id: &str) -> Result<(), CommandError> {
        match self.unarchive_channel(channel_id) {
            Ok(_) => Ok(()),
            Err(error) => {
                let message = error.0.to_lowercase();
                if message.contains("not archived")
                    || message.contains("already active")
                    || message.contains("already unarchived")
                {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    pub fn members(&self, channel_id: &str) -> Result<Vec<Value>, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "members".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_array(result))
    }

    pub fn add_member(
        &self,
        channel_id: &str,
        pubkey: &str,
        role: &str,
    ) -> Result<Value, CommandError> {
        if !BUZZ_ROLES.contains(&role) {
            return err(format!("invalid Buzz channel role: {role}"));
        }
        let result = self.run(
            &[
                "channels".to_string(),
                "add-member".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
                "--pubkey".to_string(),
                pubkey.to_string(),
                "--role".to_string(),
                role.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    pub fn remove_member(&self, channel_id: &str, pubkey: &str) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "channels".to_string(),
                "remove-member".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
                "--pubkey".to_string(),
                pubkey.to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    /// Archive this client's own generated identity through Buzz's NIP-IA
    /// control plane. Deprovisioning never invokes this for imported keys.
    pub fn archive_identity(&self, pubkey: &str) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "agents".to_string(),
                "archive".to_string(),
                pubkey.to_string(),
                "--reason".to_string(),
                "retired".to_string(),
                "--content".to_string(),
                "Deprovisioned by buzzr".to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_object(result))
    }

    pub fn archived_identities(&self) -> Result<Vec<String>, CommandError> {
        let result = self.run(&["agents".to_string(), "archived".to_string()], None, 30)?;
        Ok(result
            .get("archived")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Upload a file to the relay media endpoint (long timeout).
    pub fn upload_file(&self, path: &Path) -> Result<Value, CommandError> {
        let (argv, _env) = self.build_upload_command(path);
        let result = self.run(&argv[1..], None, 150)?;
        Ok(Self::as_object(result))
    }

    pub fn set_profile(
        &self,
        name: &str,
        about: &str,
        avatar: Option<&str>,
    ) -> Result<Value, CommandError> {
        let mut args = vec![
            "users".to_string(),
            "set-profile".to_string(),
            "--name".to_string(),
            name.to_string(),
            "--about".to_string(),
            about.to_string(),
        ];
        if let Some(avatar) = avatar {
            if !avatar.is_empty() {
                args.push("--avatar".to_string());
                args.push(avatar.to_string());
            }
        }
        let result = self.run(&args, None, 30)?;
        Ok(Self::as_object(result))
    }

    pub fn messages(&self, channel_id: &str, since: i64) -> Result<Vec<Value>, CommandError> {
        let result = self.run(
            &[
                "messages".to_string(),
                "get".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
                "--since".to_string(),
                since.to_string(),
                "--limit".to_string(),
                "200".to_string(),
            ],
            None,
            30,
        )?;
        Ok(Self::as_array(result))
    }

    /// Reply to a message; the content goes over stdin ("--content -").
    pub fn send_reply(
        &self,
        channel_id: &str,
        event_id: &str,
        content: &str,
    ) -> Result<Value, CommandError> {
        let result = self.run(
            &[
                "messages".to_string(),
                "send".to_string(),
                "--channel".to_string(),
                channel_id.to_string(),
                "--reply-to".to_string(),
                event_id.to_string(),
                "--content".to_string(),
                "-".to_string(),
            ],
            Some(content),
            30,
        )?;
        Ok(Self::as_object(result))
    }
}

impl FileUploader for BuzzClient {
    fn upload_file(&self, path: &Path) -> Result<Value, CommandError> {
        BuzzClient::upload_file(self, path)
    }
}
