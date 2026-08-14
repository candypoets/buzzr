//! Bridge daemon: topology reconciliation and mention routing.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde_json::{json, Value};

use crate::clients::{BuzzClient, CommandError, HerdrClient};
use crate::config::{load_config, Config};
use crate::provisioning::provision_local;
use crate::state::{
    ensure_private_directory, open_private_lock, runtime_directory, write_private_file, StateStore,
};
use crate::sync::reconcile;
use crate::topology::{build_topology, mentioned_pubkeys, AgentBinding, Topology};

pub const READY_STATES: [&str; 2] = ["idle", "done"];

fn err<T>(message: impl Into<String>) -> Result<T, CommandError> {
    Err(CommandError(message.into()))
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn monotonic_now() -> Instant {
    Instant::now()
}

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_signal(_signal: libc::c_int) {
    RUNNING.store(false, Ordering::SeqCst);
}

/// Install SIGTERM/SIGINT handlers that ask the daemon or dashboard loop to
/// stop, and reset the flag for a fresh run.
pub fn begin_signal_handling() {
    RUNNING.store(true, Ordering::SeqCst);
    unsafe {
        let handler = handle_signal as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

/// Whether the loop should keep going (no SIGTERM/SIGINT received yet).
pub fn still_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Sleep for `duration`, waking at least every 250ms to honor a stop request.
pub fn sleep_interruptible(duration: Duration) {
    let deadline = monotonic_now() + duration;
    while still_running() {
        let now = monotonic_now();
        if now >= deadline {
            break;
        }
        std::thread::sleep(deadline.duration_since(now).min(Duration::from_millis(250)));
    }
}

/// Read `n` random bytes from /dev/urandom (secrets.token_bytes).
fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buffer = vec![0u8; n];
    let mut file = fs::File::open("/dev/urandom").expect("/dev/urandom is available");
    file.read_exact(&mut buffer)
        .expect("/dev/urandom is readable");
    buffer
}

/// `secrets.token_urlsafe(nbytes)`: base64url without padding.
fn token_urlsafe(nbytes: usize) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = random_bytes(nbytes);
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let value = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(value >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(value >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(value >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[value as usize & 0x3f] as char);
        }
    }
    out
}

/// `uuid.uuid4().hex` equivalent: 32 lowercase hex characters.
fn random_hex_id() -> String {
    hex::encode(random_bytes(16))
}

/// Shell-quote the path and token shapes used in the reply command.
fn shlex_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "@%_+=:,./-".contains(c))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

/// Integer conversion for JSON scalars that appear in state.
fn json_int(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().map(|v| v as i64))
            .or_else(|| number.as_f64().map(|v| v as i64)),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    }
}

/// Stable string conversion for event scalar fields.
fn json_str(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

/// Convert a required context field to a string, returning its quoted key when
/// missing.
fn required_str(context: &Value, key: &str) -> Result<String, String> {
    match context.get(key) {
        Some(value) => Ok(json_str(Some(value))),
        None => Err(crate::config::quoted_repr(key)),
    }
}

/// `_author_allowed`: who may trigger inbound routing.
pub fn author_allowed(config: &Config, author: &str) -> bool {
    let mode = config.bridge.respond_to.as_str();
    let author = author.to_lowercase();
    if mode == "anyone" {
        return true;
    }
    if mode == "nobody" {
        return false;
    }
    let owner = config.owner_public_key().unwrap_or_default();
    if mode == "owner-only" {
        return !owner.is_empty() && author == owner;
    }
    let mut allowed: std::collections::HashSet<String> = config
        .bridge
        .respond_to_allowlist
        .iter()
        .map(|value| value.to_lowercase())
        .collect();
    if !owner.is_empty() {
        allowed.insert(owner);
    }
    allowed.contains(&author)
}

pub struct BridgeService {
    pub config: Config,
    pub store: StateStore,
    pub plugin_root: PathBuf,
    pub config_path: Option<PathBuf>,
    herdr: HerdrClient,
    pub runtime_dir: PathBuf,
    pub outbox_dir: PathBuf,
}

impl BridgeService {
    pub fn new(
        config: Config,
        store: StateStore,
        plugin_root: PathBuf,
        config_path: Option<PathBuf>,
    ) -> Result<Self, CommandError> {
        Self::with_runtime_dir(config, store, plugin_root, config_path, runtime_directory())
    }

    /// Same as [`BridgeService::new`] with an explicit runtime directory.
    pub fn with_runtime_dir(
        config: Config,
        store: StateStore,
        plugin_root: PathBuf,
        config_path: Option<PathBuf>,
        runtime_dir: PathBuf,
    ) -> Result<Self, CommandError> {
        let io = |error: std::io::Error| CommandError(error.to_string());
        ensure_private_directory(&runtime_dir).map_err(io)?;
        let outbox_dir = runtime_dir.join("outbox");
        ensure_private_directory(&outbox_dir).map_err(io)?;
        let herdr = HerdrClient::new(config.bridge.herdr_bin.clone());
        Ok(BridgeService {
            config,
            store,
            plugin_root,
            config_path,
            herdr,
            runtime_dir,
            outbox_dir,
        })
    }

    fn identity_client(&self, identity_id: &str) -> Result<Option<BuzzClient>, CommandError> {
        let (private_key, auth_tag) = self
            .config
            .identity_credentials(identity_id)
            .map_err(|error| CommandError(error.to_string()))?;
        match private_key {
            Some(private_key) if !private_key.is_empty() => Ok(Some(BuzzClient::new(
                self.config.bridge.buzz_bin.clone(),
                self.config.bridge.relay_url.clone(),
                private_key,
                auth_tag,
            ))),
            _ => Ok(None),
        }
    }

    /// The credential-free reply command handed to the agent.
    pub fn reply_command(&self, token: &str) -> String {
        let executable = self.plugin_root.join("bin").join("buzzr");
        format!(
            "printf '%s' '<your reply>' | {} reply --token {} --content -",
            shlex_quote(&executable.to_string_lossy()),
            shlex_quote(token)
        )
    }

    fn dispatch(&self, binding: &AgentBinding, event: &Value, state: &mut Value) -> bool {
        let token = token_urlsafe(24);
        let event_id = json_str(event.get("id"));
        let channel_id = state
            .get("channels")
            .and_then(|channels| channels.get(binding.workspace_id.as_str()))
            .filter(|channel| channel.is_object())
            .and_then(|channel| channel.get("channel_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let (channel_id, identity_id) = match (channel_id, binding.identity_id.clone()) {
            (Some(channel_id), Some(identity_id)) if !identity_id.is_empty() => {
                (channel_id, identity_id)
            }
            _ => return false,
        };
        state["reply_contexts"][token.clone()] = json!({
            "identity_id": identity_id,
            "channel_id": channel_id,
            "event_id": event_id,
            "workspace_id": binding.workspace_id,
            "pane_id": binding.pane_id,
            "created_at": now_seconds(),
        });
        let content = json_str(event.get("content"));
        let author = json_str(event.get("pubkey"));
        let prompt = format!(
            "[Buzz bridge]\nSpace: {}\nBuzz channel: #{}\nBuzz event: {}\nAuthor pubkey: {}\n\n\
             {}\n\n\
             When you have a useful answer, you MUST publish it back to the originating \
             Buzz thread. Replace <your reply> and run exactly this local bridge command; \
             it does not expose Buzz credentials:\n{}",
            binding.workspace_label,
            binding.channel_name,
            event_id,
            author,
            content,
            self.reply_command(&token)
        );
        if self.herdr.prompt(&binding.pane_id, &prompt).is_err() {
            state
                .get_mut("reply_contexts")
                .and_then(Value::as_object_mut)
                .map(|contexts| contexts.remove(&token));
            return false;
        }
        true
    }

    /// Process queued reply requests from `buzzr reply`.
    pub fn process_outbox(&self, state: &mut Value) -> Result<(), CommandError> {
        let mut requests: Vec<PathBuf> = fs::read_dir(&self.outbox_dir)
            .map(|entries| {
                entries
                    .filter_map(std::result::Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.file_name()
                            .map(|name| name.to_string_lossy().ends_with(".request.json"))
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();
        requests.sort();
        for request_path in requests {
            let result_path = request_path.with_file_name(
                request_path
                    .file_name()
                    .map(|name| {
                        name.to_string_lossy()
                            .replace(".request.json", ".result.json")
                    })
                    .unwrap_or_default(),
            );
            let result = self.fulfill_reply(&request_path, state);
            let temporary = result_path.with_extension("tmp");
            // A write failure escapes to the daemon boundary.
            let io = |error: std::io::Error| CommandError(error.to_string());
            fs::write(
                &temporary,
                serde_json::to_string(&result).unwrap_or_default(),
            )
            .map_err(io)?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(io)?;
            fs::rename(&temporary, &result_path).map_err(io)?;
            let _ = fs::remove_file(&request_path);
        }
        Ok(())
    }

    /// Build the result document for one reply request.
    fn fulfill_reply(&self, request_path: &Path, state: &mut Value) -> Value {
        match self.fulfill_reply_inner(request_path, state) {
            Ok(response) => json!({"ok": true, "response": response}),
            Err(error) => json!({"ok": false, "error": error}),
        }
    }

    fn fulfill_reply_inner(&self, request_path: &Path, state: &mut Value) -> Result<Value, String> {
        let text = fs::read_to_string(request_path).map_err(|error| error.to_string())?;
        let request: Value = serde_json::from_str(&text).map_err(|error| format!("{error}"))?;
        let token = json_str(request.get("token"));
        let content = json_str(request.get("content"));
        let context = state
            .get("reply_contexts")
            .and_then(|contexts| contexts.get(token.as_str()))
            .filter(|context| context.is_object())
            .cloned();
        let context = match context {
            Some(context) => context,
            None => return Err("reply token is unknown, expired, or already used".to_string()),
        };
        if content.trim().is_empty() {
            return Err("reply content is empty".to_string());
        }
        if content.len() > 65_535 {
            return Err("reply content exceeds 65,535 bytes".to_string());
        }
        let identity_id = required_str(&context, "identity_id")?;
        let client = self
            .identity_client(&identity_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| {
                format!(
                    "private key for identity {} is unavailable",
                    crate::config::quoted_repr(&identity_id)
                )
            })?;
        let response = client
            .send_reply(
                &required_str(&context, "channel_id")?,
                &required_str(&context, "event_id")?,
                &content,
            )
            .map_err(|error| error.to_string())?;
        state
            .get_mut("reply_contexts")
            .and_then(Value::as_object_mut)
            .map(|contexts| contexts.remove(&token));
        Ok(response)
    }

    fn poll_messages(&self, topology: &Topology, state: &mut Value) -> Result<(), CommandError> {
        let now = now_seconds();
        let mut processed: std::collections::HashSet<String> = state
            .get("processed")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        for binding in topology.agents() {
            let (identity_id, public_key) = match (&binding.identity_id, &binding.public_key) {
                (Some(identity_id), Some(public_key))
                    if !identity_id.is_empty() && !public_key.is_empty() =>
                {
                    (identity_id.clone(), public_key.clone())
                }
                _ => continue,
            };
            let channel_id = state
                .get("channels")
                .and_then(|channels| channels.get(binding.workspace_id.as_str()))
                .filter(|channel| channel.is_object())
                .and_then(|channel| channel.get("channel_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string);
            let channel_id = match channel_id {
                Some(channel_id) => channel_id,
                None => continue,
            };
            let client = match self.identity_client(&identity_id)? {
                Some(client) => client,
                None => continue,
            };
            let cursor_key = format!("{channel_id}:{identity_id}");
            let since = state
                .get("last_seen")
                .and_then(|last_seen| last_seen.get(cursor_key.as_str()))
                .map(|value| json_int(Some(value)).unwrap_or(now - 2))
                .unwrap_or(now - 2);
            let mut events = match client.messages(&channel_id, since) {
                Ok(events) => events,
                Err(_) => continue,
            };
            events.sort_by_key(|event| json_int(event.get("created_at")).unwrap_or(0));
            let mut newest = since;
            for event in &events {
                let created_at = json_int(event.get("created_at")).unwrap_or(0);
                newest = newest.max(created_at);
                let event_id = json_str(event.get("id"));
                if event_id.is_empty() || processed.contains(&event_id) {
                    continue;
                }
                if json_str(event.get("pubkey")).to_lowercase() == public_key {
                    processed.insert(event_id);
                    continue;
                }
                if !mentioned_pubkeys(event).contains(&public_key) {
                    continue;
                }
                if !author_allowed(&self.config, &json_str(event.get("pubkey"))) {
                    processed.insert(event_id);
                    continue;
                }
                let content = json_str(event.get("content")).trim().to_string();
                if content == "!cancel" {
                    let _ = self.herdr.interrupt(&binding.pane_id);
                    processed.insert(event_id);
                    continue;
                }
                if !READY_STATES.contains(&binding.status.as_str()) {
                    continue;
                }
                if self.dispatch(binding, event, state) {
                    processed.insert(event_id);
                }
            }
            state["last_seen"][cursor_key] = json!(newest);
        }
        let mut remaining: Vec<Value> = processed.into_iter().map(Value::String).collect();
        if remaining.len() > 5000 {
            remaining = remaining.split_off(remaining.len() - 5000);
        }
        state["processed"] = Value::Array(remaining);
        Ok(())
    }

    /// One daemon pass; errors are recorded in state by [`BridgeService::run`].
    fn pass(&mut self, last_message_poll: &mut Option<Instant>) -> Result<(), CommandError> {
        if let Some(config_path) = &self.config_path {
            self.config =
                load_config(config_path).map_err(|error| CommandError(error.to_string()))?;
            self.herdr = HerdrClient::new(self.config.bridge.herdr_bin.clone());
        }
        let snapshot = self.herdr.snapshot()?;
        let mut topology = build_topology(&snapshot, &self.config);
        if self.config.bridge.auto_provision_agents
            && topology
                .agents()
                .iter()
                .any(|agent| agent.identity_id.is_none())
        {
            let config_path = match &self.config_path {
                Some(config_path) => config_path.clone(),
                None => {
                    return err("automatic provisioning requires a persistent config path");
                }
            };
            let (config, refreshed, _report) =
                provision_local(&config_path, &snapshot, &self.store)
                    .map_err(|error| CommandError(error.to_string()))?;
            self.config = config;
            topology = refreshed;
        }
        reconcile(&self.config, &topology, &self.store, false)?;
        let routing_enabled = self.config.bridge.routing_enabled;
        let message_poll_seconds = self.config.bridge.message_poll_seconds;
        self.store
            .with_lock(|| -> Result<(), CommandError> {
                let mut state = self
                    .store
                    .load_strict()
                    .map_err(|error| CommandError(format!("cannot load state: {error}")))?;
                self.process_outbox(&mut state)?;
                let now = monotonic_now();
                let due = match last_message_poll {
                    Some(last) => now.duration_since(*last).as_secs_f64() >= message_poll_seconds,
                    None => true,
                };
                if routing_enabled && due {
                    self.poll_messages(&topology, &mut state)?;
                    *last_message_poll = Some(now);
                }
                state["last_error"] = Value::Null;
                self.store
                    .save(&state)
                    .map_err(|error| CommandError(format!("cannot save state: {error}")))?;
                Ok(())
            })
            .map_err(|error| CommandError(format!("cannot lock state: {error}")))??;
        Ok(())
    }

    /// Run the daemon loop until SIGTERM/SIGINT, holding the runtime lock.
    pub fn run(&mut self) -> Result<(), CommandError> {
        let io = |error: std::io::Error| CommandError(error.to_string());
        let lock_path = self.runtime_dir.join("daemon.lock");
        let pid_path = self.runtime_dir.join("daemon.pid");
        let stop_path = self.runtime_dir.join("stop.request");
        let lock = open_private_lock(&lock_path).map_err(io)?;
        lock.try_lock_exclusive()
            .map_err(|_| CommandError("buzzr daemon is already running".to_string()))?;
        let _ = fs::remove_file(&stop_path);
        write_private_file(&pid_path, format!("{}\n", std::process::id()).as_bytes())
            .map_err(io)?;
        begin_signal_handling();
        let result = self.run_loop();
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&stop_path);
        result
    }

    /// The poll loop body; errors in a pass are recorded and retried.
    fn run_loop(&mut self) -> Result<(), CommandError> {
        let mut last_message_poll: Option<Instant> = None;
        while still_running() && !self.runtime_dir.join("stop.request").exists() {
            if let Err(error) = self.pass(&mut last_message_poll) {
                let _ = self.store.with_lock(|| -> Result<(), CommandError> {
                    let mut state = self
                        .store
                        .load_strict()
                        .map_err(|error| CommandError(format!("cannot load state: {error}")))?;
                    state["last_error"] = json!(error.to_string());
                    self.store
                        .save(&state)
                        .map_err(|error| CommandError(format!("cannot save state: {error}")))?;
                    Ok(())
                });
            }
            let deadline =
                monotonic_now() + Duration::from_secs_f64(self.config.bridge.poll_seconds.max(0.0));
            while still_running()
                && !self.runtime_dir.join("stop.request").exists()
                && monotonic_now() < deadline
            {
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        Ok(())
    }
}

/// Queue a reply for the credential-owning daemon and wait for the result.
pub fn queue_reply(token: &str, content: &str, timeout: Duration) -> Result<Value, CommandError> {
    let io = |error: std::io::Error| CommandError(error.to_string());
    let runtime = runtime_directory();
    ensure_private_directory(&runtime).map_err(io)?;
    let outbox = runtime.join("outbox");
    ensure_private_directory(&outbox).map_err(io)?;
    let request_id = random_hex_id();
    let request_path = outbox.join(format!("{request_id}.request.json"));
    let result_path = outbox.join(format!("{request_id}.result.json"));
    let temporary = outbox.join(format!("{request_id}.tmp"));
    let body = serde_json::to_string(&json!({"token": token, "content": content}))
        .map_err(|error| CommandError(error.to_string()))?;
    fs::write(&temporary, body).map_err(io)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(io)?;
    fs::rename(&temporary, &request_path).map_err(io)?;
    let deadline = monotonic_now() + timeout;
    while monotonic_now() < deadline {
        if result_path.exists() {
            let text = fs::read_to_string(&result_path).map_err(io)?;
            let result: Value =
                serde_json::from_str(&text).map_err(|error| CommandError(error.to_string()))?;
            let _ = fs::remove_file(&result_path);
            return Ok(result);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    err("bridge daemon did not acknowledge the reply within 30 seconds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> Config {
        Config {
            bridge: crate::config::BridgeConfig {
                respond_to: "owner-only".to_string(),
                human_pubkey: Some("a".repeat(64)),
                ..crate::config::BridgeConfig::default()
            },
            identities: HashMap::new(),
            secrets: HashMap::new(),
        }
    }

    fn test_service(runtime_dir: &Path) -> BridgeService {
        fs::set_permissions(runtime_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let store = StateStore::new(runtime_dir.join("state"));
        BridgeService::with_runtime_dir(
            test_config(),
            store,
            PathBuf::from("/plugin"),
            None,
            runtime_dir.to_path_buf(),
        )
        .expect("service constructs")
    }

    #[test]
    fn token_urlsafe_has_expected_shape() {
        let token = token_urlsafe(24);
        assert_eq!(token.len(), 32);
        assert!(token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn shlex_quote_handles_supported_values() {
        assert_eq!(shlex_quote("/plain/path-1.2"), "/plain/path-1.2");
        assert_eq!(shlex_quote(""), "''");
        assert_eq!(shlex_quote("a b"), "'a b'");
        assert_eq!(shlex_quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn author_allowed_modes() {
        let config = test_config();
        assert!(author_allowed(&config, &"A".repeat(64)));
        assert!(!author_allowed(&config, &"b".repeat(64)));

        let mut anyone = test_config();
        anyone.bridge.respond_to = "anyone".to_string();
        assert!(author_allowed(&anyone, "whatever"));

        let mut nobody = test_config();
        nobody.bridge.respond_to = "nobody".to_string();
        assert!(!author_allowed(&nobody, &"a".repeat(64)));

        let mut allowlist = test_config();
        allowlist.bridge.respond_to = "allowlist".to_string();
        allowlist.bridge.respond_to_allowlist = vec!["C".repeat(64)];
        assert!(author_allowed(&allowlist, &"a".repeat(64))); // owner always allowed
        assert!(author_allowed(&allowlist, &"c".repeat(64)));
        assert!(!author_allowed(&allowlist, &"d".repeat(64)));
    }

    #[test]
    fn reply_command_mentions_binary_and_token() {
        let directory = tempfile::tempdir().unwrap();
        let service = test_service(directory.path());
        let command = service.reply_command("tok-1");
        assert!(command.starts_with("printf '%s' '<your reply>' | /plugin/bin/buzzr reply"));
        assert!(command.contains("--token tok-1 --content -"));
    }

    #[test]
    fn process_outbox_rejects_unknown_token() {
        let directory = tempfile::tempdir().unwrap();
        let service = test_service(directory.path());
        let mut state = crate::state::default_state();
        let request_path = service.outbox_dir.join("req1.request.json");
        fs::write(&request_path, r#"{"token": "nope", "content": "hi"}"#).unwrap();
        service.process_outbox(&mut state).unwrap();
        assert!(!request_path.exists());
        let result: Value = serde_json::from_str(
            &fs::read_to_string(service.outbox_dir.join("req1.result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(result["ok"], json!(false));
        assert_eq!(
            result["error"],
            json!("reply token is unknown, expired, or already used")
        );
    }

    #[test]
    fn process_outbox_rejects_empty_content() {
        let directory = tempfile::tempdir().unwrap();
        let service = test_service(directory.path());
        let mut state = crate::state::default_state();
        state["reply_contexts"]["tok"] = json!({
            "identity_id": "sol",
            "channel_id": "c1",
            "event_id": "e1",
        });
        let request_path = service.outbox_dir.join("req2.request.json");
        fs::write(&request_path, r#"{"token": "tok", "content": "   "}"#).unwrap();
        service.process_outbox(&mut state).unwrap();
        let result: Value = serde_json::from_str(
            &fs::read_to_string(service.outbox_dir.join("req2.result.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"ok": false, "error": "reply content is empty"})
        );
        // The context survives a failed reply.
        assert!(state["reply_contexts"].get("tok").is_some());
    }
}
