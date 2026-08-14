//! Command line interface.
//!
//! Argument parsing is hand-rolled to keep the binary dependency-minimal.

use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::avatars::normalize_lexical;
use crate::clients::{BuzzClient, CommandError, HerdrClient};
use crate::config::{
    load_config, normalize_human_pubkey, update_bridge_settings, update_dotenv, Config, ConfigError,
};
use crate::lifecycle::{
    apply_deprovision, build_deprovision_plan, deactivate, render_deprovision_plan, stop_daemon,
    DeprovisionPlan, StopOutcome,
};
use crate::provisioning::{provision_local, resolve_identity_intents};
use crate::service::{
    begin_signal_handling, queue_reply, sleep_interruptible, still_running, BridgeService,
};
use crate::state::StateStore;
use crate::sync::{reconcile, refresh_profiles, SyncReport};
use crate::topology::{build_topology, Topology};

// --- errors ---------------------------------------------------------------

/// User-facing failures map to `error: {message}` on stderr with exit 1.
#[derive(Debug)]
pub enum CliError {
    Config(ConfigError),
    Command(CommandError),
    Io(std::io::Error),
    Value(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Config(error) => write!(f, "{error}"),
            CliError::Command(error) => write!(f, "{error}"),
            CliError::Io(error) => write!(f, "{error}"),
            CliError::Value(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ConfigError> for CliError {
    fn from(error: ConfigError) -> Self {
        CliError::Config(error)
    }
}

impl From<CommandError> for CliError {
    fn from(error: CommandError) -> Self {
        CliError::Command(error)
    }
}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        CliError::Io(error)
    }
}

// --- paths ----------------------------------------------------------------

/// Plugin root: `$HERDR_PLUGIN_ROOT`, else the installed executable's
/// grandparent, else the source checkout (see `crate::paths`).
pub fn plugin_root() -> PathBuf {
    crate::paths::plugin_root()
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// Expand a leading `~` against the current user's home directory.
fn expanduser(value: &str) -> PathBuf {
    if value == "~" || value.starts_with("~/") {
        if let Some(home) = nonempty_env("HOME") {
            let mut expanded = PathBuf::from(home);
            if value.len() > 2 {
                expanded.push(&value[2..]);
            }
            return expanded;
        }
    }
    PathBuf::from(value)
}

/// Expand `~`, normalize the path, and resolve existing symlinks.
fn resolve_path(value: &str) -> PathBuf {
    let mut resolved = expanduser(value);
    if !resolved.is_absolute() {
        if let Ok(cwd) = std::env::current_dir() {
            resolved = cwd.join(resolved);
        }
    }
    let resolved = normalize_lexical(&resolved);
    resolved.canonicalize().unwrap_or(resolved)
}

/// Config file resolution: flag > env > plugin config dir > plugin root.
pub fn config_path(argument: Option<&str>) -> PathBuf {
    if let Some(argument) = argument {
        return expanduser(argument);
    }
    if let Some(explicit) =
        nonempty_env("BUZZR_CONFIG").or_else(|| nonempty_env("HERDR_BUZZ_CONFIG"))
    {
        return expanduser(&explicit);
    }
    if let Some(config_dir) = nonempty_env("HERDR_PLUGIN_CONFIG_DIR") {
        return PathBuf::from(config_dir).join("config.toml");
    }
    plugin_root().join("config.toml")
}

/// State directory resolution: flag > env > plugin state dir > plugin root.
pub fn state_directory(argument: Option<&str>) -> PathBuf {
    if let Some(argument) = argument {
        return expanduser(argument);
    }
    if let Some(explicit) =
        nonempty_env("BUZZR_STATE_DIR").or_else(|| nonempty_env("HERDR_BUZZ_STATE_DIR"))
    {
        return expanduser(&explicit);
    }
    if let Some(state_dir) = nonempty_env("HERDR_PLUGIN_STATE_DIR") {
        return PathBuf::from(state_dir);
    }
    plugin_root().join(".state")
}

fn load_all(parsed: &Parsed) -> Result<(Config, StateStore, Topology), CliError> {
    let config = load_config(&config_path(parsed.config.as_deref()))?;
    let store = StateStore::new(state_directory(parsed.state_dir.as_deref()));
    let snapshot = HerdrClient::new(config.bridge.herdr_bin.clone()).snapshot()?;
    let topology = build_topology(&snapshot, &config);
    Ok((config, store, topology))
}

/// Create the generic safe template; returns true when it was created.
fn ensure_config(destination: &Path) -> Result<bool, CliError> {
    if let Some(parent) = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    if destination.exists() {
        return Ok(false);
    }
    fs::copy(plugin_root().join("config.example.toml"), destination)?;
    fs::set_permissions(destination, fs::Permissions::from_mode(0o600))?;
    Ok(true)
}

// --- rendering (pure) ------------------------------------------------------

/// `_credential_source`.
pub fn credential_source(config: &Config) -> String {
    if !config.bridge.secrets_files.is_empty() {
        return config
            .bridge
            .secrets_files
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
    }
    "inherited environment".to_string()
}

/// `_print_credential_summary`.
pub fn credential_summary(config: &Config) -> String {
    let (private_key, auth_tag) = config.bridge_credentials();
    let mut out = format!("Credential source: {}\n", credential_source(config));
    out.push_str(&format!(
        "Bridge signing key ({}): {}\n",
        config.bridge.bridge_private_key_env,
        if private_key.is_some() {
            "available"
        } else {
            "MISSING"
        }
    ));
    if let Some(auth_tag_env) = &config.bridge.bridge_auth_tag_env {
        out.push_str(&format!(
            "Delegation ({}): {}\n",
            auth_tag_env,
            if auth_tag.is_some() {
                "available"
            } else {
                "not set"
            }
        ));
    }
    out.push_str(&format!(
        "Human controller pubkey: {}\n",
        if config.human_public_key().is_some() {
            "available"
        } else {
            "MISSING"
        }
    ));
    out
}

/// `_topology_dict`.
pub fn topology_dict(topology: &Topology) -> Value {
    let spaces: Vec<Value> = topology
        .spaces
        .iter()
        .map(|space| {
            json!({
                "workspace_id": space.workspace_id,
                "space": space.workspace_label,
                "channel": space.channel_name,
                "agents": space.agents.iter().map(|agent| json!({
                    "label": agent.display_label,
                    "identity": agent.identity_id,
                    "runtime": agent.runtime,
                    "status": agent.status,
                    "pane_id": agent.pane_id,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "spaces": spaces,
        "warnings": topology.warnings,
    })
}

/// `_print_plan`.
pub fn render_plan(topology: &Topology) -> String {
    let mut out = format!(
        "Herdr → Buzz: {} Spaces, {} agents\n",
        topology.spaces.len(),
        topology.agents().len()
    );
    for space in &topology.spaces {
        out.push_str(&format!(
            "\n#{}  ({}, {})\n",
            space.channel_name, space.workspace_id, space.workspace_label
        ));
        if space.agents.is_empty() {
            out.push_str("  · no agents\n");
            continue;
        }
        for agent in &space.agents {
            let identity = agent.identity_id.as_deref().unwrap_or("UNMAPPED");
            out.push_str(&format!(
                "  · {} → {} [{}/{}] {}\n",
                agent.display_label, identity, agent.runtime, agent.status, agent.pane_id
            ));
        }
    }
    if !topology.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for warning in &topology.warnings {
            out.push_str(&format!("  ! {warning}\n"));
        }
    }
    out
}

/// `_print_report`.
pub fn render_report(report: &SyncReport) -> String {
    let mut out = String::from(if report.applied {
        "mode: APPLY\n"
    } else {
        "mode: PREVIEW\n"
    });
    if report.actions.is_empty() {
        out.push_str("  · already reconciled\n");
    } else {
        for action in &report.actions {
            out.push_str(&format!("  · {action}\n"));
        }
    }
    for warning in &report.warnings {
        out.push_str(&format!("  ! {warning}\n"));
    }
    out
}

/// The JSON document behind `buzzr status`.
pub fn status_payload(config: &Config, state: &Value, topology: &Topology) -> Value {
    let (bridge_key, _bridge_auth) = config.bridge_credentials();
    let object_len = |key: &str| -> usize {
        state
            .get(key)
            .and_then(Value::as_object)
            .map(serde_json::Map::len)
            .unwrap_or(0)
    };
    json!({
        "relay_url": config.bridge.relay_url,
        "sync_enabled": config.bridge.sync_enabled,
        "routing_enabled": config.bridge.routing_enabled,
        "bridge_credential_available": bridge_key.is_some(),
        "bridge_public_key_available": config
            .bridge
            .bridge_public_key
            .as_deref()
            .map(|value| !value.is_empty())
            .unwrap_or(false),
        "human_pubkey_available": config.human_public_key().is_some(),
        "credential_source": credential_source(config),
        "spaces": topology.spaces.len(),
        "agents": topology.agents().len(),
        "mapped_agents": topology
            .agents()
            .iter()
            .filter(|agent| agent.identity_id.is_some())
            .count(),
        "channels": state.get("channels").cloned().unwrap_or_else(|| json!({})),
        "profiled_identities": object_len("identity_profiles"),
        "uploaded_avatars": object_len("avatar_uploads"),
        "last_reconcile_at": state.get("last_reconcile_at").cloned().unwrap_or(Value::Null),
        "last_error": state.get("last_error").cloned().unwrap_or(Value::Null),
        "warnings": topology.warnings,
    })
}

/// The human-readable rendering of [`status_payload`].
pub fn render_status_text(payload: &Value) -> String {
    let truthy = |key: &str| payload.get(key).and_then(Value::as_bool).unwrap_or(false);
    let number = |key: &str| payload.get(key).and_then(Value::as_i64).unwrap_or(0);
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let mut out = format!("Relay: {}\n", text("relay_url"));
    out.push_str(&format!("Credentials: {}\n", text("credential_source")));
    out.push_str(&format!(
        "Topology: {} Spaces, {} agents\n",
        number("spaces"),
        number("agents")
    ));
    out.push_str(&format!(
        "Mapped agents: {}/{}\n",
        number("mapped_agents"),
        number("agents")
    ));
    out.push_str(&format!(
        "Channel writes: {}\n",
        if truthy("sync_enabled") {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(
        "Message routing: {}\n",
        if truthy("routing_enabled") {
            "enabled"
        } else {
            "disabled"
        }
    ));
    out.push_str(&format!(
        "Bridge credential: {}\n",
        if truthy("bridge_credential_available") {
            "available"
        } else {
            "MISSING"
        }
    ));
    out.push_str(&format!(
        "Human pubkey: {}\n",
        if truthy("human_pubkey_available") {
            "available"
        } else {
            "MISSING"
        }
    ));
    let channels = payload
        .get("channels")
        .and_then(Value::as_object)
        .map(serde_json::Map::len)
        .unwrap_or(0);
    out.push_str(&format!("Known channels: {channels}\n"));
    out.push_str(&format!(
        "Managed profiles: {}\n",
        number("profiled_identities")
    ));
    out.push_str(&format!(
        "Uploaded avatars: {}\n",
        number("uploaded_avatars")
    ));
    if let Some(last_error) = payload.get("last_error").and_then(Value::as_str) {
        if !last_error.is_empty() {
            out.push_str(&format!("Last error: {last_error}\n"));
        }
    }
    if let Some(warnings) = payload.get("warnings").and_then(Value::as_array) {
        for warning in warnings {
            out.push_str(&format!("! {}\n", warning.as_str().unwrap_or_default()));
        }
    }
    out
}

/// The `[bridge]` updates implied by `configure` flags (pure mapping).
pub fn configure_updates(args: &ConfigureArgs) -> Vec<(String, Option<Value>)> {
    let mut updates: Vec<(String, Option<Value>)> = Vec::new();
    if let Some(relay) = &args.relay {
        updates.push(("relay_url".to_string(), Some(json!(relay))));
    }
    if args.environment {
        updates.push(("secrets_file".to_string(), None));
        updates.push(("secrets_files".to_string(), None));
    } else if let Some(secrets_file) = &args.secrets_file {
        let resolved = resolve_path(secrets_file);
        updates.push((
            "secrets_files".to_string(),
            Some(json!([resolved.to_string_lossy()])),
        ));
        updates.push(("secrets_file".to_string(), None));
    }
    if !args.private_key_env.is_empty() {
        updates.push((
            "bridge_private_key_env".to_string(),
            Some(json!(args.private_key_env)),
        ));
    }
    if !args.auth_tag_env.is_empty() {
        updates.push((
            "bridge_auth_tag_env".to_string(),
            Some(json!(args.auth_tag_env)),
        ));
    }
    if let Some(owner_pubkey) = &args.owner_pubkey {
        let owner_pubkey =
            normalize_human_pubkey(owner_pubkey).unwrap_or_else(|_| owner_pubkey.to_lowercase());
        updates.push(("human_pubkey".to_string(), Some(json!(owner_pubkey))));
    }
    updates
}

fn apply_configuration(destination: &Path, args: &ConfigureArgs) -> Result<Config, CliError> {
    ensure_config(destination)?;
    let updates = configure_updates(args);
    if !updates.is_empty() {
        update_bridge_settings(destination, &updates)?;
    }
    Ok(load_config(destination)?)
}

// --- subcommands -----------------------------------------------------------

fn cmd_init(parsed: &Parsed, force: bool) -> Result<i32, CliError> {
    let destination = config_path(parsed.config.as_deref());
    if destination.exists() && !force {
        eprintln!("configuration already exists: {}", destination.display());
        return Ok(1);
    }
    if force && destination.exists() {
        fs::remove_file(&destination)?;
    }
    ensure_config(&destination)?;
    println!("{}", destination.display());
    Ok(0)
}

fn cmd_configure(parsed: &Parsed, args: &ConfigureArgs) -> Result<i32, CliError> {
    let destination = config_path(parsed.config.as_deref());
    let config = apply_configuration(&destination, args)?;
    println!("Configured: {}", destination.display());
    println!("Relay: {}", config.bridge.relay_url);
    print!("{}", credential_summary(&config));
    println!("Channel writes and message routing were not enabled.");
    Ok(0)
}

/// Shared bootstrap body used by `bootstrap` and the interactive `setup`.
fn run_bootstrap(parsed: &Parsed, args: &BootstrapArgs) -> Result<i32, CliError> {
    let destination = config_path(parsed.config.as_deref());
    ensure_config(&destination)?;

    let current = load_config(&destination).ok();
    let human_pubkey = args
        .human_pubkey
        .clone()
        .filter(|value| !value.is_empty())
        .or_else(|| current.as_ref().and_then(Config::human_public_key));
    let human_pubkey = match human_pubkey {
        Some(human_pubkey) => normalize_human_pubkey(&human_pubkey)?,
        None => {
            return Err(
                ConfigError("--human-pubkey is required on first bootstrap".to_string()).into(),
            );
        }
    };

    let relay_url = args
        .relay
        .clone()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            current
                .as_ref()
                .map(|current| current.bridge.relay_url.clone())
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| ConfigError("--relay is required on first bootstrap".to_string()))?;

    let managed = match &args.managed_secrets_file {
        Some(path) => resolve_path(path),
        None => {
            let fallback = destination
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .join("secrets.env");
            resolve_path(&fallback.to_string_lossy())
        }
    };
    // Create the destination before pointing config.toml at it. Empty is valid.
    update_dotenv(&managed, &[])?;

    let managed_str = managed.to_string_lossy().into_owned();
    let mut secret_paths: Vec<String> = Vec::new();
    if let Some(current) = &current {
        for path in &current.bridge.secrets_files {
            let resolved = normalize_lexical(path);
            let resolved = resolved.canonicalize().unwrap_or(resolved);
            let resolved = resolved.to_string_lossy().into_owned();
            if resolved != managed_str && !secret_paths.contains(&resolved) {
                secret_paths.push(resolved);
            }
        }
    }
    if let Some(agent_secrets) = &args.agent_secrets_file {
        let resolved = resolve_path(agent_secrets).to_string_lossy().into_owned();
        if resolved != managed_str && !secret_paths.contains(&resolved) {
            secret_paths.push(resolved);
        }
    }
    // The managed file is last, so generated values win over legacy variables.
    secret_paths.push(managed_str.clone());

    let compose_default = current
        .as_ref()
        .and_then(|current| current.bridge.compose_file.as_ref())
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| "~/buzz/docker-compose.yml".to_string());
    let compose_file = resolve_path(args.compose_file.as_deref().unwrap_or(&compose_default));

    let mut updates: Vec<(String, Option<Value>)> = vec![
        ("human_pubkey".to_string(), Some(json!(human_pubkey))),
        ("relay_url".to_string(), Some(json!(relay_url))),
        (
            "compose_file".to_string(),
            Some(json!(compose_file.to_string_lossy())),
        ),
        ("managed_secrets_file".to_string(), Some(json!(managed_str))),
        ("secrets_files".to_string(), Some(json!(secret_paths))),
        ("secrets_file".to_string(), None),
        (
            "bridge_private_key_env".to_string(),
            Some(json!("BUZZR_BRIDGE_PRIVATE_KEY")),
        ),
        ("bridge_auth_tag_env".to_string(), None),
        ("owner_private_key_env".to_string(), None),
        ("owner_auth_tag_env".to_string(), None),
        ("owner_pubkey".to_string(), None),
        // Enable only after provisioning and the first reconcile both succeed.
        ("sync_enabled".to_string(), Some(json!(false))),
        ("routing_enabled".to_string(), Some(json!(false))),
        ("auto_provision_agents".to_string(), Some(json!(false))),
    ];
    if let Some(buzz_bin) = &args.buzz_bin {
        updates.push((
            "buzz_bin".to_string(),
            Some(json!(resolve_path(buzz_bin).to_string_lossy())),
        ));
    }
    if args.nak_bin.is_some() {
        eprintln!(
            "warning: --nak-bin is deprecated and ignored; buzzr publishes to Nostr natively"
        );
    }
    update_bridge_settings(&destination, &updates)?;

    let config = load_config(&destination)?;
    let snapshot = HerdrClient::new(config.bridge.herdr_bin.clone()).snapshot()?;
    let store = StateStore::new(state_directory(parsed.state_dir.as_deref()));
    let (config, topology, provision) = provision_local(&destination, &snapshot, &store)?;
    let report = reconcile(&config, &topology, &store, true)?;
    update_bridge_settings(
        &destination,
        &[
            ("sync_enabled".to_string(), Some(json!(true))),
            ("routing_enabled".to_string(), Some(json!(true))),
            ("auto_provision_agents".to_string(), Some(json!(true))),
        ],
    )?;

    println!("Configured: {}", destination.display());
    println!("Relay: {}", config.bridge.relay_url);
    println!("Human controller: {human_pubkey}");
    println!(
        "Bridge identity: {}",
        config.bridge.bridge_public_key.as_deref().unwrap_or("None")
    );
    println!(
        "Provisioned: {} new agent identities, {} new relay members",
        provision.identities_created.len(),
        provision.relay_members_added
    );
    print!("{}", render_report(&report));
    println!("Channel sync, automatic agent provisioning, and mention routing are enabled.");
    Ok(0)
}

fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

/// `_ask`: prompt with an optional default, returning the stripped answer.
fn ask(prompt: &str, default: Option<&str>) -> Result<String, CliError> {
    let suffix = match default {
        Some(default) if !default.is_empty() => format!(" [{default}]"),
        _ => String::new(),
    };
    print!("{prompt}{suffix}: ");
    std::io::stdout().flush()?;
    let mut answer = String::new();
    let read = std::io::stdin().read_line(&mut answer)?;
    if read == 0 {
        return Err(CliError::Value("EOF when reading a line".to_string()));
    }
    let answer = answer.trim();
    if answer.is_empty() {
        Ok(default.unwrap_or("").to_string())
    } else {
        Ok(answer.to_string())
    }
}

/// Human-facing handoff after the first successful provisioning run.
pub fn setup_completion_text(plugin_id: &str, daemon_started: bool) -> String {
    let daemon = if daemon_started {
        "Routing daemon: started.\n".to_string()
    } else {
        format!(
            "Routing daemon: not started automatically outside a Herdr plugin pane.\n\
             Start it with: herdr plugin action invoke start --plugin {plugin_id}\n"
        )
    };
    format!(
        "\nSetup complete.\n{daemon}\
         Next: open Buzz, enter a mirrored channel, and @mention one of your agents.\n"
    )
}

fn cmd_setup(parsed: &Parsed) -> Result<i32, CliError> {
    if !stdin_is_tty() {
        return Err(ConfigError(
            "setup needs an interactive terminal; open the plugin's Setup overlay or use \
             `buzzr bootstrap --help`"
                .to_string(),
        )
        .into());
    }
    let destination = config_path(parsed.config.as_deref());
    ensure_config(&destination)?;
    let current = load_config(&destination).ok();
    let default_relay = current
        .as_ref()
        .map(|current| current.bridge.relay_url.clone())
        .filter(|value| !value.is_empty())
        .or_else(|| nonempty_env("BUZZ_RELAY_URL"));

    println!("buzzr setup");
    println!("Your human private key is never requested or used.\n");
    let relay = ask("Buzz relay URL", default_relay.as_deref())?;
    let current_human = current
        .as_ref()
        .and_then(|current| current.human_public_key());
    let human_pubkey = ask(
        "Your Buzz public key (npub or 64 hex)",
        current_human.as_deref(),
    )?;
    let compose_file = ask("Buzz docker-compose.yml", Some("~/buzz/docker-compose.yml"))?;
    let agent_secrets = ask(
        "Existing agent dotenv (optional; Enter to generate every missing identity)",
        None,
    )?;
    let bootstrap_args = BootstrapArgs {
        human_pubkey: Some(human_pubkey),
        relay: Some(relay),
        compose_file: Some(compose_file),
        agent_secrets_file: if agent_secrets.is_empty() {
            None
        } else {
            Some(agent_secrets)
        },
        ..BootstrapArgs::default()
    };
    println!("\nProvisioning relay members, agent ownership, and channels…");
    let exit_code = run_bootstrap(parsed, &bootstrap_args)?;
    if exit_code != 0 {
        return Ok(exit_code);
    }

    let plugin_id = nonempty_env("HERDR_PLUGIN_ID").unwrap_or_else(|| "buzzr".to_string());
    let daemon_started = if nonempty_env("HERDR_PLUGIN_ID").is_some() {
        let config = load_config(&destination)?;
        let herdr_bin = nonempty_env("HERDR_BIN_PATH").unwrap_or(config.bridge.herdr_bin);
        HerdrClient::new(herdr_bin)
            .invoke_plugin_action(&plugin_id, "start")
            .map_err(|error| {
                CommandError(format!(
                    "bridge provisioning succeeded, but the routing daemon could not start: \
                     {error}; retry with `herdr plugin action invoke start --plugin {plugin_id}`"
                ))
            })?;
        true
    } else {
        false
    };
    print!("{}", setup_completion_text(&plugin_id, daemon_started));
    Ok(0)
}

fn cmd_doctor(parsed: &Parsed) -> Result<i32, CliError> {
    let (config, _store, topology) = load_all(parsed)?;
    println!(
        "Config: {}",
        config_path(parsed.config.as_deref()).display()
    );
    println!("Relay: {}", config.bridge.relay_url);
    print!("{}", credential_summary(&config));
    if config.bridge.relay_url.trim().is_empty() {
        println!("Result: NOT READY — bridge.relay_url is missing; run `buzzr setup`");
        return Ok(1);
    }
    let (bridge_key, bridge_auth) = config.bridge_credentials();
    let bridge_public_key = config
        .bridge
        .bridge_public_key
        .as_deref()
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    if bridge_key.is_none() || !bridge_public_key {
        println!("Result: NOT READY — the bridge keypair is missing; run `buzzr bootstrap`");
        return Ok(1);
    }
    if config.human_public_key().is_none() {
        println!("Result: NOT READY — bridge.human_pubkey is missing");
        return Ok(1);
    }

    let client = BuzzClient::new(
        config.bridge.buzz_bin.clone(),
        config.bridge.relay_url.clone(),
        bridge_key.unwrap_or_default(),
        bridge_auth,
    );
    let channels = client.list_channels()?;
    let mapped: Vec<&crate::topology::AgentBinding> = topology
        .agents()
        .into_iter()
        .filter(|agent| agent.identity_id.is_some())
        .collect();
    let mut mapped_with_keys = 0;
    for agent in &mapped {
        let identity_id = agent.identity_id.as_deref().unwrap_or_default();
        let (private_key, _auth) = config.identity_credentials(identity_id)?;
        if private_key.is_some() {
            mapped_with_keys += 1;
        }
    }
    println!("Relay check: okay ({} visible channels)", channels.len());
    println!(
        "Herdr mapping: {} Spaces, {}/{} agents",
        topology.spaces.len(),
        mapped.len(),
        topology.agents().len()
    );
    println!(
        "Reply credentials: {}/{} mapped agents",
        mapped_with_keys,
        mapped.len()
    );
    let mut missing_keys: Vec<&String> = config
        .identities
        .keys()
        .filter(|identity_id| {
            config
                .identity_credentials(identity_id)
                .map(|(private_key, _auth)| private_key.is_none())
                .unwrap_or(true)
        })
        .collect();
    missing_keys.sort();
    if !missing_keys.is_empty() {
        let names: Vec<String> = missing_keys.iter().map(|key| key.to_string()).collect();
        println!(
            "Result: NOT READY — missing private keys for: {}",
            names.join(", ")
        );
        return Ok(1);
    }
    if !topology.warnings.is_empty() {
        println!(
            "Result: NOT READY — {} topology warning(s)",
            topology.warnings.len()
        );
        return Ok(1);
    }
    println!(
        "{}",
        if config.bridge.sync_enabled && config.bridge.routing_enabled {
            "Result: ACTIVE"
        } else {
            "Result: READY"
        }
    );
    Ok(0)
}

fn cmd_plan(parsed: &Parsed, as_json: bool) -> Result<i32, CliError> {
    let (_config, _store, topology) = load_all(parsed)?;
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&topology_dict(&topology))
                .map_err(|error| CliError::Value(error.to_string()))?
        );
    } else {
        print!("{}", render_plan(&topology));
    }
    Ok(0)
}

fn cmd_reconcile(parsed: &Parsed, apply: bool) -> Result<i32, CliError> {
    let (config, store, topology) = load_all(parsed)?;
    let report = reconcile(&config, &topology, &store, apply)?;
    print!("{}", render_report(&report));
    Ok(0)
}

fn cmd_refresh_profiles(parsed: &Parsed, reupload: bool) -> Result<i32, CliError> {
    let (config, store, topology) = load_all(parsed)?;
    let report = refresh_profiles(&config, &topology, &store, reupload)?;
    print!("{}", render_report(&report));
    Ok(0)
}

fn cmd_status(parsed: &Parsed, as_json: bool) -> Result<i32, CliError> {
    let (config, store, topology) = load_all(parsed)?;
    let state = store.load()?;
    let payload = status_payload(&config, &state, &topology);
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload)
                .map_err(|error| CliError::Value(error.to_string()))?
        );
    } else {
        print!("{}", render_status_text(&payload));
    }
    Ok(0)
}

fn cmd_dashboard(parsed: &Parsed) -> Result<i32, CliError> {
    begin_signal_handling();
    while still_running() {
        print!("\x1b[2J\x1b[H");
        match cmd_status(parsed, false) {
            Ok(_) => {}
            Err(error) => println!("buzzr\n\n{error}"),
        }
        println!("\nRefreshes every 2 seconds · Ctrl-C to close");
        let _ = std::io::stdout().flush();
        sleep_interruptible(Duration::from_secs(2));
    }
    Ok(0)
}

fn cmd_daemon(parsed: &Parsed) -> Result<i32, CliError> {
    let persistent_config = config_path(parsed.config.as_deref());
    let config = load_config(&persistent_config)?;
    if !config.bridge.sync_enabled
        && !config.bridge.routing_enabled
        && !config.bridge.auto_provision_agents
    {
        println!("buzzr is deactivated; run bootstrap or enable a bridge writer before start.");
        return Ok(0);
    }
    let store = StateStore::new(state_directory(parsed.state_dir.as_deref()));
    let mut service = BridgeService::new(config, store, plugin_root(), Some(persistent_config))?;
    service.run()?;
    Ok(0)
}

fn render_stop(outcome: StopOutcome) -> String {
    match outcome {
        StopOutcome::Stopped(Some(pid)) => format!("Stopped buzzr daemon (pid {pid}).\n"),
        StopOutcome::Stopped(None) => "Stopped buzzr daemon.\n".to_string(),
        StopOutcome::NotRunning => "buzzr daemon is not running.\n".to_string(),
    }
}

fn cmd_stop() -> Result<i32, CliError> {
    let outcome = stop_daemon(&crate::state::runtime_directory(), Duration::from_secs(30))?;
    print!("{}", render_stop(outcome));
    Ok(0)
}

fn cmd_deactivate(parsed: &Parsed) -> Result<i32, CliError> {
    let destination = config_path(parsed.config.as_deref());
    let outcome = deactivate(&destination)?;
    print!("{}", render_stop(outcome));
    println!("Synchronization, routing, and automatic provisioning are disabled.");
    Ok(0)
}

fn print_deprovision(plan: &DeprovisionPlan, applied: bool, as_json: bool) -> Result<(), CliError> {
    if as_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "mode": if applied { "apply" } else { "preview" },
                "plan": plan,
            }))
            .map_err(|error| CliError::Value(error.to_string()))?
        );
    } else {
        print!("{}", render_deprovision_plan(plan, applied));
    }
    Ok(())
}

fn cmd_deprovision(parsed: &Parsed, args: &DeprovisionArgs) -> Result<i32, CliError> {
    let destination = config_path(parsed.config.as_deref());
    let config = load_config(&destination)?;
    let store = StateStore::new(state_directory(parsed.state_dir.as_deref()));
    let mut state = store.load_strict()?;
    resolve_identity_intents(&config, &mut state);
    let mut delete_local_data = args.delete_local_data;
    let plan = build_deprovision_plan(&destination, &config, &store, &state, delete_local_data);
    if args.interactive {
        if !stdin_is_tty() {
            return Err(CliError::Value(
                "--interactive requires a terminal; open the plugin Cleanup overlay".to_string(),
            ));
        }
        print_deprovision(&plan, false, false)?;
        let confirmation = ask(
            "Type the exact relay URL to apply this cleanup (Enter cancels)",
            None,
        )?;
        if confirmation.is_empty() {
            println!("Deprovision cancelled; nothing changed.");
            return Ok(0);
        }
        if confirmation != config.bridge.relay_url {
            return Err(CliError::Value(
                "relay confirmation did not match; nothing changed".to_string(),
            ));
        }
        let local = ask(
            "Also delete local config, managed secrets, and state?",
            Some("no"),
        )?;
        delete_local_data = matches!(local.to_lowercase().as_str(), "y" | "yes");
        let applied = apply_deprovision(&destination, &config, &store, delete_local_data)?;
        print_deprovision(&applied, true, false)?;
        return Ok(0);
    }
    if !args.apply {
        print_deprovision(&plan, false, args.json)?;
        return Ok(0);
    }
    if args.confirm_relay.as_deref() != Some(config.bridge.relay_url.as_str()) {
        return Err(CliError::Value(format!(
            "refusing deprovision: --confirm-relay must exactly equal {}",
            config.bridge.relay_url
        )));
    }
    let applied = apply_deprovision(&destination, &config, &store, delete_local_data)?;
    print_deprovision(&applied, true, args.json)?;
    Ok(0)
}

fn cmd_reply(token: &str, content: &str) -> Result<i32, CliError> {
    let content = if content == "-" {
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    } else {
        content.to_string()
    };
    let result = queue_reply(token, &content, Duration::from_secs(30))?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|error| CliError::Value(error.to_string()))?
    );
    Ok(
        if result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            0
        } else {
            1
        },
    )
}

// --- argument parsing --------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct Parsed {
    pub config: Option<String>,
    pub state_dir: Option<String>,
    pub command: Command,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Command {
    InitConfig {
        force: bool,
    },
    Configure(ConfigureArgs),
    Bootstrap(BootstrapArgs),
    Setup,
    Doctor,
    Plan {
        json: bool,
    },
    Reconcile {
        apply: bool,
    },
    RefreshProfiles {
        reupload: bool,
    },
    Status {
        json: bool,
    },
    Dashboard,
    Stop,
    Deactivate,
    Deprovision(DeprovisionArgs),
    #[default]
    Daemon,
    Reply {
        token: String,
        content: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeprovisionArgs {
    pub apply: bool,
    pub confirm_relay: Option<String>,
    pub delete_local_data: bool,
    pub json: bool,
    pub interactive: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigureArgs {
    pub relay: Option<String>,
    pub environment: bool,
    pub secrets_file: Option<String>,
    /// argparse default: BUZZ_PRIVATE_KEY
    pub private_key_env: String,
    /// argparse default: BUZZ_AUTH_TAG
    pub auth_tag_env: String,
    pub owner_pubkey: Option<String>,
}

impl Default for ConfigureArgs {
    fn default() -> Self {
        ConfigureArgs {
            relay: None,
            environment: false,
            secrets_file: None,
            private_key_env: "BUZZ_PRIVATE_KEY".to_string(),
            auth_tag_env: "BUZZ_AUTH_TAG".to_string(),
            owner_pubkey: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BootstrapArgs {
    pub human_pubkey: Option<String>,
    pub relay: Option<String>,
    pub compose_file: Option<String>,
    pub managed_secrets_file: Option<String>,
    pub agent_secrets_file: Option<String>,
    pub buzz_bin: Option<String>,
    /// Deprecated no-op; accepted for CLI compatibility (prints a warning).
    pub nak_bin: Option<String>,
}

/// Parsing did not produce a runnable command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseFailure {
    /// `-h`/`--help`: print to stdout, exit 0.
    Help(String),
    /// argparse-style error: usage + message to stderr, exit 2.
    Error(String),
}

const SUBCOMMANDS: [(&str, &str); 15] = [
    ("init-config", "write a safe config template"),
    (
        "configure",
        "select the relay and credential source without copying secrets",
    ),
    (
        "bootstrap",
        "provision bridge/agents, bind the human owner, create channels, and enable routing",
    ),
    ("setup", "run the interactive first-use setup"),
    ("doctor", "validate credentials, relay access, and mapping"),
    ("plan", "preview Space/channel and agent/member mappings"),
    ("reconcile", "discover or synchronize Buzz channels"),
    (
        "refresh-profiles",
        "republish managed profiles and their stable avatars",
    ),
    ("status", "show bridge readiness and current state"),
    ("dashboard", "open a refreshing status display"),
    ("stop", "stop the routing daemon without deleting data"),
    (
        "deactivate",
        "stop the daemon and disable automatic bridge writes",
    ),
    (
        "deprovision",
        "preview or apply provenance-safe Buzz resource cleanup",
    ),
    ("daemon", "run topology reconciliation and message routing"),
    (
        "reply",
        "queue a reply through the credential-owning daemon",
    ),
];

fn usage_line() -> String {
    let names: Vec<&str> = SUBCOMMANDS.iter().map(|(name, _)| *name).collect();
    format!(
        "usage: buzzr [-h] [--config CONFIG] [--state-dir STATE_DIR] {{{}}} ...",
        names.join(",")
    )
}

fn top_help() -> String {
    let mut out = format!("{}\n\n", usage_line());
    out.push_str("Mirror Herdr Spaces and their live agents into Buzz channels.\n\n");
    out.push_str("options:\n");
    out.push_str("  -h, --help           show this help message and exit\n");
    out.push_str("  --config CONFIG      override config.toml path\n");
    out.push_str("  --state-dir DIR      override persistent state directory\n\n");
    out.push_str("commands:\n");
    for (name, help) in SUBCOMMANDS {
        out.push_str(&format!("  {name:<17} {help}\n"));
    }
    out
}

fn sub_help(name: &str) -> String {
    let help = SUBCOMMANDS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, help)| *help)
        .unwrap_or_default();
    let mut out = format!("usage: buzzr {name} [-h]");
    for flag in flag_specs(name) {
        if flag.takes_value {
            out.push_str(&format!(" [{} {}]", flag.name, flag.metavar));
        } else {
            out.push_str(&format!(" [{}]", flag.name));
        }
    }
    out.push_str(&format!(
        "\n\n{help}\n\noptions:\n  -h, --help  show this help message and exit\n"
    ));
    for flag in flag_specs(name) {
        out.push_str(&format!(
            "  {:<28} {}\n",
            if flag.takes_value {
                format!("{} {}", flag.name, flag.metavar)
            } else {
                flag.name.to_string()
            },
            flag.help
        ));
    }
    out
}

struct FlagSpec {
    name: &'static str,
    metavar: &'static str,
    takes_value: bool,
    required: bool,
    help: &'static str,
}

fn flag_specs(name: &str) -> &'static [FlagSpec] {
    macro_rules! spec {
        ($($name:literal, $metavar:literal, $takes:expr, $required:expr, $help:literal);* $(;)?) => {
            &[$(FlagSpec { name: $name, metavar: $metavar, takes_value: $takes, required: $required, help: $help }),*]
        };
    }
    match name {
        "init-config" => spec!("--force", "", false, false, "overwrite an existing config"),
        "configure" => spec!(
            "--relay", "RELAY", true, false, "Buzz relay URL";
            "--environment", "", false, false, "read credentials from the Herdr server environment";
            "--secrets-file", "PATH", true, false, "read credentials from a mode-0600 dotenv file";
            "--private-key-env", "NAME", true, false, "environment variable holding the bridge private key";
            "--auth-tag-env", "NAME", true, false, "environment variable holding the delegation tag";
            "--owner-pubkey", "PUBKEY", true, false, "owner public key for owner-only inbound routing";
        ),
        "bootstrap" => spec!(
            "--human-pubkey", "PUBKEY", true, false, "human controller's npub or 64-character hex public key";
            "--relay", "RELAY", true, false, "public Buzz relay URL";
            "--compose-file", "PATH", true, false, "local Buzz docker-compose.yml";
            "--managed-secrets-file", "PATH", true, false, "private dotenv buzzr may create/update (default: plugin config dir/secrets.env)";
            "--agent-secrets-file", "PATH", true, false, "optional existing mode-0600 dotenv containing imported agent keys";
            "--buzz-bin", "PATH", true, false, "Buzz CLI binary";
            "--nak-bin", "PATH", true, false, "deprecated: ignored (buzzr publishes to Nostr natively)";
        ),
        "plan" => spec!("--json", "", false, false, "emit the topology as JSON"),
        "reconcile" => spec!(
            "--apply",
            "",
            false,
            false,
            "apply even when bridge.sync_enabled is false"
        ),
        "refresh-profiles" => spec!(
            "--reupload",
            "",
            false,
            false,
            "upload image blobs again instead of reusing cached URLs"
        ),
        "status" => spec!("--json", "", false, false, "emit the status as JSON"),
        "dashboard" => spec!(
            "--json",
            "",
            false,
            false,
            "accepted for compatibility; ignored"
        ),
        "deprovision" => spec!(
            "--apply", "", false, false, "apply the displayed cleanup plan";
            "--confirm-relay", "URL", true, false, "exact relay URL required with --apply";
            "--delete-local-data", "", false, false, "also delete buzzr config, managed secrets, and marked state";
            "--json", "", false, false, "emit the plan as JSON";
            "--interactive", "", false, false, "prompt for relay confirmation and local-data deletion";
        ),
        "reply" => spec!(
            "--token", "TOKEN", true, true, "reply token from the bridge prompt";
            "--content", "CONTENT", true, true, "reply text, or - to read stdin";
        ),
        _ => &[],
    }
}

fn error<T>(message: impl Into<String>) -> Result<T, ParseFailure> {
    Err(ParseFailure::Error(message.into()))
}

/// Split `--flag=value` into (`--flag`, Some(value)).
fn split_flag(argument: &str) -> (&str, Option<&str>) {
    match argument.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (argument, None),
    }
}

/// Parse the arguments of one subcommand against its flag specs. Returns the
/// collected values keyed by flag name.
fn parse_flags(
    command_name: &str,
    args: &[String],
) -> Result<Vec<(&'static str, Option<String>)>, ParseFailure> {
    let specs = flag_specs(command_name);
    let mut collected: Vec<(&'static str, Option<String>)> = Vec::new();
    let mut unrecognized: Vec<String> = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == "-h" || argument == "--help" {
            return Err(ParseFailure::Help(sub_help(command_name)));
        }
        let (name, inline_value) = split_flag(argument);
        match specs.iter().find(|spec| spec.name == name) {
            Some(spec) if spec.takes_value => {
                let value = match inline_value {
                    Some(value) => value.to_string(),
                    None => {
                        index += 1;
                        match args.get(index) {
                            Some(value) => value.clone(),
                            None => {
                                return error(format!("argument {name}: expected one argument"));
                            }
                        }
                    }
                };
                collected.push((spec.name, Some(value)));
            }
            Some(spec) => collected.push((spec.name, None)),
            None => unrecognized.push(argument.clone()),
        }
        index += 1;
    }
    if !unrecognized.is_empty() {
        return error(format!(
            "unrecognized arguments: {}",
            unrecognized.join(" ")
        ));
    }
    let missing: Vec<&str> = specs
        .iter()
        .filter(|spec| spec.required)
        .filter(|spec| !collected.iter().any(|(name, _)| *name == spec.name))
        .map(|spec| spec.name)
        .collect();
    if !missing.is_empty() {
        return error(format!(
            "the following arguments are required: {}",
            missing.join(", ")
        ));
    }
    Ok(collected)
}

fn last_value<'a>(flags: &'a [(&'static str, Option<String>)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .rev()
        .find(|(candidate, _)| *candidate == name)
        .and_then(|(_, value)| value.as_deref())
}

fn has_flag(flags: &[(&'static str, Option<String>)], name: &str) -> bool {
    flags.iter().any(|(candidate, _)| *candidate == name)
}

fn parse_command(command_name: &str, args: &[String]) -> Result<Command, ParseFailure> {
    let flags = parse_flags(command_name, args)?;
    let command = match command_name {
        "init-config" => Command::InitConfig {
            force: has_flag(&flags, "--force"),
        },
        "configure" => {
            let environment = has_flag(&flags, "--environment");
            let secrets_file = last_value(&flags, "--secrets-file").map(str::to_string);
            if environment && secrets_file.is_some() {
                return error("argument --secrets-file: not allowed with argument --environment");
            }
            let defaults = ConfigureArgs::default();
            Command::Configure(ConfigureArgs {
                relay: last_value(&flags, "--relay").map(str::to_string),
                environment,
                secrets_file,
                private_key_env: last_value(&flags, "--private-key-env")
                    .map(str::to_string)
                    .unwrap_or(defaults.private_key_env),
                auth_tag_env: last_value(&flags, "--auth-tag-env")
                    .map(str::to_string)
                    .unwrap_or(defaults.auth_tag_env),
                owner_pubkey: last_value(&flags, "--owner-pubkey").map(str::to_string),
            })
        }
        "bootstrap" => Command::Bootstrap(BootstrapArgs {
            human_pubkey: last_value(&flags, "--human-pubkey").map(str::to_string),
            relay: last_value(&flags, "--relay").map(str::to_string),
            compose_file: last_value(&flags, "--compose-file").map(str::to_string),
            managed_secrets_file: last_value(&flags, "--managed-secrets-file").map(str::to_string),
            agent_secrets_file: last_value(&flags, "--agent-secrets-file").map(str::to_string),
            buzz_bin: last_value(&flags, "--buzz-bin").map(str::to_string),
            nak_bin: last_value(&flags, "--nak-bin").map(str::to_string),
        }),
        "setup" => Command::Setup,
        "doctor" => Command::Doctor,
        "plan" => Command::Plan {
            json: has_flag(&flags, "--json"),
        },
        "reconcile" => Command::Reconcile {
            apply: has_flag(&flags, "--apply"),
        },
        "refresh-profiles" => Command::RefreshProfiles {
            reupload: has_flag(&flags, "--reupload"),
        },
        "status" => Command::Status {
            json: has_flag(&flags, "--json"),
        },
        "dashboard" => Command::Dashboard,
        "stop" => Command::Stop,
        "deactivate" => Command::Deactivate,
        "deprovision" => {
            let interactive = has_flag(&flags, "--interactive");
            if interactive
                && (has_flag(&flags, "--apply")
                    || has_flag(&flags, "--delete-local-data")
                    || has_flag(&flags, "--json")
                    || last_value(&flags, "--confirm-relay").is_some())
            {
                return error(
                    "argument --interactive: not allowed with apply/confirmation/output flags",
                );
            }
            Command::Deprovision(DeprovisionArgs {
                apply: has_flag(&flags, "--apply"),
                confirm_relay: last_value(&flags, "--confirm-relay").map(str::to_string),
                delete_local_data: has_flag(&flags, "--delete-local-data"),
                json: has_flag(&flags, "--json"),
                interactive,
            })
        }
        "daemon" => Command::Daemon,
        "reply" => Command::Reply {
            token: last_value(&flags, "--token")
                .unwrap_or_default()
                .to_string(),
            content: last_value(&flags, "--content")
                .unwrap_or_default()
                .to_string(),
        },
        _ => unreachable!("parse_command only called for known subcommands"),
    };
    Ok(command)
}

/// Parse argv, excluding argv[0].
pub fn parse(args: &[String]) -> Result<Parsed, ParseFailure> {
    let mut parsed = Parsed::default();
    let mut index = 0;
    loop {
        let argument = match args.get(index) {
            Some(argument) => argument,
            None => {
                return error("the following arguments are required: command");
            }
        };
        if argument == "-h" || argument == "--help" {
            return Err(ParseFailure::Help(top_help()));
        }
        let (name, inline_value) = split_flag(argument);
        match name {
            "--config" | "--state-dir" => {
                let value = match inline_value {
                    Some(value) => value.to_string(),
                    None => {
                        index += 1;
                        match args.get(index) {
                            Some(value) => value.clone(),
                            None => {
                                return error(format!("argument {name}: expected one argument"));
                            }
                        }
                    }
                };
                if name == "--config" {
                    parsed.config = Some(value);
                } else {
                    parsed.state_dir = Some(value);
                }
                index += 1;
            }
            _ if argument.starts_with('-') => {
                return error(format!("unrecognized arguments: {argument}"));
            }
            _ => {
                if !SUBCOMMANDS
                    .iter()
                    .any(|(candidate, _)| *candidate == argument)
                {
                    return error(format!(
                        "argument command: invalid choice: '{}' (choose from {})",
                        argument,
                        SUBCOMMANDS
                            .iter()
                            .map(|(candidate, _)| format!("'{candidate}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                parsed.command = parse_command(argument, &args[index + 1..])?;
                return Ok(parsed);
            }
        }
    }
}

// --- entry point -------------------------------------------------------------

fn run(parsed: &Parsed) -> Result<i32, CliError> {
    match &parsed.command {
        Command::InitConfig { force } => cmd_init(parsed, *force),
        Command::Configure(args) => cmd_configure(parsed, args),
        Command::Bootstrap(args) => run_bootstrap(parsed, args),
        Command::Setup => cmd_setup(parsed),
        Command::Doctor => cmd_doctor(parsed),
        Command::Plan { json } => cmd_plan(parsed, *json),
        Command::Reconcile { apply } => cmd_reconcile(parsed, *apply),
        Command::RefreshProfiles { reupload } => cmd_refresh_profiles(parsed, *reupload),
        Command::Status { json } => cmd_status(parsed, *json),
        Command::Dashboard => cmd_dashboard(parsed),
        Command::Stop => cmd_stop(),
        Command::Deactivate => cmd_deactivate(parsed),
        Command::Deprovision(args) => cmd_deprovision(parsed, args),
        Command::Daemon => cmd_daemon(parsed),
        Command::Reply { token, content } => cmd_reply(token, content),
    }
}

/// Port of `main()`: parse, dispatch, and map errors to exit codes.
pub fn main(args: &[String]) -> i32 {
    match parse(args) {
        Ok(parsed) => match run(&parsed) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("error: {error}");
                1
            }
        },
        Err(ParseFailure::Help(text)) => {
            print!("{text}");
            0
        }
        Err(ParseFailure::Error(message)) => {
            eprintln!("{}", usage_line());
            eprintln!("buzzr: error: {message}");
            2
        }
    }
}
