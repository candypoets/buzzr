//! Safe plugin lifecycle operations.
//!
//! Stopping and uninstalling are intentionally non-destructive. External Buzz
//! cleanup is a separate, provenance-gated deprovision transaction.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use fs2::FileExt;
use serde::Serialize;
use serde_json::{json, Value};

use crate::clients::{BuzzClient, CommandError, LocalBuzzAdmin};
use crate::config::{update_bridge_settings, Config};
use crate::provisioning::resolve_identity_intents;
use crate::state::{
    normalize_managed_resources, open_private_lock, open_private_read, runtime_directory,
    validate_private_directory, write_private_file, StateStore, STATE_MARKER,
};

fn err<T>(message: impl Into<String>) -> Result<T, CommandError> {
    Err(CommandError(message.into()))
}

fn io(error: std::io::Error) -> CommandError {
    CommandError(error.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    Stopped(Option<u32>),
    NotRunning,
}

/// Ask the daemon holding the private runtime lock to stop. This deliberately
/// uses a cooperative request file instead of signalling a PID, so stale or
/// reused process identifiers can never terminate an unrelated process.
pub fn stop_daemon(runtime_dir: &Path, timeout: Duration) -> Result<StopOutcome, CommandError> {
    match fs::symlink_metadata(runtime_dir) {
        Ok(_) => validate_private_directory(runtime_dir).map_err(io)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StopOutcome::NotRunning)
        }
        Err(error) => return Err(io(error)),
    }
    let lock_path = runtime_dir.join("daemon.lock");
    let pid_path = runtime_dir.join("daemon.pid");
    let request_path = runtime_dir.join("stop.request");
    if !lock_path.exists() {
        let _ = fs::remove_file(pid_path);
        let _ = fs::remove_file(request_path);
        return Ok(StopOutcome::NotRunning);
    }

    let lock = open_private_lock(&lock_path).map_err(io)?;
    match lock.try_lock_exclusive() {
        Ok(()) => {
            let _ = FileExt::unlock(&lock);
            let _ = fs::remove_file(pid_path);
            let _ = fs::remove_file(request_path);
            return Ok(StopOutcome::NotRunning);
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(io(error)),
    }

    let mut pid = fs::read_to_string(&pid_path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|pid| *pid > 1);

    let deadline = Instant::now() + timeout;
    loop {
        write_private_file(&request_path, b"stop\n").map_err(io)?;
        if pid.is_none() {
            pid = fs::read_to_string(&pid_path)
                .ok()
                .and_then(|raw| raw.trim().parse::<u32>().ok())
                .filter(|pid| *pid > 1);
        }
        match lock.try_lock_exclusive() {
            Ok(()) => {
                let _ = FileExt::unlock(&lock);
                let _ = fs::remove_file(&pid_path);
                let _ = fs::remove_file(&request_path);
                return Ok(StopOutcome::Stopped(pid));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(io(error)),
        }
        if Instant::now() >= deadline {
            return err(format!(
                "buzzr daemon did not stop within {} seconds; its stop request remains queued",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Stop routing and persistently disable every automatic writer.
pub fn deactivate(config_path: &Path) -> Result<StopOutcome, CommandError> {
    update_bridge_settings(
        config_path,
        &[
            ("sync_enabled".to_string(), Some(json!(false))),
            ("routing_enabled".to_string(), Some(json!(false))),
            ("auto_provision_agents".to_string(), Some(json!(false))),
        ],
    )
    .map_err(|error| CommandError(error.to_string()))?;
    stop_daemon(&runtime_directory(), Duration::from_secs(30))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum DeprovisionAction {
    StopDaemon,
    Deactivate,
    ArchiveChannel {
        workspace_id: String,
        channel_id: String,
        name: String,
    },
    RemoveChannelMember {
        channel_id: String,
        name: String,
        pubkey: String,
        identity_kind: String,
        identity_id: String,
        recorded_role: String,
    },
    ArchiveIdentity {
        pubkey: String,
        identity_kind: String,
        identity_id: String,
    },
    ClearOwnership {
        pubkey: String,
        owner_pubkey: String,
    },
    RemoveRelayMember {
        pubkey: String,
    },
    DeleteLocalData {
        config: String,
        managed_secrets: Option<String>,
        state_dir: String,
    },
}

impl DeprovisionAction {
    pub fn description(&self) -> String {
        match self {
            DeprovisionAction::StopDaemon => "stop the routing daemon if running".to_string(),
            DeprovisionAction::Deactivate => {
                "disable synchronization, routing, and automatic provisioning".to_string()
            }
            DeprovisionAction::ArchiveChannel {
                channel_id, name, ..
            } => format!("archive buzzr-created #{name} ({channel_id})"),
            DeprovisionAction::RemoveChannelMember {
                name, identity_id, ..
            } => format!("remove generated {identity_id} from adopted #{name}"),
            DeprovisionAction::ArchiveIdentity {
                pubkey,
                identity_id,
                ..
            } => format!(
                "archive generated identity {identity_id} ({})",
                short_pubkey(pubkey)
            ),
            DeprovisionAction::ClearOwnership { pubkey, .. } => format!(
                "clear buzzr-assigned ownership for {}",
                short_pubkey(pubkey)
            ),
            DeprovisionAction::RemoveRelayMember { pubkey } => format!(
                "remove buzzr-added relay membership for {}",
                short_pubkey(pubkey)
            ),
            DeprovisionAction::DeleteLocalData {
                config,
                managed_secrets,
                state_dir,
            } => format!(
                "delete local config {config}, state {state_dir}{}",
                managed_secrets
                    .as_ref()
                    .map(|path| format!(", and managed secrets {path}"))
                    .unwrap_or_default()
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeprovisionPlan {
    pub relay_url: String,
    pub actions: Vec<DeprovisionAction>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedIdentity {
    pubkey: String,
    identity_kind: String,
    identity_id: String,
    archived: bool,
}

fn short_pubkey(pubkey: &str) -> String {
    pubkey.chars().take(12).collect()
}

fn managed_identities(state: &Value) -> BTreeMap<String, ManagedIdentity> {
    state
        .get("managed_resources")
        .and_then(|resources| resources.get("identities"))
        .and_then(Value::as_object)
        .map(|identities| {
            identities
                .iter()
                .filter_map(|(pubkey, record)| {
                    if record.get("origin").and_then(Value::as_str) != Some("generated") {
                        return None;
                    }
                    let identity_kind = record
                        .get("identity_kind")
                        .and_then(Value::as_str)
                        .filter(|kind| matches!(*kind, "bridge" | "agent"))?;
                    Some((
                        pubkey.clone(),
                        ManagedIdentity {
                            pubkey: pubkey.clone(),
                            identity_kind: identity_kind.to_string(),
                            identity_id: record
                                .get("identity_id")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_string(),
                            archived: record
                                .get("archived")
                                .and_then(Value::as_bool)
                                .unwrap_or(false),
                        },
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Build a deterministic cleanup plan from recorded provenance only.
pub fn build_deprovision_plan(
    config_path: &Path,
    config: &Config,
    store: &StateStore,
    state: &Value,
    delete_local_data: bool,
) -> DeprovisionPlan {
    let mut actions = vec![DeprovisionAction::Deactivate, DeprovisionAction::StopDaemon];
    let mut warnings = Vec::new();
    let identities = managed_identities(state);
    if let Some(intents) = state["managed_resources"]["identity_intents"].as_object() {
        for intent in intents.values() {
            let identity_id = intent
                .get("identity_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            warnings.push(format!(
                "preserving unresolved generated identity intent {identity_id}: no complete keypair is available"
            ));
        }
    }

    let mut channels_by_id: BTreeMap<String, (String, String, String)> = BTreeMap::new();
    if let Some(channels) = state.get("channels").and_then(Value::as_object) {
        let mut entries: Vec<_> = channels.iter().collect();
        entries.sort_by_key(|(workspace_id, _)| *workspace_id);
        for (workspace_id, channel) in entries {
            let channel_id = channel
                .get("channel_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if channel_id.is_empty() {
                continue;
            }
            let name = channel
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(workspace_id)
                .to_string();
            let origin = channel
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            channels_by_id.insert(
                channel_id.clone(),
                (workspace_id.clone(), name.clone(), origin.clone()),
            );
            match origin.as_str() {
                "created"
                    if !channel
                        .get("archived")
                        .and_then(Value::as_bool)
                        .unwrap_or(false) =>
                {
                    actions.push(DeprovisionAction::ArchiveChannel {
                        workspace_id: workspace_id.clone(),
                        channel_id,
                        name,
                    })
                }
                "created" => {}
                "adopted" => warnings.push(format!(
                    "preserving adopted #{name}; only tracked generated memberships are eligible"
                )),
                _ => warnings.push(format!(
                    "preserving #{name}: legacy state has no creation provenance"
                )),
            }
        }
    }

    if let Some(channel_memberships) = state
        .get("managed_resources")
        .and_then(|resources| resources.get("channel_memberships"))
        .and_then(Value::as_object)
    {
        let mut channel_entries: Vec<_> = channel_memberships.iter().collect();
        channel_entries.sort_by_key(|(channel_id, _)| *channel_id);
        for (channel_id, memberships) in channel_entries {
            let Some((_workspace_id, name, origin)) = channels_by_id.get(channel_id) else {
                continue;
            };
            if origin != "adopted" {
                continue;
            }
            let mut membership_entries: Vec<_> = memberships
                .as_object()
                .map(|items| items.iter().collect())
                .unwrap_or_default();
            membership_entries.sort_by_key(|(pubkey, _)| *pubkey);
            for (pubkey, record) in membership_entries {
                let membership_origin = record
                    .get("origin")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if membership_origin != "added" {
                    if membership_origin == "adding" {
                        warnings.push(format!(
                            "preserving unresolved membership for {} in #{name}",
                            short_pubkey(pubkey)
                        ));
                    }
                    continue;
                }
                let Some(identity) = identities.get(pubkey) else {
                    continue;
                };
                let recorded_role = record
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                if !matches!(recorded_role, "bot" | "member") {
                    continue;
                }
                actions.push(DeprovisionAction::RemoveChannelMember {
                    channel_id: channel_id.clone(),
                    name: name.clone(),
                    pubkey: pubkey.clone(),
                    identity_kind: identity.identity_kind.clone(),
                    identity_id: identity.identity_id.clone(),
                    recorded_role: recorded_role.to_string(),
                });
            }
        }
    }

    let relay_members: BTreeSet<String> = state
        .get("managed_resources")
        .and_then(|resources| resources.get("relay_members"))
        .and_then(Value::as_object)
        .map(|members| {
            members
                .iter()
                .filter(|(_, record)| record.get("origin").and_then(Value::as_str) == Some("added"))
                .map(|(pubkey, _)| pubkey.clone())
                .collect()
        })
        .unwrap_or_default();
    let ownerships = state
        .get("managed_resources")
        .and_then(|resources| resources.get("ownerships"))
        .and_then(Value::as_object);
    for identity in identities.values() {
        if !identity.archived {
            actions.push(DeprovisionAction::ArchiveIdentity {
                pubkey: identity.pubkey.clone(),
                identity_kind: identity.identity_kind.clone(),
                identity_id: identity.identity_id.clone(),
            });
        }
        if let Some(owner_pubkey) = ownerships
            .and_then(|owners| owners.get(&identity.pubkey))
            .filter(|record| record.get("origin").and_then(Value::as_str) == Some("assigned"))
            .and_then(|record| record.get("owner_pubkey"))
            .and_then(Value::as_str)
        {
            actions.push(DeprovisionAction::ClearOwnership {
                pubkey: identity.pubkey.clone(),
                owner_pubkey: owner_pubkey.to_string(),
            });
        }
        if relay_members.contains(&identity.pubkey) {
            actions.push(DeprovisionAction::RemoveRelayMember {
                pubkey: identity.pubkey.clone(),
            });
        }
    }

    let imported = config
        .identities
        .values()
        .filter(|identity| !identities.contains_key(&identity.public_key))
        .count();
    if imported > 0 {
        warnings.push(format!(
            "preserving {imported} imported or legacy identity/identities and their relay access"
        ));
    }
    warnings.push(
        "published Nostr events remain in relay history; identity archival is a signed status request, not erasure"
            .to_string(),
    );

    if delete_local_data {
        actions.push(DeprovisionAction::DeleteLocalData {
            config: config_path.display().to_string(),
            managed_secrets: config
                .bridge
                .managed_secrets_file
                .as_ref()
                .map(|path| path.display().to_string()),
            state_dir: store.directory.display().to_string(),
        });
        if config.bridge.secrets_files.len()
            > usize::from(config.bridge.managed_secrets_file.is_some())
        {
            warnings.push("external/imported secrets files will be preserved".to_string());
        }
    }

    DeprovisionPlan {
        relay_url: config.bridge.relay_url.clone(),
        actions,
        warnings,
    }
}

pub fn render_deprovision_plan(plan: &DeprovisionPlan, applied: bool) -> String {
    let mut output = format!(
        "mode: {}\nrelay: {}\n",
        if applied { "APPLY" } else { "PREVIEW" },
        plan.relay_url
    );
    for action in &plan.actions {
        output.push_str(&format!(
            "  · {}{}\n",
            if applied { "" } else { "would " },
            action.description()
        ));
    }
    for warning in &plan.warnings {
        output.push_str(&format!("  ! {warning}\n"));
    }
    if !applied {
        output.push_str(&format!(
            "\nTo apply, rerun with --apply --confirm-relay {}\n",
            plan.relay_url
        ));
    }
    output
}

fn bridge_client(config: &Config) -> Result<BuzzClient, CommandError> {
    let (private_key, auth_tag) = config.bridge_credentials();
    let private_key = private_key.ok_or_else(|| {
        CommandError(format!(
            "{} is unavailable; cannot deprovision bridge-owned resources",
            config.bridge.bridge_private_key_env
        ))
    })?;
    Ok(BuzzClient::new(
        config.bridge.buzz_bin.clone(),
        config.bridge.relay_url.clone(),
        private_key,
        auth_tag,
    ))
}

fn identity_client(
    config: &Config,
    identity_kind: &str,
    identity_id: &str,
    expected_pubkey: &str,
) -> Result<BuzzClient, CommandError> {
    if identity_kind == "bridge" {
        if config.bridge.bridge_public_key.as_deref() != Some(expected_pubkey) {
            return err("managed bridge provenance does not match the configured public key");
        }
        return bridge_client(config);
    }
    if identity_kind != "agent" {
        return err("managed identity has an invalid identity kind");
    }
    let identity = config.identities.get(identity_id).ok_or_else(|| {
        CommandError(format!(
            "managed identity {identity_id} is missing from config; refusing cleanup"
        ))
    })?;
    if identity.public_key != expected_pubkey {
        return err(format!(
            "managed identity {identity_id} provenance does not match its configured public key"
        ));
    }
    let (private_key, auth_tag) = config
        .identity_credentials(identity_id)
        .map_err(|error| CommandError(error.to_string()))?;
    let private_key = private_key.ok_or_else(|| {
        CommandError(format!(
            "{} is unavailable; cannot deprovision generated identity {identity_id}",
            identity.private_key_env
        ))
    })?;
    Ok(BuzzClient::new(
        config.bridge.buzz_bin.clone(),
        config.bridge.relay_url.clone(),
        private_key,
        auth_tag,
    ))
}

fn local_admin(config: &Config) -> Result<LocalBuzzAdmin, CommandError> {
    let compose_file = config.bridge.compose_file.clone().ok_or_else(|| {
        CommandError("bridge.compose_file is required to remove local relay resources".to_string())
    })?;
    if !compose_file.exists() {
        return err(format!(
            "Buzz Compose file does not exist: {}",
            compose_file.display()
        ));
    }
    let mut admin = LocalBuzzAdmin::new(compose_file);
    admin.relay_service = config.bridge.relay_service.clone();
    admin.postgres_service = config.bridge.postgres_service.clone();
    admin.postgres_user = config.bridge.postgres_user.clone();
    admin.postgres_database = config.bridge.postgres_database.clone();
    Ok(admin)
}

fn update_state<F>(store: &StateStore, update: F) -> Result<(), CommandError>
where
    F: FnOnce(&mut Value),
{
    store
        .with_lock(|| -> Result<(), CommandError> {
            let mut state = store
                .load_strict()
                .map_err(|error| CommandError(format!("cannot load state: {error}")))?;
            normalize_managed_resources(&mut state);
            update(&mut state);
            store
                .save(&state)
                .map_err(|error| CommandError(format!("cannot save state: {error}")))
        })
        .map_err(|error| CommandError(format!("cannot lock state: {error}")))?
}

fn remove_object_entry(state: &mut Value, section: &str, key: &str) {
    if let Some(object) = state["managed_resources"][section].as_object_mut() {
        object.remove(key);
    }
}

fn remove_membership_entry(state: &mut Value, channel_id: &str, pubkey: &str) {
    if let Some(memberships) = state["managed_resources"]["channel_memberships"]
        .get_mut(channel_id)
        .and_then(Value::as_object_mut)
    {
        memberships.remove(pubkey);
    }
    let empty = state["managed_resources"]["channel_memberships"]
        .get(channel_id)
        .and_then(Value::as_object)
        .map(serde_json::Map::is_empty)
        .unwrap_or(false);
    if empty {
        remove_object_entry(state, "channel_memberships", channel_id);
    }
}

fn remove_file_if_present(path: &Path) -> Result<(), CommandError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(error)),
    }
}

fn validate_local_data_deletion(store: &StateStore) -> Result<(), CommandError> {
    let state_dir = store
        .directory
        .canonicalize()
        .unwrap_or_else(|_| store.directory.clone());
    let depth = state_dir
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let cwd = std::env::current_dir().ok();
    if depth < 2
        || home.as_deref() == Some(state_dir.as_path())
        || cwd.as_deref() == Some(state_dir.as_path())
    {
        return err(format!(
            "refusing broad state directory for local-data deletion: {}",
            state_dir.display()
        ));
    }
    validate_private_directory(&store.directory).map_err(io)?;
    let marker = store.directory.join(".buzzr-state");
    let marker_valid = open_private_read(&marker)
        .and_then(|mut marker| {
            let mut content = String::new();
            marker.read_to_string(&mut content)?;
            Ok(content == STATE_MARKER)
        })
        .unwrap_or(false);
    if !marker_valid {
        return err(format!(
            "refusing to delete state without a valid buzzr marker: {}",
            store.directory.display()
        ));
    }
    let state_file_valid = open_private_read(&store.path).is_ok();
    if !state_file_valid {
        return err(format!(
            "refusing to delete local data without a valid state file: {}",
            store.path.display()
        ));
    }
    Ok(())
}

fn delete_local_data(
    config_path: &Path,
    config: &Config,
    store: &StateStore,
) -> Result<(), CommandError> {
    validate_local_data_deletion(store)?;
    let marker = store.directory.join(".buzzr-state");

    if let Some(secrets) = &config.bridge.managed_secrets_file {
        if secrets != config_path {
            remove_file_if_present(secrets)?;
        }
    }
    remove_file_if_present(config_path)?;
    remove_file_if_present(&store.path)?;
    remove_file_if_present(&store.directory.join("state.lock"))?;
    let avatars = store.directory.join("avatars");
    if avatars.is_symlink() {
        remove_file_if_present(&avatars)?;
    } else if avatars.exists() {
        fs::remove_dir_all(&avatars).map_err(io)?;
    }
    remove_file_if_present(&marker)?;
    match fs::remove_dir(&store.directory) {
        Ok(()) => {}
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(error) => return Err(io(error)),
    }
    Ok(())
}

/// Apply a previously previewable cleanup. Callers must verify the typed relay
/// confirmation before entering this function.
pub fn apply_deprovision(
    config_path: &Path,
    config: &Config,
    store: &StateStore,
    delete_local: bool,
) -> Result<DeprovisionPlan, CommandError> {
    // Fail closed before changing configuration, then quiesce every writer and
    // reload the final state snapshot used for destructive planning.
    store
        .load_strict()
        .map_err(|error| CommandError(format!("cannot safely load lifecycle state: {error}")))?;
    if delete_local {
        validate_local_data_deletion(store)?;
    }
    update_bridge_settings(
        config_path,
        &[
            ("sync_enabled".to_string(), Some(json!(false))),
            ("routing_enabled".to_string(), Some(json!(false))),
            ("auto_provision_agents".to_string(), Some(json!(false))),
        ],
    )
    .map_err(|error| CommandError(error.to_string()))?;
    stop_daemon(&runtime_directory(), Duration::from_secs(30))?;

    // An in-flight provisioning pass may have started from the old config and
    // persisted it just before releasing the daemon lock. Reapply deactivation
    // after the writer is quiescent, then verify the final configuration.
    update_bridge_settings(
        config_path,
        &[
            ("sync_enabled".to_string(), Some(json!(false))),
            ("routing_enabled".to_string(), Some(json!(false))),
            ("auto_provision_agents".to_string(), Some(json!(false))),
        ],
    )
    .map_err(|error| CommandError(error.to_string()))?;
    let final_config = crate::config::load_config(config_path)
        .map_err(|error| CommandError(format!("cannot reload lifecycle config: {error}")))?;
    if final_config.bridge.relay_url != config.bridge.relay_url {
        return err("refusing cleanup because the configured relay changed while stopping buzzr");
    }
    if final_config.bridge.sync_enabled
        || final_config.bridge.routing_enabled
        || final_config.bridge.auto_provision_agents
    {
        return err("refusing cleanup because automatic bridge writers could not be deactivated");
    }
    let config = &final_config;
    let mut state = store
        .load_strict()
        .map_err(|error| CommandError(format!("cannot safely reload lifecycle state: {error}")))?;
    if resolve_identity_intents(config, &mut state) {
        update_state(store, |state| {
            resolve_identity_intents(config, state);
        })?;
        state = store.load_strict().map_err(|error| {
            CommandError(format!(
                "cannot reload checkpointed lifecycle state: {error}"
            ))
        })?;
    }
    let plan = build_deprovision_plan(config_path, config, store, &state, delete_local);
    let mut admin: Option<LocalBuzzAdmin> = None;

    for action in &plan.actions {
        match action {
            DeprovisionAction::StopDaemon | DeprovisionAction::Deactivate => {}
            DeprovisionAction::ArchiveChannel {
                workspace_id,
                channel_id,
                ..
            } => {
                let client = bridge_client(config)?;
                client.archive_channel_idempotent(channel_id)?;
                update_state(store, |state| {
                    if let Some(channels) = state["channels"].as_object_mut() {
                        channels.remove(workspace_id);
                    }
                    remove_object_entry(state, "channel_memberships", channel_id);
                })?;
            }
            DeprovisionAction::RemoveChannelMember {
                channel_id,
                pubkey,
                identity_kind,
                identity_id,
                recorded_role,
                ..
            } => {
                let client = identity_client(config, identity_kind, identity_id, pubkey)?;
                let members = client.members(channel_id)?;
                let current_role = members.iter().find_map(|member| {
                    (member.get("pubkey").and_then(Value::as_str) == Some(pubkey.as_str())).then(
                        || {
                            member
                                .get("role")
                                .and_then(Value::as_str)
                                .unwrap_or("member")
                        },
                    )
                });
                if let Some(current_role) = current_role {
                    if current_role != recorded_role {
                        return err(format!(
                            "refusing to remove {} from channel {channel_id}: role changed from \
                             {recorded_role} to {current_role}",
                            short_pubkey(pubkey)
                        ));
                    }
                    client.remove_member(channel_id, pubkey)?;
                }
                update_state(store, |state| {
                    remove_membership_entry(state, channel_id, pubkey)
                })?;
            }
            DeprovisionAction::ArchiveIdentity {
                pubkey,
                identity_kind,
                identity_id,
            } => {
                let client = identity_client(config, identity_kind, identity_id, pubkey)?;
                if !client
                    .archived_identities()?
                    .iter()
                    .any(|archived| archived == pubkey)
                {
                    client.archive_identity(pubkey)?;
                }
                update_state(store, |state| {
                    state["managed_resources"]["identities"][pubkey]["archived"] = json!(true);
                })?;
            }
            DeprovisionAction::ClearOwnership {
                pubkey,
                owner_pubkey,
            } => {
                let client = match &admin {
                    Some(client) => client,
                    None => admin.insert(local_admin(config)?),
                };
                let _ = client.clear_agent_owner(owner_pubkey, pubkey)?;
                update_state(store, |state| {
                    remove_object_entry(state, "ownerships", pubkey)
                })?;
            }
            DeprovisionAction::RemoveRelayMember { pubkey } => {
                let client = match &admin {
                    Some(client) => client,
                    None => admin.insert(local_admin(config)?),
                };
                let _ = client.remove_relay_member(pubkey)?;
                update_state(store, |state| {
                    remove_object_entry(state, "relay_members", pubkey)
                })?;
            }
            DeprovisionAction::DeleteLocalData { .. } => {
                delete_local_data(config_path, config, store)?;
            }
        }
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BridgeConfig, IdentityConfig};
    use crate::state::default_state;
    use std::collections::HashMap;
    use std::fs::OpenOptions;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    #[test]
    fn plan_only_touches_resources_with_creation_provenance() {
        let mut state = default_state();
        state["channels"] = json!({
            "w1": {"channel_id": "created", "name": "owned", "origin": "created"},
            "w2": {"channel_id": "adopted", "name": "shared", "origin": "adopted"},
            "w3": {"channel_id": "legacy", "name": "old"},
        });
        let generated = "a".repeat(64);
        let imported = "b".repeat(64);
        let untrusted = "d".repeat(64);
        state["managed_resources"]["identities"][&generated] = json!({
            "origin": "generated", "identity_kind": "agent", "identity_id": "sol",
            "archived": false
        });
        state["managed_resources"]["channel_memberships"]["adopted"][&generated] =
            json!({"origin": "added", "role": "bot"});
        state["managed_resources"]["relay_members"][&generated] = json!({"origin": "added"});
        state["managed_resources"]["ownerships"][&generated] = json!({
            "origin": "assigned", "owner_pubkey": "c".repeat(64)
        });
        state["managed_resources"]["identities"][&untrusted] = json!({
            "origin": "generated", "identity_kind": "agent", "identity_id": "bridge",
            "archived": false
        });
        state["managed_resources"]["channel_memberships"]["adopted"][&untrusted] =
            json!({"origin": "adding", "role": "bot"});
        state["managed_resources"]["relay_members"][&untrusted] = json!({"origin": "manual"});
        state["managed_resources"]["ownerships"][&untrusted] = json!({
            "origin": "manual", "owner_pubkey": "c".repeat(64)
        });
        let config = Config {
            bridge: BridgeConfig::default(),
            identities: HashMap::from([
                (
                    "sol".to_string(),
                    IdentityConfig {
                        identity_id: "sol".to_string(),
                        display_name: "Sol".to_string(),
                        aliases: vec!["sol".to_string()],
                        public_key: generated,
                        private_key_env: "SOL_KEY".to_string(),
                        auth_tag_env: None,
                    },
                ),
                (
                    "bridge".to_string(),
                    IdentityConfig {
                        identity_id: "bridge".to_string(),
                        display_name: "Bridge agent".to_string(),
                        aliases: vec!["bridge".to_string()],
                        public_key: untrusted.clone(),
                        private_key_env: "MANUAL_KEY".to_string(),
                        auth_tag_env: None,
                    },
                ),
                (
                    "imported".to_string(),
                    IdentityConfig {
                        identity_id: "imported".to_string(),
                        display_name: "Imported".to_string(),
                        aliases: vec!["imported".to_string()],
                        public_key: imported,
                        private_key_env: "IMPORTED_KEY".to_string(),
                        auth_tag_env: None,
                    },
                ),
            ]),
            secrets: HashMap::new(),
        };
        let store = StateStore::new(PathBuf::from("/tmp/buzzr-test-state"));
        let plan = build_deprovision_plan(
            Path::new("/tmp/config.toml"),
            &config,
            &store,
            &state,
            false,
        );
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            DeprovisionAction::ArchiveChannel { channel_id, .. } if channel_id == "created"
        )));
        assert!(!plan.actions.iter().any(|action| matches!(
            action,
            DeprovisionAction::ArchiveChannel { channel_id, .. } if channel_id != "created"
        )));
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            DeprovisionAction::RemoveChannelMember { channel_id, .. } if channel_id == "adopted"
        )));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("legacy state")));
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("imported or legacy")));
        assert!(!plan.actions.iter().any(|action| matches!(
            action,
            DeprovisionAction::RemoveChannelMember { pubkey, .. }
                | DeprovisionAction::ClearOwnership { pubkey, .. }
                | DeprovisionAction::RemoveRelayMember { pubkey }
                if pubkey == &untrusted
        )));
        assert!(plan.actions.iter().any(|action| matches!(
            action,
            DeprovisionAction::ArchiveIdentity {
                pubkey,
                identity_kind,
                identity_id,
            } if pubkey == &untrusted && identity_kind == "agent" && identity_id == "bridge"
        )));
    }

    #[test]
    fn daemon_lock_helper() {
        let Some(runtime_dir) = std::env::var_os("BUZZR_TEST_LOCK_HELPER_DIR") else {
            return;
        };
        let runtime_dir = PathBuf::from(runtime_dir);
        fs::create_dir_all(&runtime_dir).unwrap();
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700)).unwrap();
        let lock = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(runtime_dir.join("daemon.lock"))
            .unwrap();
        fs::set_permissions(
            runtime_dir.join("daemon.lock"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        lock.lock_exclusive().unwrap();
        fs::write(
            runtime_dir.join("daemon.pid"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        while !runtime_dir.join("stop.request").exists() {
            thread::sleep(Duration::from_secs(1));
        }
    }

    #[test]
    fn stop_daemon_cooperates_only_with_the_runtime_lock_holder() {
        let directory = tempfile::tempdir().unwrap();
        let runtime_dir = directory.path().join("runtime");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "lifecycle::tests::daemon_lock_helper",
                "--nocapture",
            ])
            .env("BUZZR_TEST_LOCK_HELPER_DIR", &runtime_dir)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runtime_dir.join("daemon.pid").exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(runtime_dir.join("daemon.pid").exists());

        let outcome = stop_daemon(&runtime_dir, Duration::from_secs(5)).unwrap();
        assert_eq!(outcome, StopOutcome::Stopped(Some(child.id())));
        let _ = child.wait();
        assert!(!runtime_dir.join("daemon.pid").exists());
        assert_eq!(
            stop_daemon(&runtime_dir, Duration::from_secs(1)).unwrap(),
            StopOutcome::NotRunning
        );
    }

    #[test]
    fn local_data_deletion_is_marker_gated_and_preserves_imported_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        let managed = directory.path().join("managed.env");
        let imported = directory.path().join("imported.env");
        fs::write(&config_path, "[bridge]\n").unwrap();
        fs::write(&managed, "MANAGED=value\n").unwrap();
        fs::write(&imported, "IMPORTED=value\n").unwrap();
        let store = StateStore::new(directory.path().join("state"));
        store.save(&default_state()).unwrap();
        fs::create_dir_all(store.directory.join("avatars")).unwrap();
        fs::write(store.directory.join("avatars/bee.png"), b"png").unwrap();
        let config = Config {
            bridge: BridgeConfig {
                managed_secrets_file: Some(managed.clone()),
                secrets_files: vec![imported.clone(), managed.clone()],
                ..BridgeConfig::default()
            },
            ..Config::default()
        };

        delete_local_data(&config_path, &config, &store).unwrap();
        assert!(!config_path.exists());
        assert!(!managed.exists());
        assert!(!store.path.exists());
        assert!(!store.directory.join("avatars").exists());
        assert!(imported.exists());
    }

    #[test]
    fn local_data_deletion_rejects_broad_state_directories_before_marker_checks() {
        let store = StateStore::new(PathBuf::from("/"));
        let error = delete_local_data(Path::new("/tmp/config.toml"), &Config::default(), &store)
            .unwrap_err();
        assert!(error.to_string().contains("refusing broad state directory"));
    }
}
