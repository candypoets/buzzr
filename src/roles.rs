//! Opt-in persistent identities and durable mention delivery. No project scheduler.
use std::collections::{BTreeMap, HashSet};
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::clients::{run_with_timeout, CommandError};
use crate::config::{normalize_name, Config, ConfigError};
use crate::topology::{AgentBinding, SpaceBinding, Topology};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistentRole {
    pub project: String,
    pub role: String,
    pub channel_id: String,
    pub channel_name: String,
    pub launcher: Vec<String>,
    /// Optional explicit enrollment time. Otherwise the first poll enrolls now.
    pub since: Option<i64>,
    /// Opt-in native Buzz task repository, independent of local checkout paths.
    pub tasks: Option<crate::tasks::TaskRepo>,
    /// Other repositories belonging to this same project. The primary remains
    /// the default for creates; reads aggregate the explicit allowlist.
    #[serde(default)]
    pub additional_task_repositories: Vec<crate::tasks::TaskRepo>,
    /// Opt-in: unaddressed messages from the configured human go to this role.
    #[serde(default)]
    pub default_for_channel: bool,
}

pub fn parse(raw: Option<&toml::Value>) -> Result<BTreeMap<String, PersistentRole>, ConfigError> {
    let roles: BTreeMap<String, PersistentRole> = match raw {
        None => BTreeMap::new(),
        Some(value) => value
            .clone()
            .try_into()
            .map_err(|_| ConfigError("invalid persistent_roles configuration".into()))?,
    };
    let mut projects = BTreeMap::new();
    let mut channels = BTreeMap::new();
    let mut bindings = HashSet::new();
    let mut task_repositories = BTreeMap::new();
    let mut default_channels = HashSet::new();
    for (id, role) in &roles {
        if role.default_for_channel && !default_channels.insert(&role.channel_id) {
            return Err(ConfigError(
                "a channel can have only one default role".into(),
            ));
        }
        if role.additional_task_repositories.len() > 7
            || (role.tasks.is_none() && !role.additional_task_repositories.is_empty())
        {
            return Err(ConfigError(
                "additional task repositories require a primary and at most seven entries".into(),
            ));
        }
        let mut role_repositories = HashSet::new();
        for repo in role.tasks.iter().chain(&role.additional_task_repositories) {
            repo.validate().map_err(ConfigError)?;
            if !role_repositories.insert(repo.coordinate()) {
                return Err(ConfigError("duplicate task repository in role".into()));
            }
            if task_repositories
                .insert(repo.coordinate(), &role.project)
                .is_some_and(|p| p != &role.project)
            {
                return Err(ConfigError(
                    "persistent projects must have distinct task repositories".into(),
                ));
            }
        }
        if [id, &role.project, &role.role]
            .iter()
            .any(|s| s.is_empty() || normalize_name(s) != **s)
            || role.channel_id.is_empty()
            || role.channel_name.is_empty()
            || role.launcher.is_empty()
            || role
                .launcher
                .iter()
                .any(|s| s.is_empty() || s.contains('\0'))
            || !bindings.insert((&role.project, &role.role))
        {
            return Err(ConfigError("persistent roles require unique normalized ids/project-role pairs, channel ids and launcher argv".into()));
        }
        if projects
            .insert(&role.project, &role.channel_id)
            .is_some_and(|v| v != &role.channel_id)
            || channels
                .insert(&role.channel_id, &role.project)
                .is_some_and(|v| v != &role.project)
        {
            return Err(ConfigError(
                "persistent projects must have distinct explicit channel bindings".into(),
            ));
        }
    }
    Ok(roles)
}

pub fn workspace_key(project: &str) -> String {
    format!("buzzr-role:{project}")
}

/// Configured roles exist even with no workspace or process. Never infer identity
/// from a repo path, workspace label, native session id or runtime kind.
pub fn add_topology(topology: &mut Topology, config: &Config) {
    for (id, role) in &config.bridge.persistent_roles {
        let workspace_id = workspace_key(&role.project);
        if !topology
            .spaces
            .iter()
            .any(|s| s.workspace_id == workspace_id)
        {
            topology.spaces.push(SpaceBinding {
                workspace_id: workspace_id.clone(),
                workspace_label: role.project.clone(),
                channel_name: role.channel_name.clone(),
                number: 0,
                agents: vec![],
            });
        }
        let identity = config.identities.get(id);
        let space = topology
            .spaces
            .iter_mut()
            .find(|s| s.workspace_id == workspace_id)
            .unwrap();
        space.agents.push(AgentBinding {
            workspace_id,
            workspace_label: role.project.clone(),
            channel_name: role.channel_name.clone(),
            pane_id: String::new(),
            terminal_id: String::new(),
            tab_id: String::new(),
            tab_label: String::new(),
            runtime: "persistent-role".into(),
            status: "offline".into(),
            agent_name: Some(id.clone()),
            display_label: id.clone(),
            identity_id: identity.map(|_| id.clone()),
            public_key: identity.map(|i| i.public_key.clone()),
        });
    }
}

pub fn bind_channels(config: &Config, state: &mut Value) {
    for role in config.bridge.persistent_roles.values() {
        state["channels"][workspace_key(&role.project)] = json!({"channel_id": role.channel_id, "name": role.channel_name, "space_label": role.project, "origin": "adopted"});
    }
}

pub fn request_id(role_id: &str, channel: &str, event: &str) -> String {
    hex::encode(Sha256::digest(
        format!("{role_id}\0{channel}\0{event}").as_bytes(),
    ))
}

/// Called only after channel-scoped mention and author checks. Never prune this
/// dedup ledger by arbitrary count: cursor rewind must not replay old requests.
pub fn enqueue(
    state: &mut Value,
    role_id: &str,
    role: &PersistentRole,
    event: &Value,
    now: i64,
) -> String {
    let id = request_id(
        role_id,
        &role.channel_id,
        event["id"].as_str().unwrap_or_default(),
    );
    if state["role_requests"].get(&id).is_none() {
        state["role_requests"][&id] = json!({"role_id":role_id, "project":role.project, "channel_id":role.channel_id, "event":event, "status":"queued", "created_at":now, "not_before":0});
    }
    id
}

/// Child contract is JSON over stdin/stdout. Never expose arbitrary child errors
/// or inherit bridge keys. The child reads its own quota credential source.
pub fn call_launcher(
    config: &Config,
    role: &PersistentRole,
    request: &Value,
) -> Result<Value, CommandError> {
    let mut command = Command::new(&role.launcher[0]);
    command.args(&role.launcher[1..]);
    for (name, _) in std::env::vars() {
        if name.starts_with("BUZZ")
            || name.starts_with("NOSTR")
            || name.starts_with("PAPERCLIP")
            || name == "CLIPROXYAPI_MANAGEMENT_KEY"
        {
            command.env_remove(name);
        }
    }
    command.env_remove(&config.bridge.bridge_private_key_env);
    if let Some(name) = &config.bridge.bridge_auth_tag_env {
        command.env_remove(name);
    }
    for identity in config.identities.values() {
        command.env_remove(&identity.private_key_env);
        if let Some(name) = &identity.auth_tag_env {
            command.env_remove(name);
        }
    }
    let input =
        serde_json::to_string(request).map_err(|_| CommandError("invalid role request".into()))?;
    let output = run_with_timeout(&mut command, Some(&input), Duration::from_secs(55))
        .map_err(|_| CommandError("role launcher unavailable or timed out".into()))?;
    if output.code != 0 || output.stdout.len() > 65536 {
        return Err(CommandError("role launcher failed".into()));
    }
    let value: Value = serde_json::from_str(&output.stdout)
        .map_err(|_| CommandError("invalid role launcher response".into()))?;
    if value["version"] != 1
        || ![
            "queued",
            "ready",
            "busy",
            "starting",
            "blocked",
            "delivered",
            "uncertain",
        ]
        .contains(&value["state"].as_str().unwrap_or_default())
    {
        return Err(CommandError("invalid role launcher response".into()));
    }
    Ok(value)
}

/// Save a bounded diagnostic projection, not raw launcher output or credentials.
pub fn diagnostic(value: &Value) -> Value {
    let reason = value["reason"].as_str().unwrap_or("");
    let reason = if [
        "",
        "quota",
        "unknown_capacity",
        "auth_error",
        "compatibility",
        "startup",
        "busy",
        "approval",
        "configuration",
        "ambiguous_activation",
        "ambiguous_delivery",
        "unavailable",
    ]
    .contains(&reason)
    {
        reason
    } else {
        "unavailable"
    };
    json!({"state":value["state"].as_str().unwrap_or("blocked"), "reason":reason,
        "route":value["route"].as_str().filter(|s| s.len() <= 128 && normalize_name(s) == *s),
        "fallback":value["fallback"].as_bool().unwrap_or(false),
        "retry_at":value["retry_at"].as_i64()})
}

pub fn summary(state: &Value) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    if let Some(requests) = state["role_requests"].as_object() {
        for entry in requests.values() {
            *counts
                .entry(entry["status"].as_str().unwrap_or("invalid").into())
                .or_default() += 1;
        }
    }
    json!({"counts": counts, "roles":state["role_status"], "poll_errors":state["role_poll_errors"]})
}
