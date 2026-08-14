//! Local Buzz relay provisioning: bridge identity, agent identities, relay
//! membership, and ownership binding.
//!
//! All failures surface as `ConfigError`, giving callers one error type for
//! configuration, admin, and Nostr operations.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use regex::Regex;
use serde_json::Value;

use crate::clients::{LocalBuzzAdmin, NostrTools};
use crate::config::{
    append_identities, load_config, normalize_name, update_bridge_settings, update_dotenv, Config,
    ConfigError, IdentityConfig,
};
use crate::state::{normalize_managed_resources, StateStore};
use crate::topology::{build_topology, AgentBinding, Topology};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvisionReport {
    pub bridge_created: bool,
    pub identities_created: Vec<String>,
    pub relay_members_added: usize,
    pub relay_member_pubkeys_added: Vec<String>,
    pub ownership_bound: usize,
}

fn command_err(error: crate::clients::CommandError) -> ConfigError {
    ConfigError(error.to_string())
}

fn private_env_name(identity_id: &str) -> String {
    let uppercased = identity_id.to_uppercase();
    let token = Regex::new(r"[^A-Z0-9]+")
        .unwrap()
        .replace_all(&uppercased, "_");
    let token = token.trim_matches('_');
    let token = if token.is_empty() { "AGENT" } else { token };
    format!("BUZZR_AGENT_{token}_PRIVATE_KEY")
}

fn aliases(binding: &AgentBinding) -> Vec<String> {
    let mut values = vec![binding.display_label.clone()];
    if let Some(agent_name) = &binding.agent_name {
        if !agent_name.is_empty() {
            values.push(agent_name.clone());
        }
    }
    let tab_label = binding.tab_label.trim();
    if !tab_label.is_empty() && !tab_label.chars().all(|c| c.is_numeric()) {
        values.push(binding.tab_label.clone());
    }
    let mut result: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for value in values {
        let normalized = normalize_name(&value);
        if !normalized.is_empty() && !seen.contains(&normalized) {
            seen.insert(normalized);
            result.push(value);
        }
    }
    result
}

fn admin(config: &Config) -> Result<LocalBuzzAdmin, ConfigError> {
    let compose_file = config.bridge.compose_file.clone().ok_or_else(|| {
        ConfigError("bridge.compose_file is required for local automatic provisioning".to_string())
    })?;
    if !compose_file.exists() {
        return Err(ConfigError(format!(
            "Buzz Compose file does not exist: {}",
            compose_file.display()
        )));
    }
    let mut admin = LocalBuzzAdmin::new(compose_file);
    admin.relay_service = config.bridge.relay_service.clone();
    admin.postgres_service = config.bridge.postgres_service.clone();
    admin.postgres_user = config.bridge.postgres_user.clone();
    admin.postgres_database = config.bridge.postgres_database.clone();
    Ok(admin)
}

fn managed_secrets(config: &Config) -> Result<PathBuf, ConfigError> {
    config.bridge.managed_secrets_file.clone().ok_or_else(|| {
        ConfigError("bridge.managed_secrets_file is required for generated identities".to_string())
    })
}

fn planned_agent_identity_ids(
    config: &Config,
    snapshot: &Value,
) -> Result<Vec<String>, ConfigError> {
    let topology = build_topology(snapshot, config);
    let mut identity_ids = BTreeSet::new();
    for binding in topology.agents() {
        if binding
            .identity_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        {
            continue;
        }
        let mut identity_id = normalize_name(&binding.display_label);
        if identity_id.is_empty() {
            identity_id = normalize_name(&format!("{}-{}", binding.runtime, binding.pane_id));
        }
        if identity_id.is_empty() {
            return Err(ConfigError(format!(
                "cannot derive an identity id for pane {}",
                binding.pane_id
            )));
        }
        identity_ids.insert(identity_id);
    }
    Ok(identity_ids.into_iter().collect())
}

fn record_identity_intents(
    store: &StateStore,
    intents: &[(String, String, String, String)],
) -> Result<(), ConfigError> {
    if intents.is_empty() {
        return Ok(());
    }
    update_provenance(store, |state| {
        for (identity_kind, identity_id, private_key_env, expected_pubkey) in intents {
            let key = format!("{identity_kind}:{identity_id}");
            state["managed_resources"]["identity_intents"][&key] = serde_json::json!({
                "identity_kind": identity_kind,
                "identity_id": identity_id,
                "private_key_env": private_key_env,
                "expected_pubkey": expected_pubkey,
            });
        }
    })
}

/// Resolve write-ahead identity intents into ordinary generated-identity
/// provenance once their keypair is present in the loaded configuration.
/// This is pure so deprovision preview remains filesystem-read-only.
pub fn resolve_identity_intents(config: &Config, state: &mut Value) -> bool {
    normalize_managed_resources(state);
    let tools = NostrTools::new();
    let intents: Vec<(String, Value)> = state["managed_resources"]["identity_intents"]
        .as_object()
        .map(|intents| {
            intents
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect()
        })
        .unwrap_or_default();
    let mut resolved = Vec::new();
    for (key, intent) in intents {
        let identity_kind = intent
            .get("identity_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let identity_id = intent
            .get("identity_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let private_key_env = intent
            .get("private_key_env")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let expected_pubkey = intent
            .get("expected_pubkey")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let pubkey = match identity_kind {
            "bridge" => {
                let (private_key, _) = config.bridge_credentials();
                match (
                    private_key.filter(|value| !value.is_empty()),
                    config.bridge.bridge_public_key.clone(),
                ) {
                    (Some(private_key), Some(pubkey))
                        if tools.public_key(&private_key).ok().as_deref()
                            == Some(pubkey.as_str()) =>
                    {
                        Some(pubkey)
                    }
                    _ => None,
                }
            }
            "agent" => {
                let private_key = config
                    .identity_credentials(identity_id)
                    .ok()
                    .and_then(|(private_key, _)| private_key);
                match (
                    private_key.filter(|value| !value.is_empty()),
                    config.identities.get(identity_id),
                ) {
                    (Some(private_key), Some(identity))
                        if tools.public_key(&private_key).ok().as_deref()
                            == Some(identity.public_key.as_str()) =>
                    {
                        Some(identity.public_key.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        };
        if let Some(pubkey) = pubkey.filter(|value| {
            !value.is_empty() && !expected_pubkey.is_empty() && value == expected_pubkey
        }) {
            state["managed_resources"]["identities"][&pubkey] = serde_json::json!({
                "origin": "generated",
                "identity_kind": identity_kind,
                "identity_id": identity_id,
                "private_key_env": private_key_env,
                "archived": false,
            });
            resolved.push(key);
        }
    }
    if let Some(intents) = state["managed_resources"]["identity_intents"].as_object_mut() {
        for key in &resolved {
            intents.remove(key);
        }
    }
    !resolved.is_empty()
}

fn recover_identity_intents(store: &StateStore, config: &Config) -> Result<(), ConfigError> {
    update_provenance(store, |state| {
        // Credential lookup was already validated by the caller's loaded
        // config; preserve unresolved intents if a secret is still absent.
        resolve_identity_intents(config, state);
    })
}

/// Create the non-human operational identity once and persist it privately.
pub fn ensure_bridge_identity(
    config_path: &Path,
    config: &Config,
) -> Result<(Config, bool), ConfigError> {
    ensure_bridge_identity_with_generated(config_path, config, None)
}

fn ensure_bridge_identity_with_generated(
    config_path: &Path,
    config: &Config,
    generated: Option<(String, String)>,
) -> Result<(Config, bool), ConfigError> {
    let tools = NostrTools::new();
    let (private_key, _auth) = config.bridge_credentials();
    let public_key = config.bridge.bridge_public_key.clone();
    let mut created = false;

    if let Some(private_key) = private_key {
        let derived = tools.public_key(&private_key).map_err(command_err)?;
        match &public_key {
            Some(configured) if derived != *configured => {
                return Err(ConfigError(
                    "configured bridge_public_key does not match the bridge private key"
                        .to_string(),
                ));
            }
            None => {
                update_bridge_settings(
                    config_path,
                    &[(
                        "bridge_public_key".to_string(),
                        Some(serde_json::Value::String(derived)),
                    )],
                )?;
            }
            _ => {}
        }
    } else if public_key.is_some() {
        return Err(ConfigError(format!(
            "{} is missing but bridge_public_key is configured",
            config.bridge.bridge_private_key_env
        )));
    } else {
        let (private_key, generated_public_key) = match generated {
            Some(keys) => keys,
            None => tools.generate_keypair().map_err(command_err)?,
        };
        update_dotenv(
            &managed_secrets(config)?,
            &[(config.bridge.bridge_private_key_env.clone(), private_key)],
        )?;
        update_bridge_settings(
            config_path,
            &[(
                "bridge_public_key".to_string(),
                Some(serde_json::Value::String(generated_public_key)),
            )],
        )?;
        created = true;
    }

    Ok((load_config(config_path)?, created))
}

/// Create one stable Buzz identity for each currently unmapped agent label.
pub fn ensure_agent_identities(
    config_path: &Path,
    config: &Config,
    snapshot: &Value,
) -> Result<(Config, Topology, Vec<IdentityConfig>), ConfigError> {
    ensure_agent_identities_with_generated(config_path, config, snapshot, None)
}

fn ensure_agent_identities_with_generated(
    config_path: &Path,
    config: &Config,
    snapshot: &Value,
    generated: Option<&HashMap<String, (String, String)>>,
) -> Result<(Config, Topology, Vec<IdentityConfig>), ConfigError> {
    let topology = build_topology(snapshot, config);
    let mut grouped: BTreeMap<String, Vec<&AgentBinding>> = BTreeMap::new();
    for binding in topology.agents() {
        if binding
            .identity_id
            .as_ref()
            .map(|identity_id| !identity_id.is_empty())
            .unwrap_or(false)
        {
            continue;
        }
        let mut identity_id = normalize_name(&binding.display_label);
        if identity_id.is_empty() {
            identity_id = normalize_name(&format!("{}-{}", binding.runtime, binding.pane_id));
        }
        if identity_id.is_empty() {
            return Err(ConfigError(format!(
                "cannot derive an identity id for pane {}",
                binding.pane_id
            )));
        }
        grouped.entry(identity_id).or_default().push(binding);
    }

    if grouped.is_empty() {
        return Ok((config.clone(), topology, Vec::new()));
    }

    let tools = NostrTools::new();
    let mut identities: Vec<IdentityConfig> = Vec::new();
    let mut secrets: Vec<(String, String)> = Vec::new();
    for (identity_id, bindings) in &grouped {
        if config.identities.contains_key(identity_id) {
            // Defensive: this normally cannot happen because the identity id is
            // itself an alias and build_topology would already have matched it.
            continue;
        }
        let (private_key, public_key) = match generated.and_then(|keys| keys.get(identity_id)) {
            Some(keys) => keys.clone(),
            None => tools.generate_keypair().map_err(command_err)?,
        };
        let env_name = private_env_name(identity_id);
        let mut alias_values: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for binding in bindings {
            for alias in aliases(binding) {
                let normalized = normalize_name(&alias);
                if !seen.contains(&normalized) {
                    seen.insert(normalized);
                    alias_values.push(alias);
                }
            }
        }
        identities.push(IdentityConfig {
            identity_id: identity_id.clone(),
            display_name: bindings[0].display_label.clone(),
            aliases: if alias_values.is_empty() {
                vec![identity_id.clone()]
            } else {
                alias_values
            },
            public_key,
            private_key_env: env_name.clone(),
            auth_tag_env: None,
        });
        secrets.push((env_name, private_key));
    }

    let mut config = config.clone();
    let mut topology = topology;
    if !identities.is_empty() {
        update_dotenv(&managed_secrets(&config)?, &secrets)?;
        append_identities(config_path, &identities)?;
        config = load_config(config_path)?;
        topology = build_topology(snapshot, &config);
    }
    Ok((config, topology, identities))
}

/// Fully provision bridge/agents in a locally administered Buzz relay.
pub fn provision_local(
    config_path: &Path,
    snapshot: &Value,
    store: &StateStore,
) -> Result<(Config, Topology, ProvisionReport), ConfigError> {
    provision_local_internal(config_path, snapshot, None, Some(store))
}

fn update_provenance<F>(store: &StateStore, update: F) -> Result<(), ConfigError>
where
    F: FnOnce(&mut Value),
{
    store
        .with_lock(|| -> Result<(), ConfigError> {
            let mut state = store.load_strict().map_err(io_state)?;
            normalize_managed_resources(&mut state);
            update(&mut state);
            store.save(&state).map_err(io_state)
        })
        .map_err(io_state)??;
    Ok(())
}

fn record_generated_identities(
    store: &StateStore,
    config: &Config,
    bridge_created: bool,
    created_identity_ids: &[String],
) -> Result<(), ConfigError> {
    let mut generated: Vec<(String, String, String, String)> = Vec::new();
    if bridge_created {
        if let Some(pubkey) = config.bridge.bridge_public_key.clone() {
            generated.push((
                pubkey,
                "bridge".to_string(),
                "bridge".to_string(),
                config.bridge.bridge_private_key_env.clone(),
            ));
        }
    }
    for identity_id in created_identity_ids {
        if let Some(identity) = config.identities.get(identity_id) {
            generated.push((
                identity.public_key.clone(),
                "agent".to_string(),
                identity_id.clone(),
                identity.private_key_env.clone(),
            ));
        }
    }
    if generated.is_empty() {
        return Ok(());
    }
    update_provenance(store, |state| {
        for (pubkey, identity_kind, identity_id, private_key_env) in generated {
            state["managed_resources"]["identities"][&pubkey] = serde_json::json!({
                "origin": "generated",
                "identity_kind": identity_kind,
                "identity_id": identity_id,
                "private_key_env": private_key_env,
                "archived": false,
            });
        }
    })
}

fn record_generated_resource(
    store: &StateStore,
    section: &str,
    pubkey: &str,
    record: Value,
) -> Result<(), ConfigError> {
    update_provenance(store, |state| {
        let generated = state["managed_resources"]["identities"]
            .get(pubkey)
            .and_then(|identity| identity.get("origin"))
            .and_then(Value::as_str)
            == Some("generated");
        if generated {
            state["managed_resources"][section][pubkey] = record;
        }
    })
}

/// Persist provenance only for identities generated during this provisioning
/// transaction. Existing/imported identities remain deliberately unmanaged.
pub fn record_provisioned_resources(
    store: &StateStore,
    config: &Config,
    report: &ProvisionReport,
) -> Result<(), ConfigError> {
    record_generated_identities(
        store,
        config,
        report.bridge_created,
        &report.identities_created,
    )?;
    let human = config.human_public_key();
    for pubkey in &report.relay_member_pubkeys_added {
        record_generated_resource(
            store,
            "relay_members",
            pubkey,
            serde_json::json!({"origin": "added"}),
        )?;
    }
    if let Some(human) = human {
        let pubkeys: Vec<String> = config
            .bridge
            .bridge_public_key
            .iter()
            .chain(
                config
                    .identities
                    .values()
                    .map(|identity| &identity.public_key),
            )
            .cloned()
            .collect();
        for pubkey in pubkeys {
            if pubkey != human {
                record_generated_resource(
                    store,
                    "ownerships",
                    &pubkey,
                    serde_json::json!({"origin": "assigned", "owner_pubkey": human}),
                )?;
            }
        }
    }
    Ok(())
}

fn io_state(error: std::io::Error) -> ConfigError {
    ConfigError(format!(
        "cannot persist managed-resource provenance: {error}"
    ))
}

/// `provision_local` with an injectable admin client (tests, remote relays).
pub fn provision_local_with_admin(
    config_path: &Path,
    snapshot: &Value,
    admin_override: Option<&LocalBuzzAdmin>,
) -> Result<(Config, Topology, ProvisionReport), ConfigError> {
    provision_local_internal(config_path, snapshot, admin_override, None)
}

/// Provisioning seam that keeps the injectable admin while exercising the
/// same crash-consistent provenance checkpoints as production.
pub fn provision_local_with_admin_and_store(
    config_path: &Path,
    snapshot: &Value,
    admin_override: &LocalBuzzAdmin,
    store: &StateStore,
) -> Result<(Config, Topology, ProvisionReport), ConfigError> {
    provision_local_internal(config_path, snapshot, Some(admin_override), Some(store))
}

fn provision_local_internal(
    config_path: &Path,
    snapshot: &Value,
    admin_override: Option<&LocalBuzzAdmin>,
    store: Option<&StateStore>,
) -> Result<(Config, Topology, ProvisionReport), ConfigError> {
    let config = load_config(config_path)?;
    let human_pubkey = config
        .human_public_key()
        .ok_or_else(|| ConfigError("bridge.human_pubkey is required".to_string()))?;
    let tools = NostrTools::new();
    let (bridge_private_key, _) = config.bridge_credentials();
    let bridge_missing = bridge_private_key
        .as_deref()
        .map(str::is_empty)
        .unwrap_or(true)
        && config
            .bridge
            .bridge_public_key
            .as_deref()
            .map(str::is_empty)
            .unwrap_or(true);
    let generated_bridge = if store.is_some() && bridge_missing {
        Some(tools.generate_keypair().map_err(command_err)?)
    } else {
        None
    };
    if let Some(store) = store {
        recover_identity_intents(store, &config)?;
        if let Some((_private_key, expected_pubkey)) = &generated_bridge {
            record_identity_intents(
                store,
                &[(
                    "bridge".to_string(),
                    "bridge".to_string(),
                    config.bridge.bridge_private_key_env.clone(),
                    expected_pubkey.clone(),
                )],
            )?;
        }
    }
    let (config, bridge_created) =
        ensure_bridge_identity_with_generated(config_path, &config, generated_bridge)?;
    if let Some(store) = store {
        recover_identity_intents(store, &config)?;
        record_generated_identities(store, &config, bridge_created, &[])?;
    }
    let mut generated_agents: HashMap<String, (String, String)> = HashMap::new();
    if let Some(store) = store {
        let mut intents = Vec::new();
        for identity_id in planned_agent_identity_ids(&config, snapshot)? {
            let keys = tools.generate_keypair().map_err(command_err)?;
            intents.push((
                "agent".to_string(),
                identity_id.clone(),
                private_env_name(&identity_id),
                keys.1.clone(),
            ));
            generated_agents.insert(identity_id, keys);
        }
        record_identity_intents(store, &intents)?;
    }
    let generated_agents = store.is_some().then_some(&generated_agents);
    let (config, topology, created_identities) =
        ensure_agent_identities_with_generated(config_path, &config, snapshot, generated_agents)?;
    let created_identity_ids: Vec<String> = created_identities
        .iter()
        .map(|identity| identity.identity_id.clone())
        .collect();
    if let Some(store) = store {
        recover_identity_intents(store, &config)?;
        record_generated_identities(store, &config, false, &created_identity_ids)?;
    }

    let bridge_public_key = config.bridge.bridge_public_key.clone();
    let (bridge_private_key, _bridge_auth) = config.bridge_credentials();
    let bridge_public_key = match (bridge_public_key, bridge_private_key) {
        (Some(public_key), Some(private_key))
            if !public_key.is_empty() && !private_key.is_empty() =>
        {
            public_key
        }
        _ => {
            return Err(ConfigError(
                "bridge identity provisioning did not produce a complete keypair".to_string(),
            ))
        }
    };

    let owned_admin;
    let admin = match admin_override {
        Some(admin) => admin,
        None => {
            owned_admin = admin(&config)?;
            &owned_admin
        }
    };
    let current_relay_members = admin.relay_member_pubkeys().map_err(command_err)?;
    let mut desired_pubkeys = vec![bridge_public_key];
    desired_pubkeys.extend(
        config
            .identities
            .values()
            .map(|identity| identity.public_key.clone()),
    );
    let unique_pubkeys: BTreeSet<String> = desired_pubkeys.iter().cloned().collect();
    let mut added_pubkeys = Vec::new();
    for pubkey in &unique_pubkeys {
        if !current_relay_members.contains(pubkey) {
            if let Some(store) = store {
                // Write-ahead provenance makes a successful remote mutation
                // recoverable even if the process dies before the next line.
                record_generated_resource(
                    store,
                    "relay_members",
                    pubkey,
                    serde_json::json!({"origin": "added"}),
                )?;
            }
            admin.add_relay_member(pubkey).map_err(command_err)?;
            added_pubkeys.push(pubkey.clone());
        }
    }

    // This trusted local write is the missing ownership link: it never requires
    // the human's secret key, and refuses to overwrite another existing owner.
    for pubkey in &unique_pubkeys {
        if pubkey == &human_pubkey {
            continue;
        }
        if let Some(store) = store {
            record_generated_resource(
                store,
                "ownerships",
                pubkey,
                serde_json::json!({"origin": "assigned", "owner_pubkey": human_pubkey}),
            )?;
        }
        admin
            .assign_agent_owner(&human_pubkey, std::slice::from_ref(pubkey))
            .map_err(command_err)?;
    }

    let report = ProvisionReport {
        bridge_created,
        identities_created: created_identity_ids,
        relay_members_added: added_pubkeys.len(),
        relay_member_pubkeys_added: added_pubkeys,
        ownership_bound: unique_pubkeys.len(),
    };
    Ok((config, topology, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(display_label: &str, agent_name: Option<&str>, tab_label: &str) -> AgentBinding {
        AgentBinding {
            workspace_id: "w1".to_string(),
            workspace_label: "Alpha".to_string(),
            channel_name: "alpha".to_string(),
            pane_id: "w1:p1".to_string(),
            terminal_id: "term-1".to_string(),
            tab_id: "w1:t1".to_string(),
            tab_label: tab_label.to_string(),
            runtime: "codex".to_string(),
            status: "idle".to_string(),
            agent_name: agent_name.map(str::to_string),
            display_label: display_label.to_string(),
            identity_id: None,
            public_key: None,
        }
    }

    #[test]
    fn private_env_name_normalization_is_stable() {
        assert_eq!(private_env_name("sol"), "BUZZR_AGENT_SOL_PRIVATE_KEY");
        assert_eq!(
            private_env_name("K3 Agent!"),
            "BUZZR_AGENT_K3_AGENT_PRIVATE_KEY"
        );
        assert_eq!(private_env_name("---"), "BUZZR_AGENT_AGENT_PRIVATE_KEY");
    }

    #[test]
    fn aliases_dedupe_by_normalized_name() {
        assert_eq!(
            aliases(&binding("Sol", Some("sol"), "Sol")),
            vec!["Sol".to_string()]
        );
        assert_eq!(
            aliases(&binding("Sol", Some("helper"), "2")),
            vec!["Sol".to_string(), "helper".to_string()]
        );
        assert_eq!(
            aliases(&binding("Sol", None, "Workbench")),
            vec!["Sol".to_string(), "Workbench".to_string()]
        );
    }
}
