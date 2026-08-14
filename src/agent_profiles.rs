//! Agent directory (kind:10100) declaration building.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::clients::nostr::dump_compact_sorted;
use crate::config::Config;
use crate::topology::Topology;

// Agent profiles are replaceable events, but refreshing them occasionally makes
// recovery deterministic if relay event storage is restored independently from
// buzzr's local state.
pub const AGENT_PROFILE_REFRESH_SECONDS: i64 = 24 * 60 * 60;

/// Truthiness for channel-state JSON values.
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

/// Stable string conversion for JSON scalars in channel state.
fn json_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => number.to_string(),
        Value::Bool(flag) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        Value::Null => "None".to_string(),
        other => other.to_string(),
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AgentProfileDeclaration {
    pub identity_id: String,
    pub public_key: String,
    pub content: Value,
}

impl AgentProfileDeclaration {
    /// `json.dumps(content, separators=(",", ":"), sort_keys=True)`.
    pub fn encoded_content(&self) -> String {
        dump_compact_sorted(&self.content)
    }

    pub fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(self.encoded_content().as_bytes()))
    }
}

/// Project buzzr's author gate into Buzz Desktop's discovery contract.
///
/// Desktop's relay-agent eligibility understands `allowlist` and `anyone`.
/// It cannot resolve buzzr's locally assigned owner for `owner-only`, so the
/// equivalent wire representation is an allowlist containing the human owner.
/// An empty allowlist represents `nobody` without publishing an unknown mode.
fn directory_access(config: &Config) -> (String, Vec<String>) {
    let mode = config.bridge.respond_to.as_str();
    if mode == "anyone" {
        return ("anyone".to_string(), Vec::new());
    }

    let mut allowed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if mode == "allowlist" {
        allowed.extend(
            config
                .bridge
                .respond_to_allowlist
                .iter()
                .map(|value| value.to_lowercase()),
        );
    }
    if mode == "owner-only" || mode == "allowlist" {
        if let Some(human_pubkey) = config.human_public_key() {
            allowed.insert(human_pubkey.to_lowercase());
        }
    }
    ("allowlist".to_string(), allowed.into_iter().collect())
}

/// Build one complete kind:10100 declaration per buzzr identity.
///
/// An identity can appear in several Herdr Spaces, so its channel list must be
/// aggregated before publishing the replaceable event. Configured identities
/// that are not currently live are declared offline with no invocable channels,
/// clearing any stale directory record left by a previous topology.
pub fn build_agent_profile_declarations(
    config: &Config,
    topology: &Topology,
    channel_state: &Value,
) -> Vec<AgentProfileDeclaration> {
    let mut channel_pairs: HashMap<String, HashSet<(String, String)>> = config
        .identities
        .keys()
        .map(|identity_id| (identity_id.clone(), HashSet::new()))
        .collect();
    let mut runtimes: HashMap<String, HashSet<String>> = config
        .identities
        .keys()
        .map(|identity_id| (identity_id.clone(), HashSet::new()))
        .collect();
    let mut active_identities: HashSet<String> = HashSet::new();

    for space in &topology.spaces {
        let mapping = channel_state
            .get(space.workspace_id.as_str())
            .filter(|value| value.is_object());
        let channel_id = mapping
            .and_then(|mapping| mapping.get("channel_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        let channel_name = match mapping.and_then(|mapping| mapping.get("name")) {
            Some(value) if json_truthy(value) => json_str(value),
            _ => space.channel_name.clone(),
        };
        for agent in &space.agents {
            let identity_id = match &agent.identity_id {
                Some(identity_id)
                    if !identity_id.is_empty() && config.identities.contains_key(identity_id) =>
                {
                    identity_id
                }
                _ => continue,
            };
            active_identities.insert(identity_id.clone());
            let runtime = agent.runtime.trim();
            if !runtime.is_empty() {
                runtimes
                    .get_mut(identity_id)
                    .expect("runtimes is keyed by config identities")
                    .insert(runtime.to_string());
            }
            if let Some(channel_id) = channel_id {
                channel_pairs
                    .get_mut(identity_id)
                    .expect("channel_pairs is keyed by config identities")
                    .insert((channel_name.clone(), channel_id.to_string()));
            }
        }
    }

    let (respond_to, respond_to_allowlist) = directory_access(config);
    let mut declarations: Vec<AgentProfileDeclaration> = Vec::new();
    let mut identity_ids: Vec<&String> = config.identities.keys().collect();
    identity_ids.sort();
    for identity_id in identity_ids {
        let identity = &config.identities[identity_id];
        let mut pairs: Vec<(String, String)> = channel_pairs[identity_id].iter().cloned().collect();
        pairs.sort_by(|left, right| {
            left.0
                .to_lowercase()
                .cmp(&right.0.to_lowercase())
                .then_with(|| left.1.cmp(&right.1))
        });
        let mut runtime_values: Vec<String> = runtimes[identity_id].iter().cloned().collect();
        runtime_values.sort();
        let agent_type = if runtime_values.len() == 1 {
            runtime_values[0].clone()
        } else {
            "herdr".to_string()
        };
        declarations.push(AgentProfileDeclaration {
            identity_id: identity_id.clone(),
            public_key: identity.public_key.clone(),
            content: json!({
                "name": identity.display_name,
                "display_name": identity.display_name,
                "agent_type": agent_type,
                "channels": pairs.iter().map(|(name, _channel_id)| name).collect::<Vec<_>>(),
                "channel_ids": pairs.iter().map(|(_name, channel_id)| channel_id).collect::<Vec<_>>(),
                "capabilities": [],
                "status": if active_identities.contains(identity_id) { "online" } else { "offline" },
                "respond_to": respond_to,
                "respond_to_allowlist": respond_to_allowlist,
                // The bridge must be able to add its identities without the
                // human signing every channel membership event.
                "channel_add_policy": "anyone",
            }),
        });
    }
    declarations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hashes_the_sorted_compact_encoding() {
        let declaration = AgentProfileDeclaration {
            identity_id: "sol".to_string(),
            public_key: "a".repeat(64),
            content: json!({"b": 1, "a": [true, null]}),
        };
        assert_eq!(declaration.encoded_content(), "{\"a\":[true,null],\"b\":1}");
        let fingerprint = declaration.fingerprint();
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
