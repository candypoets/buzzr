//! Herdr snapshot → Buzz channel topology mapping.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::Value;

use crate::config::{normalize_name, quoted_repr, Config};

/// Channel name derived from a workspace label (max 64 chars, no trailing '-').
pub fn channel_slug(label: &str) -> String {
    let mut slug = normalize_name(label);
    if slug.is_empty() {
        slug = "herdr-space".to_string();
    }
    // normalize_name yields ASCII, so 64 chars == 64 bytes here.
    let truncated: String = slug.chars().take(64).collect();
    truncated.trim_end_matches('-').to_string()
}

fn meaningful_tab_label(label: &str) -> bool {
    let normalized = label.trim();
    !normalized.is_empty() && !normalized.chars().all(|c| c.is_numeric())
}

/// Match one character against a `[...]` class starting at `pattern[start]`.
///
/// Returns `(matched, index_after_class)`, or `None` when the class is
/// unterminated (fnmatch then treats `[` as a literal).
fn match_fnmatch_class(c: char, pattern: &[char], start: usize) -> Option<(bool, usize)> {
    let n = pattern.len();
    let mut j = start + 1;
    let mut negate = false;
    if j < n && pattern[j] == '!' {
        negate = true;
        j += 1;
    }
    // A leading ']' is a literal member of the class.
    let mut items: Vec<char> = Vec::new();
    if j < n && pattern[j] == ']' {
        items.push(']');
        j += 1;
    }
    while j < n && pattern[j] != ']' {
        items.push(pattern[j]);
        j += 1;
    }
    if j >= n {
        return None;
    }
    let mut matched = false;
    let mut k = 0;
    while k < items.len() {
        // Ranges: `a-z`; a trailing '-' stays literal. Backslashes have no
        // special meaning in fnmatch classes.
        if k + 2 < items.len() && items[k + 1] == '-' {
            if items[k] <= c && c <= items[k + 2] {
                matched = true;
            }
            k += 3;
        } else {
            if items[k] == c {
                matched = true;
            }
            k += 1;
        }
    }
    Some((matched != negate, j + 1))
}

/// Case-sensitive filename matching with `*`/`?` wildcards, `[...]` classes,
/// no escape character, and wildcards that also match newlines.
pub fn fnmatchcase(name: &str, pattern: &str) -> bool {
    let name: Vec<char> = name.chars().collect();
    let pattern: Vec<char> = pattern.chars().collect();
    let (mut ni, mut pi) = (0, 0);
    let (mut star_p, mut star_n) = (usize::MAX, 0);
    while ni < name.len() {
        if pi < pattern.len() {
            match pattern[pi] {
                '?' => {
                    ni += 1;
                    pi += 1;
                    continue;
                }
                '*' => {
                    while pi < pattern.len() && pattern[pi] == '*' {
                        pi += 1;
                    }
                    star_p = pi;
                    star_n = ni;
                    continue;
                }
                '[' => match match_fnmatch_class(name[ni], &pattern, pi) {
                    Some((true, next)) => {
                        ni += 1;
                        pi = next;
                        continue;
                    }
                    Some((false, _)) => {}
                    None if name[ni] == '[' => {
                        ni += 1;
                        pi += 1;
                        continue;
                    }
                    None => {}
                },
                c if name[ni] == c => {
                    ni += 1;
                    pi += 1;
                    continue;
                }
                _ => {}
            }
        }
        // Mismatch: backtrack to the last '*', letting it consume one more char.
        if star_p != usize::MAX && star_n < name.len() {
            star_n += 1;
            ni = star_n;
            pi = star_p;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

/// Stable string conversion for JSON scalars in a topology snapshot.
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

/// Convert a present JSON value to a string, otherwise use the default.
fn json_str_or(value: Option<&Value>, default: &str) -> String {
    match value {
        Some(value) => json_str(value),
        None => default.to_string(),
    }
}

fn json_int(value: Option<&Value>) -> i64 {
    match value {
        Some(Value::Number(number)) => number
            .as_i64()
            .or_else(|| number.as_u64().map(|v| v as i64))
            .or_else(|| number.as_f64().map(|v| v as i64))
            .unwrap_or(0),
        Some(Value::String(text)) => text.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

/// Truthiness for topology JSON values.
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentBinding {
    pub workspace_id: String,
    pub workspace_label: String,
    pub channel_name: String,
    pub pane_id: String,
    pub terminal_id: String,
    pub tab_id: String,
    pub tab_label: String,
    pub runtime: String,
    pub status: String,
    pub agent_name: Option<String>,
    pub display_label: String,
    pub identity_id: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpaceBinding {
    pub workspace_id: String,
    pub workspace_label: String,
    pub channel_name: String,
    pub number: i64,
    pub agents: Vec<AgentBinding>,
}

impl SpaceBinding {
    /// Sorted, deduplicated pubkeys of the mapped agents in this space.
    pub fn member_pubkeys(&self) -> Vec<String> {
        self.agents
            .iter()
            .filter_map(|agent| agent.public_key.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Topology {
    pub spaces: Vec<SpaceBinding>,
    pub warnings: Vec<String>,
}

impl Topology {
    /// All agent bindings across all spaces.
    pub fn agents(&self) -> Vec<&AgentBinding> {
        self.spaces
            .iter()
            .flat_map(|space| space.agents.iter())
            .collect()
    }
}

fn included(label: &str, config: &Config) -> bool {
    let included = config
        .bridge
        .include_spaces
        .iter()
        .any(|pattern| fnmatchcase(label, pattern));
    let excluded = config
        .bridge
        .exclude_spaces
        .iter()
        .any(|pattern| fnmatchcase(label, pattern));
    included && !excluded
}

fn identity_alias_map(config: &Config) -> HashMap<String, String> {
    let mut result = HashMap::new();
    for identity in config.identities.values() {
        for alias in identity.normalized_aliases() {
            result.insert(alias, identity.identity_id.clone());
        }
    }
    result
}

/// Build the channel/agent topology from a Herdr API snapshot.
pub fn build_topology(snapshot: &Value, config: &Config) -> Topology {
    let empty: Vec<Value> = Vec::new();
    let workspaces = snapshot
        .get("workspaces")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let tabs: HashMap<String, &Value> = snapshot
        .get("tabs")
        .and_then(Value::as_array)
        .map(|tabs| {
            tabs.iter()
                .map(|tab| {
                    (
                        tab.get("tab_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                        tab,
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let agents = snapshot
        .get("agents")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let alias_map = identity_alias_map(config);
    let mut warnings: Vec<String> = Vec::new();
    let mut spaces: Vec<SpaceBinding> = Vec::new();
    let mut channel_owners: HashMap<String, String> = HashMap::new();

    let mut sorted_workspaces: Vec<&Value> = workspaces.iter().collect();
    sorted_workspaces.sort_by_key(|workspace| json_int(workspace.get("number")));

    for workspace in sorted_workspaces {
        let workspace_id = json_str_or(workspace.get("workspace_id"), "");
        let label = json_str_or(workspace.get("label"), &workspace_id);
        if workspace_id.is_empty() || !included(&label, config) {
            continue;
        }
        let channel_name = channel_slug(&label);
        if let Some(previous) = channel_owners.get(&channel_name) {
            if *previous != workspace_id {
                warnings.push(format!(
                    "Spaces {previous} and {workspace_id} both normalize to Buzz channel {}",
                    quoted_repr(&channel_name)
                ));
            }
        }
        channel_owners.insert(channel_name.clone(), workspace_id.clone());
        let mut space = SpaceBinding {
            workspace_id: workspace_id.clone(),
            workspace_label: label.clone(),
            channel_name: channel_name.clone(),
            number: json_int(workspace.get("number")),
            agents: Vec::new(),
        };

        let mut identity_seen: HashMap<String, String> = HashMap::new();
        for agent in agents {
            let agent_workspace = agent.get("workspace_id").and_then(Value::as_str);
            if agent_workspace != Some(workspace_id.as_str()) {
                continue;
            }
            let tab_id = json_str_or(agent.get("tab_id"), "");
            let tab_label = tabs
                .get(&tab_id)
                .map(|tab| json_str_or(tab.get("label"), ""))
                .unwrap_or_default();
            let agent_name = match agent.get("name") {
                Some(value) if json_truthy(value) => Some(json_str(value)),
                _ => None,
            };
            let runtime = json_str_or(agent.get("agent"), "agent");
            let pane_id = json_str_or(agent.get("pane_id"), "");
            let terminal_id = json_str_or(agent.get("terminal_id"), &pane_id);
            let fallback = format!(
                "{runtime}-{}",
                pane_id
                    .rsplit(':')
                    .next()
                    .unwrap_or("")
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric())
                    .collect::<String>()
            );
            let display_label = agent_name.clone().unwrap_or_else(|| {
                if meaningful_tab_label(&tab_label) {
                    tab_label.clone()
                } else {
                    fallback
                }
            });

            let mut identity_id: Option<String> = None;
            let candidates = [
                agent_name.clone().unwrap_or_default(),
                tab_label.clone(),
                display_label.clone(),
            ];
            for candidate in candidates {
                let normalized = normalize_name(&candidate);
                if let Some(mapped) = alias_map.get(&normalized) {
                    identity_id = Some(mapped.clone());
                    break;
                }
            }
            let identity = identity_id
                .as_ref()
                .and_then(|id| config.identities.get(id));
            if let Some(identity_id) = &identity_id {
                if let Some(previous_pane) = identity_seen.get(identity_id) {
                    if !previous_pane.is_empty() && *previous_pane != pane_id {
                        warnings.push(format!(
                            "Space {} has multiple panes for identity {}: \
                             {previous_pane}, {pane_id}; routing will use the first ready pane",
                            quoted_repr(&label),
                            quoted_repr(identity_id)
                        ));
                    }
                }
                identity_seen
                    .entry(identity_id.clone())
                    .or_insert_with(|| pane_id.clone());
            } else {
                warnings.push(format!(
                    "Unmapped agent {} in Space {} ({pane_id}); \
                     it will be visible in the plan but cannot join or receive Buzz messages",
                    quoted_repr(&display_label),
                    quoted_repr(&label)
                ));
            }

            space.agents.push(AgentBinding {
                workspace_id: workspace_id.clone(),
                workspace_label: label.clone(),
                channel_name: channel_name.clone(),
                pane_id,
                terminal_id,
                tab_id,
                tab_label,
                runtime,
                status: json_str_or(agent.get("agent_status"), "unknown"),
                agent_name,
                display_label,
                identity_id,
                public_key: identity.map(|identity| identity.public_key.clone()),
            });
        }
        spaces.push(space);
    }

    Topology { spaces, warnings }
}

/// Lowercased pubkeys mentioned in an event's "p" tags.
pub fn mentioned_pubkeys(event: &Value) -> HashSet<String> {
    let mut mentions = HashSet::new();
    if let Some(tags) = event.get("tags").and_then(Value::as_array) {
        for tag in tags {
            if let Some(items) = tag.as_array() {
                if items.len() >= 2 && items[0].as_str() == Some("p") {
                    if let Some(pubkey) = items[1].as_str() {
                        mentions.insert(pubkey.to_lowercase());
                    }
                }
            }
        }
    }
    mentions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnmatchcase_handles_supported_globs() {
        assert!(fnmatchcase("anything", "*"));
        assert!(fnmatchcase("Cool Design", "Cool*"));
        assert!(fnmatchcase("abc", "a?c"));
        assert!(fnmatchcase("b", "[abc]"));
        assert!(fnmatchcase("d", "[!abc]"));
        assert!(!fnmatchcase("b", "[!abc]"));
        assert!(!fnmatchcase("Design", "Cool*"));
        // An unterminated character class treats '[' literally.
        assert!(fnmatchcase("a[b", "a[b"));
        assert!(!fnmatchcase("ab", "a[b"));
    }
}
