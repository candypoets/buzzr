//! Bridge configuration loading, validation, and atomic updates.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::avatars::normalize_lexical;

fn hex64_re() -> Regex {
    Regex::new(r"^[0-9a-f]{64}$").unwrap()
}

fn env_name_re() -> Regex {
    Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*$").unwrap()
}

/// Raised when bridge configuration is unsafe or invalid.
#[derive(Debug)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn err<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

fn io_err(error: std::io::Error) -> ConfigError {
    ConfigError(error.to_string())
}

/// Normalize a display name into lowercase kebab-case.
pub fn normalize_name(value: &str) -> String {
    let lowered = value.trim().to_lowercase();
    let collapsed = Regex::new(r"[^a-z0-9]+")
        .unwrap()
        .replace_all(&lowered, "-");
    collapsed.trim_matches('-').to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityConfig {
    pub identity_id: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub public_key: String,
    pub private_key_env: String,
    pub auth_tag_env: Option<String>,
}

impl IdentityConfig {
    /// All normalized names this identity answers to.
    pub fn normalized_aliases(&self) -> HashSet<String> {
        let mut values = HashSet::new();
        values.insert(normalize_name(&self.identity_id));
        values.insert(normalize_name(&self.display_name));
        for alias in &self.aliases {
            values.insert(normalize_name(alias));
        }
        values.retain(|value| !value.is_empty());
        values
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct BridgeConfig {
    pub relay_url: String,
    pub buzz_bin: String,
    pub herdr_bin: String,
    pub nak_bin: String,
    pub secrets_files: Vec<PathBuf>,
    pub managed_secrets_file: Option<PathBuf>,
    pub bridge_private_key_env: String,
    pub bridge_auth_tag_env: Option<String>,
    pub bridge_public_key: Option<String>,
    pub human_pubkey: Option<String>,
    pub compose_file: Option<PathBuf>,
    pub relay_service: String,
    pub postgres_service: String,
    pub postgres_user: String,
    pub postgres_database: String,
    pub include_spaces: Vec<String>,
    pub exclude_spaces: Vec<String>,
    pub channel_type: String,
    pub channel_visibility: String,
    pub channel_description: String,
    pub sync_enabled: bool,
    pub routing_enabled: bool,
    pub archive_closed_spaces: bool,
    pub remove_departed_agents: bool,
    pub respond_to: String,
    pub respond_to_allowlist: Vec<String>,
    pub poll_seconds: f64,
    pub message_poll_seconds: f64,
    pub auto_provision_agents: bool,
    pub avatars_enabled: bool,
    pub avatar_pack: String,
    pub avatar_pack_path: Option<PathBuf>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        BridgeConfig {
            relay_url: "wss://buzz.nuts.cash".to_string(),
            buzz_bin: "buzz".to_string(),
            herdr_bin: "herdr".to_string(),
            nak_bin: "nak".to_string(),
            secrets_files: Vec::new(),
            managed_secrets_file: None,
            bridge_private_key_env: "BUZZR_BRIDGE_PRIVATE_KEY".to_string(),
            bridge_auth_tag_env: None,
            bridge_public_key: None,
            human_pubkey: None,
            compose_file: None,
            relay_service: "relay".to_string(),
            postgres_service: "postgres".to_string(),
            postgres_user: "buzz".to_string(),
            postgres_database: "buzz".to_string(),
            include_spaces: vec!["*".to_string()],
            exclude_spaces: vec!["~".to_string()],
            channel_type: "stream".to_string(),
            channel_visibility: "private".to_string(),
            channel_description: "Mirrored from Herdr Space {space}.".to_string(),
            sync_enabled: false,
            routing_enabled: false,
            archive_closed_spaces: false,
            remove_departed_agents: false,
            respond_to: "owner-only".to_string(),
            respond_to_allowlist: Vec::new(),
            poll_seconds: 5.0,
            message_poll_seconds: 2.0,
            auto_provision_agents: false,
            avatars_enabled: true,
            avatar_pack: "bees-v2".to_string(),
            avatar_pack_path: None,
        }
    }
}

impl BridgeConfig {
    // Compatibility accessors for the pre-buzzr 0.3 configuration schema.
    pub fn secrets_file(&self) -> Option<&Path> {
        self.secrets_files.first().map(PathBuf::as_path)
    }

    pub fn owner_private_key_env(&self) -> &str {
        &self.bridge_private_key_env
    }

    pub fn owner_auth_tag_env(&self) -> Option<&str> {
        self.bridge_auth_tag_env.as_deref()
    }

    pub fn owner_pubkey(&self) -> Option<&str> {
        self.human_pubkey.as_deref()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub bridge: BridgeConfig,
    pub identities: HashMap<String, IdentityConfig>,
    pub secrets: HashMap<String, String>,
}

impl Config {
    /// Look up a secret: environment first, then the loaded secrets files.
    pub fn secret(&self, env_name: Option<&str>) -> Option<String> {
        let env_name = match env_name {
            Some(name) if !name.is_empty() => name,
            _ => return None,
        };
        match std::env::var(env_name) {
            Ok(value) if !value.is_empty() => Some(value),
            // Empty environment and dotenv values are unavailable credentials.
            _ => self
                .secrets
                .get(env_name)
                .cloned()
                .filter(|value| !value.is_empty()),
        }
    }

    pub fn bridge_credentials(&self) -> (Option<String>, Option<String>) {
        (
            self.secret(Some(&self.bridge.bridge_private_key_env)),
            self.secret(self.bridge.bridge_auth_tag_env.as_deref()),
        )
    }

    /// Compatibility alias: the old 'owner' signer is now the bridge signer.
    pub fn owner_credentials(&self) -> (Option<String>, Option<String>) {
        self.bridge_credentials()
    }

    /// Return the human controller pubkey, with legacy NIP-OA inference.
    pub fn human_public_key(&self) -> Option<String> {
        if let Some(pubkey) = &self.bridge.human_pubkey {
            return Some(pubkey.to_lowercase());
        }
        let (_private_key, auth_tag) = self.bridge_credentials();
        let auth_tag = auth_tag?;
        let value: serde_json::Value = serde_json::from_str(&auth_tag).ok()?;
        let items = value.as_array()?;
        if items.len() == 4 && items[0].as_str() == Some("auth") {
            if let Some(candidate) = items[1].as_str() {
                let lowered = candidate.to_lowercase();
                if hex64_re().is_match(&lowered) {
                    return Some(lowered);
                }
            }
        }
        None
    }

    /// Compatibility alias for human_public_key().
    pub fn owner_public_key(&self) -> Option<String> {
        self.human_public_key()
    }

    pub fn identity_credentials(
        &self,
        identity_id: &str,
    ) -> Result<(Option<String>, Option<String>), ConfigError> {
        let identity = self
            .identities
            .get(identity_id)
            .ok_or_else(|| ConfigError(quoted_repr(identity_id)))?;
        Ok((
            self.secret(Some(&identity.private_key_env)),
            self.secret(identity.auth_tag_env.as_deref()),
        ))
    }

    pub fn first_reader_credentials(&self) -> (Option<String>, Option<String>) {
        let (bridge_key, bridge_auth) = self.bridge_credentials();
        if bridge_key.is_some() {
            return (bridge_key, bridge_auth);
        }
        let mut identity_ids: Vec<&String> = self.identities.keys().collect();
        identity_ids.sort();
        for identity_id in identity_ids {
            if let Ok((key, auth)) = self.identity_credentials(identity_id) {
                if key.is_some() {
                    return (key, auth);
                }
            }
        }
        (None, None)
    }

    /// All available signers, ordered with the bridge first.
    pub fn reader_credentials(&self) -> Vec<(Option<String>, String, Option<String>)> {
        let mut result = Vec::new();
        let (bridge_key, bridge_auth) = self.bridge_credentials();
        if let Some(key) = bridge_key {
            result.push((self.bridge.bridge_public_key.clone(), key, bridge_auth));
        }
        let mut identity_ids: Vec<&String> = self.identities.keys().collect();
        identity_ids.sort();
        for identity_id in identity_ids {
            if let Ok((Some(key), auth)) = self.identity_credentials(identity_id) {
                result.push((
                    Some(self.identities[identity_id].public_key.clone()),
                    key,
                    auth,
                ));
            }
        }
        result
    }
}

// --- TOML scalar coercion helpers -----------------------------------------

/// Stable string conversion for the TOML value types used here.
fn toml_scalar_string(value: &toml::Value) -> String {
    match value {
        toml::Value::String(text) => text.clone(),
        toml::Value::Integer(number) => number.to_string(),
        toml::Value::Float(number) => {
            let rendered = number.to_string();
            if rendered.contains('.') || rendered.contains('e') || rendered.contains("inf") {
                rendered
            } else {
                format!("{rendered}.0")
            }
        }
        toml::Value::Boolean(flag) => {
            if *flag {
                "True".to_string()
            } else {
                "False".to_string()
            }
        }
        other => other.to_string(),
    }
}

/// Truthiness for TOML values accepted by legacy configuration files.
fn toml_truthy(value: &toml::Value) -> bool {
    match value {
        toml::Value::String(text) => !text.is_empty(),
        toml::Value::Integer(number) => *number != 0,
        toml::Value::Float(number) => *number != 0.0,
        toml::Value::Boolean(flag) => *flag,
        toml::Value::Array(items) => !items.is_empty(),
        toml::Value::Table(table) => !table.is_empty(),
        toml::Value::Datetime(_) => true,
    }
}

/// Convert a truthy TOML scalar to a string.
fn truthy_str(value: Option<&toml::Value>) -> Option<String> {
    match value {
        Some(value) if toml_truthy(value) => Some(toml_scalar_string(value)),
        _ => None,
    }
}

/// Convert a TOML scalar to a float, using a default when the key is missing.
fn toml_float_or(value: Option<&toml::Value>, default: f64) -> Result<f64, ConfigError> {
    match value {
        None => Ok(default),
        Some(toml::Value::Float(number)) => Ok(*number),
        Some(toml::Value::Integer(number)) => Ok(*number as f64),
        Some(toml::Value::Boolean(flag)) => Ok(if *flag { 1.0 } else { 0.0 }),
        Some(toml::Value::String(text)) => text.trim().parse::<f64>().map_err(|_| {
            ConfigError(format!(
                "could not convert string to float: {}",
                quoted_repr(text)
            ))
        }),
        Some(_) => err("float() argument must be a string or a number"),
    }
}

/// Stable quoted representation for user-facing errors.
pub(crate) fn quoted_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn as_tuple(value: Option<&toml::Value>, default: &[&str]) -> Result<Vec<String>, ConfigError> {
    match value {
        None => Ok(default.iter().map(|item| item.to_string()).collect()),
        Some(toml::Value::Array(items)) if items.iter().all(|item| item.as_str().is_some()) => {
            Ok(items
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect())
        }
        Some(_) => err("expected an array of strings"),
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn expanduser(path: &Path) -> Result<PathBuf, ConfigError> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| ConfigError("cannot expand ~: HOME is not set".to_string()))?;
        let mut expanded = PathBuf::from(home);
        if text.len() > 2 {
            expanded.push(&text[2..]);
        }
        Ok(expanded)
    } else {
        Ok(path.to_path_buf())
    }
}

/// Parse a dotenv secrets file, enforcing owner-only permissions.
pub fn parse_dotenv(path: &Path) -> Result<HashMap<String, String>, ConfigError> {
    if !path.exists() {
        return err(format!("secrets file does not exist: {}", path.display()));
    }
    let metadata = fs::metadata(path).map_err(io_err)?;
    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        return err(format!(
            "secrets file must not be group/world accessible: {} (mode {mode:o})",
            path.display()
        ));
    }

    let text = fs::read_to_string(path).map_err(io_err)?;
    let mut values = HashMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let mut line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("export ") {
            line = rest.trim_start();
        }
        if !line.contains('=') {
            return err(format!(
                "invalid secrets line {line_number} in {}",
                path.display()
            ));
        }
        let (key, value) = line.split_once('=').unwrap();
        let key = key.trim();
        if !env_name_re().is_match(key) {
            return err(format!(
                "invalid environment name on line {line_number} in {}",
                path.display()
            ));
        }
        let value = value.trim();
        let value = if value.len() >= 2 {
            let first = value.as_bytes()[0];
            let last = value.as_bytes()[value.len() - 1];
            if first == last && (first == b'"' || first == b'\'') {
                &value[1..value.len() - 1]
            } else {
                value
            }
        } else {
            value
        };
        values.insert(key.to_string(), value.to_string());
    }
    Ok(values)
}

/// Render a value as a TOML literal (bool, array, or JSON-escaped string).
fn toml_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Bool(flag) => {
            if *flag {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(toml_value).collect();
            format!("[{}]", rendered.join(", "))
        }
        // JSON basic strings are also valid TOML basic strings for the values
        // used by this configuration file.
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".to_string()),
    }
}

/// Write `content` to `path` atomically (tempfile + fsync + chmod + rename).
fn atomic_write(path: &Path, content: &str, mode: u32) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(io_err)?;
    let stem = path
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "tmp".to_string());
    let suffix = path
        .extension()
        .map(|extension| format!(".{}", extension.to_string_lossy()))
        .unwrap_or_default();
    let mut temporary = tempfile::Builder::new()
        .prefix(&format!("{stem}-"))
        .suffix(&suffix)
        .tempfile_in(parent)
        .map_err(io_err)?;
    temporary.write_all(content.as_bytes()).map_err(io_err)?;
    temporary.flush().map_err(io_err)?;
    temporary.as_file().sync_all().map_err(io_err)?;
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(mode)).map_err(io_err)?;
    temporary
        .persist(path)
        .map_err(|error| ConfigError(error.error.to_string()))?;
    Ok(())
}

/// Atomically update keys in [bridge] without touching identity tables.
pub fn update_bridge_settings(
    path: &Path,
    updates: &[(String, Option<serde_json::Value>)],
) -> Result<(), ConfigError> {
    if !path.exists() {
        return err(format!("configuration not found: {}", path.display()));
    }
    let text = fs::read_to_string(path).map_err(io_err)?;
    let mut lines: Vec<String> = text.lines().map(|line| line.to_string()).collect();
    let mut bridge_start: Option<usize> = None;
    let mut bridge_end = lines.len();
    for (index, line) in lines.iter().enumerate() {
        let stripped = line.trim();
        if stripped == "[bridge]" {
            bridge_start = Some(index);
            continue;
        }
        if let Some(start) = bridge_start {
            if index > start && stripped.starts_with('[') {
                bridge_end = index;
                break;
            }
        }
    }
    if bridge_start.is_none() {
        lines.insert(0, "[bridge]".to_string());
        bridge_start = Some(0);
        bridge_end = 1;
    }
    let bridge_start = bridge_start.unwrap();

    let mut remaining: Vec<(String, Option<serde_json::Value>)> = updates.to_vec();
    let key_pattern = Regex::new(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=").unwrap();
    let mut rewritten: Vec<String> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if bridge_start < index && index < bridge_end {
            if let Some(captures) = key_pattern.captures(line.trim()) {
                let key = captures[1].to_string();
                if let Some(position) = remaining.iter().position(|(name, _)| *name == key) {
                    let (_, value) = remaining.remove(position);
                    if let Some(value) = value {
                        rewritten.push(format!("{key} = {}", toml_value(&value)));
                    }
                    continue;
                }
            }
        }
        rewritten.push(line.clone());
    }

    // Re-find the end after replacements/removals and append new keys before
    // the next TOML table.
    let mut insertion = rewritten.len();
    let mut found_bridge = false;
    for (index, line) in rewritten.iter().enumerate() {
        let stripped = line.trim();
        if stripped == "[bridge]" {
            found_bridge = true;
            continue;
        }
        if found_bridge && stripped.starts_with('[') {
            insertion = index;
            break;
        }
    }
    let additions: Vec<String> = remaining
        .iter()
        .filter_map(|(key, value)| {
            value
                .as_ref()
                .map(|value| format!("{key} = {}", toml_value(value)))
        })
        .collect();
    if !additions.is_empty() {
        rewritten.splice(insertion..insertion, additions);
    }

    let content = format!("{}\n", rewritten.join("\n").trim_end());
    atomic_write(path, &content, 0o600)
}

/// Append newly generated identity tables without rewriting user configuration.
pub fn append_identities(path: &Path, identities: &[IdentityConfig]) -> Result<(), ConfigError> {
    if !path.exists() {
        return err(format!("configuration not found: {}", path.display()));
    }
    let text = fs::read_to_string(path).map_err(io_err)?;
    let raw: toml::Value = toml::from_str(&text).map_err(|error| ConfigError(error.to_string()))?;
    let existing: HashSet<&str> = match raw.get("identities") {
        None => HashSet::new(),
        Some(toml::Value::Table(table)) => table.keys().map(String::as_str).collect(),
        Some(_) => return err("[identities] must be a table"),
    };
    let mut blocks: Vec<String> = Vec::new();
    for identity in identities {
        if existing.contains(identity.identity_id.as_str()) {
            continue;
        }
        if normalize_name(&identity.identity_id) != identity.identity_id {
            return err(format!(
                "identity id must be normalized: {}",
                identity.identity_id
            ));
        }
        let aliases: Vec<serde_json::Value> = identity
            .aliases
            .iter()
            .map(|alias| serde_json::Value::String(alias.clone()))
            .collect();
        blocks.extend([
            format!("[identities.{}]", identity.identity_id),
            format!(
                "display_name = {}",
                toml_value(&serde_json::Value::String(identity.display_name.clone()))
            ),
            format!(
                "aliases = {}",
                toml_value(&serde_json::Value::Array(aliases))
            ),
            format!(
                "public_key = {}",
                toml_value(&serde_json::Value::String(identity.public_key.clone()))
            ),
            format!(
                "private_key_env = {}",
                toml_value(&serde_json::Value::String(identity.private_key_env.clone()))
            ),
            String::new(),
        ]);
    }
    if blocks.is_empty() {
        return Ok(());
    }
    let content = format!("{}\n\n{}\n", text.trim_end(), blocks.join("\n").trim_end());
    atomic_write(path, &content, 0o600)
}

/// Atomically add or replace literal dotenv values in a private file.
pub fn update_dotenv(path: &Path, updates: &[(String, String)]) -> Result<(), ConfigError> {
    let mut values = if path.exists() {
        parse_dotenv(path)?
    } else {
        HashMap::new()
    };
    for (key, value) in updates {
        if !env_name_re().is_match(key) {
            return err(format!("invalid environment name: {key}"));
        }
        if value.contains('\n') || value.contains('\r') {
            return err(format!("dotenv value for {key} contains a newline"));
        }
        values.insert(key.clone(), value.clone());
    }
    let mut entries: Vec<(String, String)> = values.into_iter().collect();
    entries.sort();
    let mut content = String::new();
    for (key, value) in entries {
        content.push_str(&format!("{key}={value}\n"));
    }
    atomic_write(path, &content, 0o600)
}

/// Load and validate a buzzr configuration file.
pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    if !path.exists() {
        return err(format!(
            "configuration not found: {}; run `buzzr init-config`",
            path.display()
        ));
    }
    let text = fs::read_to_string(path).map_err(io_err)?;
    let raw: toml::Value = toml::from_str(&text).map_err(|error| ConfigError(error.to_string()))?;

    let bridge_raw = match raw.get("bridge") {
        None => toml::Table::new(),
        Some(toml::Value::Table(table)) => table.clone(),
        Some(_) => return err("[bridge] must be a table"),
    };

    let secrets_override =
        nonempty_env("BUZZR_SECRETS_FILE").or_else(|| nonempty_env("HERDR_BUZZ_SECRETS_FILE"));
    let secret_values: Vec<String> = if let Some(override_path) = secrets_override {
        vec![override_path]
    } else if bridge_raw.contains_key("secrets_files") {
        as_tuple(bridge_raw.get("secrets_files"), &[])?
    } else if let Some(single) = truthy_str(bridge_raw.get("secrets_file")) {
        vec![single]
    } else {
        Vec::new()
    };

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let mut secrets_files: Vec<PathBuf> = Vec::new();
    let mut secrets: HashMap<String, String> = HashMap::new();
    for raw_path in &secret_values {
        let mut secret_path = expanduser(Path::new(raw_path))?;
        if !secret_path.is_absolute() {
            secret_path = parent.join(secret_path);
        }
        let secret_path = normalize_lexical(&secret_path);
        // Follow symlinks when the path exists.
        let secret_path = secret_path.canonicalize().unwrap_or(secret_path);
        secrets_files.push(secret_path.clone());
        secrets.extend(parse_dotenv(&secret_path)?);
    }

    let external = |name: &str| -> Option<String> {
        match nonempty_env(name) {
            Some(value) => Some(value),
            None => secrets.get(name).cloned(),
        }
    };

    let mut human_pubkey = truthy_str(bridge_raw.get("human_pubkey"))
        .or_else(|| truthy_str(bridge_raw.get("owner_pubkey")))
        .or_else(|| external("BUZZR_HUMAN_PUBKEY").filter(|value| !value.is_empty()))
        .or_else(|| external("BUZZ_PUBLIC_KEY").filter(|value| !value.is_empty()));
    if human_pubkey.is_some() {
        human_pubkey = human_pubkey.map(|value| value.to_lowercase());
    }
    if let Some(value) = &human_pubkey {
        if !value.is_empty() && !hex64_re().is_match(value) {
            return err("bridge.human_pubkey must be 64 lowercase hexadecimal characters");
        }
    }

    let mut bridge_public_key = truthy_str(bridge_raw.get("bridge_public_key"))
        .or_else(|| external("BUZZR_BRIDGE_PUBLIC_KEY").filter(|value| !value.is_empty()));
    if bridge_public_key.is_some() {
        bridge_public_key = bridge_public_key.map(|value| value.to_lowercase());
    }
    if let Some(value) = &bridge_public_key {
        if !value.is_empty() && !hex64_re().is_match(value) {
            return err("bridge.bridge_public_key must be 64 lowercase hexadecimal characters");
        }
    }

    let resolve_config_path =
        |raw_value: Option<&toml::Value>| -> Result<Option<PathBuf>, ConfigError> {
            let raw = match truthy_str(raw_value) {
                Some(raw) => raw,
                None => return Ok(None),
            };
            let mut resolved = expanduser(Path::new(&raw))?;
            if !resolved.is_absolute() {
                resolved = parent.join(resolved);
            }
            let resolved = normalize_lexical(&resolved);
            // Follow symlinks when the path exists.
            Ok(Some(resolved.canonicalize().unwrap_or(resolved)))
        };

    let compose_file = resolve_config_path(bridge_raw.get("compose_file"))?;
    let managed_secrets_file = resolve_config_path(bridge_raw.get("managed_secrets_file"))?;
    let avatar_pack_path = resolve_config_path(bridge_raw.get("avatar_pack_path"))?;

    let respond_to = bridge_raw
        .get("respond_to")
        .map(toml_scalar_string)
        .unwrap_or_else(|| "owner-only".to_string());
    if !["owner-only", "allowlist", "anyone", "nobody"].contains(&respond_to.as_str()) {
        return err("bridge.respond_to must be owner-only, allowlist, anyone, or nobody");
    }
    let channel_type = bridge_raw
        .get("channel_type")
        .map(toml_scalar_string)
        .unwrap_or_else(|| "stream".to_string());
    if !["stream", "forum"].contains(&channel_type.as_str()) {
        return err("bridge.channel_type must be stream or forum");
    }
    let visibility = bridge_raw
        .get("channel_visibility")
        .map(toml_scalar_string)
        .unwrap_or_else(|| "private".to_string());
    if !["open", "private"].contains(&visibility.as_str()) {
        return err("bridge.channel_visibility must be open or private");
    }

    let toml_bool = |key: &str, default: bool| -> bool {
        bridge_raw.get(key).map(toml_truthy).unwrap_or(default)
    };
    let herdr_bin_default = std::env::var("HERDR_BIN_PATH").unwrap_or_else(|_| "herdr".to_string());
    let owner_private_key_env = bridge_raw
        .get("owner_private_key_env")
        .map(toml_scalar_string)
        .unwrap_or_else(|| "BUZZ_PRIVATE_KEY".to_string());
    let auth_tag_raw = bridge_raw
        .get("bridge_auth_tag_env")
        .or_else(|| bridge_raw.get("owner_auth_tag_env"));

    let bridge = BridgeConfig {
        relay_url: external("BUZZR_RELAY_URL")
            .filter(|value| !value.is_empty())
            .or_else(|| external("BUZZ_RELAY_URL").filter(|value| !value.is_empty()))
            .unwrap_or_else(|| {
                bridge_raw
                    .get("relay_url")
                    .map(toml_scalar_string)
                    .unwrap_or_else(|| "wss://buzz.nuts.cash".to_string())
            }),
        buzz_bin: bridge_raw
            .get("buzz_bin")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "buzz".to_string()),
        herdr_bin: bridge_raw
            .get("herdr_bin")
            .map(toml_scalar_string)
            .unwrap_or(herdr_bin_default),
        nak_bin: bridge_raw
            .get("nak_bin")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "nak".to_string()),
        secrets_files,
        managed_secrets_file,
        bridge_private_key_env: bridge_raw
            .get("bridge_private_key_env")
            .map(toml_scalar_string)
            .unwrap_or(owner_private_key_env),
        bridge_auth_tag_env: truthy_str(auth_tag_raw),
        bridge_public_key,
        human_pubkey,
        compose_file,
        relay_service: bridge_raw
            .get("relay_service")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "relay".to_string()),
        postgres_service: bridge_raw
            .get("postgres_service")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "postgres".to_string()),
        postgres_user: bridge_raw
            .get("postgres_user")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "buzz".to_string()),
        postgres_database: bridge_raw
            .get("postgres_database")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "buzz".to_string()),
        include_spaces: as_tuple(bridge_raw.get("include_spaces"), &["*"])?,
        exclude_spaces: as_tuple(bridge_raw.get("exclude_spaces"), &["~"])?,
        channel_type,
        channel_visibility: visibility,
        channel_description: bridge_raw
            .get("channel_description")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "Mirrored from Herdr Space {space}.".to_string()),
        sync_enabled: toml_bool("sync_enabled", false),
        routing_enabled: toml_bool("routing_enabled", false),
        archive_closed_spaces: toml_bool("archive_closed_spaces", false),
        remove_departed_agents: toml_bool("remove_departed_agents", false),
        respond_to,
        respond_to_allowlist: as_tuple(bridge_raw.get("respond_to_allowlist"), &[])?,
        poll_seconds: toml_float_or(bridge_raw.get("poll_seconds"), 5.0)?.max(1.0),
        message_poll_seconds: toml_float_or(bridge_raw.get("message_poll_seconds"), 2.0)?.max(1.0),
        auto_provision_agents: toml_bool("auto_provision_agents", false),
        avatars_enabled: toml_bool("avatars_enabled", true),
        avatar_pack: bridge_raw
            .get("avatar_pack")
            .map(toml_scalar_string)
            .unwrap_or_else(|| "bees-v2".to_string()),
        avatar_pack_path,
    };

    let identities_raw = match raw.get("identities") {
        None => toml::Table::new(),
        Some(toml::Value::Table(table)) => table.clone(),
        Some(_) => return err("[identities] must be a table"),
    };
    let mut identities: HashMap<String, IdentityConfig> = HashMap::new();
    let mut alias_owner: HashMap<String, String> = HashMap::new();
    for (identity_id, value) in &identities_raw {
        let table = match value {
            toml::Value::Table(table) => table,
            _ => return err(format!("[identities.{identity_id}] must be a table")),
        };
        let normalized_id = normalize_name(identity_id);
        if normalized_id.is_empty() || normalized_id != *identity_id {
            return err(format!(
                "identity id must be normalized lowercase kebab-case: {identity_id}"
            ));
        }
        let public_key = table
            .get("public_key")
            .map(toml_scalar_string)
            .unwrap_or_default();
        if !hex64_re().is_match(&public_key) {
            return err(format!(
                "identities.{identity_id}.public_key must be 64 lowercase hex"
            ));
        }
        let private_key_env = table
            .get("private_key_env")
            .map(toml_scalar_string)
            .unwrap_or_default();
        if !env_name_re().is_match(&private_key_env) {
            return err(format!(
                "identities.{identity_id}.private_key_env is invalid"
            ));
        }
        let identity = IdentityConfig {
            identity_id: identity_id.clone(),
            display_name: table
                .get("display_name")
                .map(toml_scalar_string)
                .unwrap_or_else(|| identity_id.clone()),
            aliases: as_tuple(table.get("aliases"), &[identity_id.as_str()])?,
            public_key,
            private_key_env,
            auth_tag_env: truthy_str(table.get("auth_tag_env")),
        };
        for alias in identity.normalized_aliases() {
            if let Some(previous) = alias_owner.get(&alias) {
                if previous != identity_id {
                    return err(format!(
                        "identity alias {} belongs to both {previous} and {identity_id}",
                        quoted_repr(&alias)
                    ));
                }
            }
            alias_owner.insert(alias, identity_id.clone());
        }
        identities.insert(identity_id.clone(), identity);
    }

    Ok(Config {
        bridge,
        identities,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_name_has_expected_behavior() {
        assert_eq!(normalize_name("  Hello World! "), "hello-world");
        assert_eq!(normalize_name("--Already--ok--"), "already-ok");
        assert_eq!(normalize_name("!!!"), "");
    }

    #[test]
    fn toml_value_renders_literals() {
        assert_eq!(toml_value(&serde_json::json!(true)), "true");
        assert_eq!(toml_value(&serde_json::json!(["a", "b"])), "[\"a\", \"b\"]");
        assert_eq!(toml_value(&serde_json::json!("qu\"ote")), "\"qu\\\"ote\"");
    }

    #[test]
    fn quoted_repr_uses_stable_quoting() {
        assert_eq!(quoted_repr("plain"), "'plain'");
        assert_eq!(quoted_repr("it's"), "\"it's\"");
        assert_eq!(quoted_repr("a\nb"), "'a\\nb'");
    }
}
