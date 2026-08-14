//! Reconciliation of Herdr Spaces into Buzz channels and managed Nostr
//! profiles.
//!
//! Publishing and uploading go through injection traits and a pack-loader
//! closure so external effects remain independently testable.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::agent_profiles::{build_agent_profile_declarations, AGENT_PROFILE_REFRESH_SECONDS};
use crate::avatars::{build_avatar, load_avatar_pack, AvatarAsset, AvatarPack, AvatarPackError};
use crate::clients::nostr::dump_compact_sorted;
use crate::clients::{BuzzClient, CommandError, FileUploader, NostrTools, ProfilePublisher};
use crate::config::{quoted_repr, Config};
use crate::state::{normalize_managed_resources, runtime_directory, StateStore};
use crate::topology::Topology;

pub const IDENTITY_PROFILE_REFRESH_SECONDS: i64 = 24 * 60 * 60;

fn err<T>(message: impl Into<String>) -> Result<T, CommandError> {
    Err(CommandError(message.into()))
}

fn channel_id_of(channel: &Value) -> Option<String> {
    for key in ["channel_id", "channelId", "id"] {
        if let Some(value) = channel.get(key).and_then(Value::as_str) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn has_origin(record: &Value, expected: &str) -> bool {
    record.get("origin").and_then(Value::as_str) == Some(expected)
}

fn record_channel_membership(
    state: &mut Value,
    channel_id: &str,
    pubkey: &str,
    role: &str,
    origin: &str,
) {
    normalize_managed_resources(state);
    state["managed_resources"]["channel_memberships"][channel_id][pubkey] = json!({
        "origin": origin,
        "role": role,
    });
}

fn forget_channel_membership(state: &mut Value, channel_id: &str, pubkey: &str) {
    if let Some(memberships) = state["managed_resources"]["channel_memberships"]
        .get_mut(channel_id)
        .and_then(Value::as_object_mut)
    {
        memberships.remove(pubkey);
        if memberships.is_empty() {
            state["managed_resources"]["channel_memberships"]
                .as_object_mut()
                .expect("normalized channel membership map")
                .remove(channel_id);
        }
    }
}

fn checkpoint_provenance(store: &StateStore, state: &Value) -> Result<(), CommandError> {
    store.save(state).map_err(|error| {
        CommandError(format!(
            "cannot checkpoint managed-resource provenance: {error}"
        ))
    })
}

/// Truthiness for relay JSON values.
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

/// Stable string conversion for JSON scalars in channel payloads.
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

fn now_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn channel_creation_marker(workspace_id: &str, bridge_pubkey: Option<&str>) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(workspace_id.as_bytes());
    hasher.update(bridge_pubkey.unwrap_or_default().as_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(nanos.to_le_bytes());
    let digest = hasher.finalize();
    format!("buzzr-create:{}", hex::encode(&digest[..16]))
}

fn channel_has_creation_marker(channel: &Value, marker: &str) -> bool {
    channel
        .get("description")
        .and_then(Value::as_str)
        .map(|description| description.contains(&format!("[{marker}]")))
        .unwrap_or(false)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub applied: bool,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
}

impl SyncReport {
    pub fn new(applied: bool) -> Self {
        SyncReport {
            applied,
            actions: Vec::new(),
            warnings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct ManagedProfile {
    cache_id: String,
    public_key: String,
    identity_id: Option<String>,
    name: String,
    about: String,
}

fn managed_profiles(config: &Config) -> Vec<ManagedProfile> {
    let mut profiles: Vec<ManagedProfile> = Vec::new();
    if let Some(bridge_public_key) = &config.bridge.bridge_public_key {
        profiles.push(ManagedProfile {
            cache_id: "@bridge".to_string(),
            public_key: bridge_public_key.clone(),
            identity_id: None,
            name: "buzzr".to_string(),
            about: "Herdr ↔ Buzz bridge managed by the buzzr plugin.".to_string(),
        });
    }
    let mut identities: Vec<&crate::config::IdentityConfig> = config.identities.values().collect();
    identities.sort_by(|left, right| left.identity_id.cmp(&right.identity_id));
    profiles.extend(identities.into_iter().map(|identity| ManagedProfile {
        cache_id: identity.identity_id.clone(),
        public_key: identity.public_key.clone(),
        identity_id: Some(identity.identity_id.clone()),
        name: identity.display_name.clone(),
        about: format!(
            "Herdr agent identity managed by buzzr ({}).",
            identity.identity_id
        ),
    }));
    profiles
}

fn profile_credentials(
    config: &Config,
    profile: &ManagedProfile,
) -> (Option<String>, Option<String>) {
    match &profile.identity_id {
        None => config.bridge_credentials(),
        Some(identity_id) => config
            .identity_credentials(identity_id)
            .unwrap_or((None, None)),
    }
}

fn profile_fingerprint(
    profile: &ManagedProfile,
    relay_url: &str,
    pack_id: Option<&str>,
    avatar_sha256: Option<&str>,
) -> String {
    let encoded = dump_compact_sorted(&json!({
        "public_key": profile.public_key,
        "relay_url": relay_url,
        "name": profile.name,
        "about": profile.about,
        "avatar_pack": pack_id,
        "avatar_sha256": avatar_sha256,
    }));
    hex::encode(Sha256::digest(encoded.as_bytes()))
}

/// Accept only absolute http(s) URLs, like `urlparse` + scheme/netloc checks.
fn picture_url(value: Option<&Value>) -> Option<String> {
    let text = value.and_then(Value::as_str)?;
    let (scheme, rest) = text.split_once("://")?;
    let scheme = scheme.to_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let netloc = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if netloc.is_empty() {
        return None;
    }
    Some(text.to_string())
}

fn traits_value(avatar: &AvatarAsset) -> Value {
    let traits: serde_json::Map<String, Value> = avatar
        .traits
        .iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect();
    Value::Object(traits)
}

/// Ensure `state[key]` is an object, remove it, and hand the owned map value to
/// the caller. Pair with [`put_back`] so the mutation is visible in `state`
/// again.
fn ensure_and_take(state: &mut Value, key: &str) -> Value {
    {
        let object = state.as_object_mut().expect("state is an object");
        let needs_init = !object.get(key).map(Value::is_object).unwrap_or(false);
        if needs_init {
            object.insert(key.to_string(), json!({}));
        }
        object.remove(key).expect("key was just ensured")
    }
}

fn put_back(state: &mut Value, key: &str, value: Value) {
    state
        .as_object_mut()
        .expect("state is an object")
        .insert(key.to_string(), value);
}

/// External effects of [`sync_identity_profiles`].
pub struct ProfileSyncDeps<'a, P: ProfilePublisher, L, F> {
    pub publisher: &'a P,
    pub load_pack: L,
    /// Build a per-identity uploader from its credentials.
    pub make_uploader: F,
}

/// Production wiring: real pack loading, native Nostr publishing, and the Buzz
/// CLI uploader, all derived from the bridge configuration.
#[allow(clippy::type_complexity)] // concrete closure types beat boxed trait objects here
pub fn production_deps<'a>(
    config: &'a Config,
    publisher: &'a NostrTools,
) -> ProfileSyncDeps<
    'a,
    NostrTools,
    impl Fn(&str, Option<&Path>) -> Result<AvatarPack, AvatarPackError>,
    impl Fn(&str, Option<&str>) -> BuzzClient + 'a,
> {
    ProfileSyncDeps {
        publisher,
        load_pack: |pack_id: &str, path: Option<&Path>| load_avatar_pack(pack_id, path),
        make_uploader: move |private_key: &str, auth_tag: Option<&str>| {
            BuzzClient::new(
                config.bridge.buzz_bin.clone(),
                config.bridge.relay_url.clone(),
                private_key,
                auth_tag.map(str::to_string),
            )
        },
    }
}

/// Upload stable avatars and publish kind:0 profiles for managed identities.
///
/// Port of `_sync_identity_profiles`.
#[allow(clippy::too_many_arguments)]
pub fn sync_identity_profiles<P, L, F, U>(
    config: &Config,
    state: &mut Value,
    report: &mut SyncReport,
    apply: bool,
    now: i64,
    avatar_output_dir: Option<&Path>,
    deps: &ProfileSyncDeps<'_, P, L, F>,
) where
    P: ProfilePublisher,
    L: Fn(&str, Option<&Path>) -> Result<AvatarPack, AvatarPackError>,
    F: Fn(&str, Option<&str>) -> U,
    U: FileUploader,
{
    let mut cache_value = ensure_and_take(state, "identity_profiles");
    let mut uploads_value = ensure_and_take(state, "avatar_uploads");

    let pack = if config.bridge.avatars_enabled {
        match (deps.load_pack)(
            &config.bridge.avatar_pack,
            config.bridge.avatar_pack_path.as_deref(),
        ) {
            Ok(pack) => Some(pack),
            Err(error) => {
                report
                    .warnings
                    .push(format!("managed identity profiles were skipped: {error}"));
                put_back(state, "identity_profiles", cache_value);
                put_back(state, "avatar_uploads", uploads_value);
                return;
            }
        }
    } else {
        None
    };

    let cache = cache_value
        .as_object_mut()
        .expect("identity_profiles is an object");
    let uploads = uploads_value
        .as_object_mut()
        .expect("avatar_uploads is an object");

    let profiles = managed_profiles(config);
    let mut reserved_avatar_ids: HashSet<String> = HashSet::new();
    let assets_by_id: HashMap<&str, &AvatarAsset> = match pack.as_ref().filter(|p| !p.layered()) {
        Some(pack) => pack
            .assets
            .iter()
            .map(|asset| (asset.asset_id.as_str(), asset))
            .collect(),
        None => HashMap::new(),
    };
    let mut preserved_avatars: HashMap<String, AvatarAsset> = HashMap::new();
    if let Some(pack) = pack.as_ref().filter(|p| !p.layered()) {
        // Reserve every valid existing assignment before placing newcomers, so
        // a newly-added identity that sorts earlier cannot steal an old avatar.
        for profile in &profiles {
            let cached = cache
                .get(profile.cache_id.as_str())
                .filter(|value| value.is_object());
            let cached_avatar_id = cached
                .and_then(|cached| cached.get("avatar_id"))
                .and_then(Value::as_str);
            if let Some(avatar_id) = cached_avatar_id {
                let same_pack = cached
                    .and_then(|cached| cached.get("avatar_pack"))
                    .and_then(Value::as_str)
                    == Some(pack.pack_id.as_str());
                if assets_by_id.contains_key(avatar_id)
                    && same_pack
                    && (!reserved_avatar_ids.contains(avatar_id)
                        || reserved_avatar_ids.len() >= pack.assets.len())
                {
                    preserved_avatars
                        .insert(profile.cache_id.clone(), assets_by_id[avatar_id].clone());
                    reserved_avatar_ids.insert(avatar_id.to_string());
                }
            }
        }
    }

    for profile in &profiles {
        let cached = cache
            .get(profile.cache_id.as_str())
            .filter(|value| value.is_object());
        let avatar: Option<AvatarAsset> = match &pack {
            None => None,
            Some(pack) if pack.layered() => {
                let render_directory: Option<PathBuf> = if apply {
                    Some(
                        avatar_output_dir
                            .map(Path::to_path_buf)
                            .unwrap_or_else(|| runtime_directory().join("avatars")),
                    )
                } else {
                    None
                };
                match build_avatar(
                    pack,
                    &profile.public_key,
                    render_directory.as_deref(),
                    &HashSet::new(),
                ) {
                    Ok(avatar) => Some(avatar),
                    Err(error) => {
                        report.warnings.push(format!(
                            "cannot compose avatar for {}: {error}",
                            profile.name
                        ));
                        continue;
                    }
                }
            }
            Some(pack) => {
                let chosen = match preserved_avatars.get(profile.cache_id.as_str()) {
                    Some(avatar) => avatar.clone(),
                    None => {
                        match build_avatar(pack, &profile.public_key, None, &reserved_avatar_ids) {
                            Ok(avatar) => avatar,
                            Err(error) => {
                                // Practically unreachable: manifests require at
                                // least one asset and selection falls back to the
                                // full set when every id is reserved. Treat an
                                // empty candidate set as a warning.
                                report.warnings.push(format!(
                                    "cannot select avatar for {}: {error}",
                                    profile.name
                                ));
                                continue;
                            }
                        }
                    }
                };
                reserved_avatar_ids.insert(chosen.asset_id.clone());
                Some(chosen)
            }
        };
        let fingerprint = profile_fingerprint(
            profile,
            &config.bridge.relay_url,
            pack.as_ref().map(|pack| pack.pack_id.as_str()),
            avatar.as_ref().map(|avatar| avatar.sha256.as_str()),
        );
        let published_at = cached
            .and_then(|cached| cached.get("published_at"))
            .and_then(Value::as_i64);
        let unchanged = cached
            .map(|cached| {
                cached.get("public_key").and_then(Value::as_str)
                    == Some(profile.public_key.as_str())
                    && cached.get("fingerprint").and_then(Value::as_str)
                        == Some(fingerprint.as_str())
            })
            .unwrap_or(false);
        let fresh = published_at
            .map(|published_at| {
                0 <= now - published_at && now - published_at < IDENTITY_PROFILE_REFRESH_SECONDS
            })
            .unwrap_or(false);
        if unchanged && fresh {
            continue;
        }

        let avatar_label = avatar
            .as_ref()
            .map(|avatar| format!(" with {}", avatar.asset_id))
            .unwrap_or_default();
        report.actions.push(format!(
            "{} profile for {}{avatar_label}",
            if apply { "publish" } else { "would publish" },
            profile.name
        ));
        if !apply {
            continue;
        }

        let (private_key, auth_tag) = profile_credentials(config, profile);
        let private_key = match private_key {
            Some(private_key) if !private_key.is_empty() => private_key,
            _ => {
                report.warnings.push(format!(
                    "cannot publish profile for {}: its private key is unavailable",
                    profile.name
                ));
                continue;
            }
        };

        let mut picture: Option<String> = None;
        if let Some(avatar) = &avatar {
            let cached_upload = uploads
                .get(avatar.sha256.as_str())
                .filter(|value| value.is_object());
            if let Some(cached_upload) = cached_upload {
                if cached_upload.get("relay_url").and_then(Value::as_str)
                    == Some(config.bridge.relay_url.as_str())
                {
                    picture = picture_url(cached_upload.get("url"));
                }
            }
            if picture.is_none() {
                let uploader = (deps.make_uploader)(&private_key, auth_tag.as_deref());
                let descriptor = match uploader.upload_file(&avatar.path) {
                    Ok(descriptor) => descriptor,
                    Err(error) => {
                        report.warnings.push(format!(
                            "cannot upload avatar for {}: {error}",
                            profile.name
                        ));
                        continue;
                    }
                };
                picture = picture_url(descriptor.get("url"));
                let picture_value = match &picture {
                    Some(picture_value) => picture_value.clone(),
                    None => {
                        report.warnings.push(format!(
                            "cannot upload avatar for {}: Buzz returned no public HTTP URL",
                            profile.name
                        ));
                        continue;
                    }
                };
                uploads.insert(
                    avatar.sha256.clone(),
                    json!({
                        "asset_id": avatar.asset_id,
                        "traits": traits_value(avatar),
                        "relay_url": config.bridge.relay_url,
                        "url": picture_value,
                        "uploaded_at": now,
                    }),
                );
            }
        }

        if let Err(error) = deps.publisher.publish_profile(
            &config.bridge.relay_url,
            &private_key,
            &profile.name,
            &profile.about,
            picture.as_deref(),
        ) {
            report.warnings.push(format!(
                "cannot publish profile for {}: {error}",
                profile.name
            ));
            continue;
        }
        cache.insert(
            profile.cache_id.clone(),
            json!({
                "public_key": profile.public_key,
                "fingerprint": fingerprint,
                "published_at": now,
                "avatar_id": avatar.as_ref().map(|avatar| avatar.asset_id.clone()),
                "avatar_pack": pack.as_ref().map(|pack| pack.pack_id.clone()),
                "avatar_sha256": avatar.as_ref().map(|avatar| avatar.sha256.clone()),
                "avatar_traits": avatar.as_ref().map(traits_value).unwrap_or_else(|| json!({})),
                "picture_url": picture,
            }),
        );
    }

    put_back(state, "identity_profiles", cache_value);
    put_back(state, "avatar_uploads", uploads_value);
}

/// Publish kind:10100 declarations for changed agent profiles.
///
/// Port of `_sync_agent_profiles`.
pub fn sync_agent_profiles<P: ProfilePublisher>(
    config: &Config,
    topology: &Topology,
    state: &mut Value,
    report: &mut SyncReport,
    apply: bool,
    now: i64,
    publisher: &P,
) {
    let channels = state.get("channels").cloned().unwrap_or_else(|| json!({}));
    let mut cache_value = ensure_and_take(state, "agent_profiles");
    let cache = cache_value
        .as_object_mut()
        .expect("agent_profiles is an object");

    let declarations = build_agent_profile_declarations(config, topology, &channels);
    for declaration in &declarations {
        let cached = cache
            .get(declaration.identity_id.as_str())
            .filter(|value| value.is_object());
        let published_at = cached
            .and_then(|cached| cached.get("published_at"))
            .and_then(Value::as_i64);
        let fingerprint = declaration.fingerprint();
        let unchanged = cached
            .map(|cached| {
                cached.get("public_key").and_then(Value::as_str)
                    == Some(declaration.public_key.as_str())
                    && cached.get("fingerprint").and_then(Value::as_str)
                        == Some(fingerprint.as_str())
            })
            .unwrap_or(false);
        let fresh = published_at
            .map(|published_at| {
                0 <= now - published_at && now - published_at < AGENT_PROFILE_REFRESH_SECONDS
            })
            .unwrap_or(false);
        if unchanged && fresh {
            continue;
        }

        let channel_count = declaration
            .content
            .get("channel_ids")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        let verb = if apply { "publish" } else { "would publish" };
        report.actions.push(format!(
            "{verb} agent declaration for {} ({} channel{})",
            declaration.identity_id,
            channel_count,
            if channel_count != 1 { "s" } else { "" }
        ));
        if !apply {
            continue;
        }

        let (private_key, _auth_tag) = config
            .identity_credentials(&declaration.identity_id)
            .unwrap_or((None, None));
        let private_key = match private_key {
            Some(private_key) if !private_key.is_empty() => private_key,
            _ => {
                report.warnings.push(format!(
                    "cannot publish agent declaration for {}: its private key is unavailable",
                    declaration.identity_id
                ));
                continue;
            }
        };
        if let Err(error) = publisher.publish_agent_profile(
            &config.bridge.relay_url,
            &private_key,
            &declaration.content,
        ) {
            report.warnings.push(format!(
                "cannot publish agent declaration for {}: {error}",
                declaration.identity_id
            ));
            continue;
        }
        cache.insert(
            declaration.identity_id.clone(),
            json!({
                "public_key": declaration.public_key,
                "fingerprint": fingerprint,
                "published_at": now,
                "channel_ids": declaration
                    .content
                    .get("channel_ids")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            }),
        );
    }

    put_back(state, "agent_profiles", cache_value);
}

fn reconcile_unlocked(
    config: &Config,
    topology: &Topology,
    store: &StateStore,
    force_apply: bool,
) -> Result<SyncReport, CommandError> {
    let apply = force_apply || config.bridge.sync_enabled;
    let mut report = SyncReport {
        applied: apply,
        actions: Vec::new(),
        warnings: topology.warnings.clone(),
    };
    let mut state = store
        .load_strict()
        .map_err(|error| CommandError(format!("cannot load state: {error}")))?;
    normalize_managed_resources(&mut state);
    let signer_records = config.reader_credentials();
    let (bridge_key, bridge_auth) = config.bridge_credentials();
    let bridge_pubkey = config
        .bridge
        .bridge_public_key
        .clone()
        .filter(|value| !value.is_empty());
    let human_pubkey = config.human_public_key();
    if signer_records.is_empty() {
        report
            .warnings
            .push("No Buzz credential is available; channel discovery was skipped".to_string());
        for space in &topology.spaces {
            report
                .actions
                .push(format!("would discover or create #{}", space.channel_name));
        }
        return Ok(report);
    }
    if apply && bridge_key.is_none() {
        return err(format!(
            "sync is enabled but {} is unavailable; run `buzzr bootstrap` to create the \
             operational bridge identity",
            config.bridge.bridge_private_key_env
        ));
    }

    let readers: Vec<(Option<String>, BuzzClient)> = signer_records
        .iter()
        .map(|(pubkey, private_key, auth_tag)| {
            (
                pubkey.clone(),
                BuzzClient::new(
                    config.bridge.buzz_bin.clone(),
                    config.bridge.relay_url.clone(),
                    private_key.clone(),
                    auth_tag.clone(),
                ),
            )
        })
        .collect();
    // Index into `readers`; usize::MAX marks the writer client.
    const WRITER: usize = usize::MAX;
    let mut channels_by_id: HashMap<String, Value> = HashMap::new();
    let mut channel_readers: HashMap<String, usize> = HashMap::new();
    for (index, (_pubkey, client)) in readers.iter().enumerate() {
        let visible = match client.list_channels() {
            Ok(visible) => visible,
            Err(error) => {
                report.warnings.push(format!(
                    "one Buzz identity could not list channels: {error}"
                ));
                continue;
            }
        };
        for channel in visible {
            if let Some(channel_id) = channel_id_of(&channel) {
                channel_readers.entry(channel_id.clone()).or_insert(index);
                channels_by_id.entry(channel_id).or_insert(channel);
            }
        }
    }

    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
    for (channel_id, channel) in &channels_by_id {
        let name = channel
            .get("name")
            .map(json_str)
            .unwrap_or_default()
            .to_lowercase();
        if !name.is_empty() {
            by_name.entry(name).or_default().push(channel_id.clone());
        }
    }

    let writer = bridge_key.map(|bridge_key| {
        BuzzClient::new(
            config.bridge.buzz_bin.clone(),
            config.bridge.relay_url.clone(),
            bridge_key,
            bridge_auth,
        )
    });
    let active_workspace_ids: HashSet<&str> = topology
        .spaces
        .iter()
        .map(|space| space.workspace_id.as_str())
        .collect();

    for space in &topology.spaces {
        let mapping = state
            .get("channels")
            .and_then(|channels| channels.get(space.workspace_id.as_str()))
            .filter(|value| value.is_object());
        let mut channel_origin = mapping
            .and_then(|mapping| mapping.get("origin"))
            .and_then(Value::as_str)
            .filter(|value| matches!(*value, "created" | "adopted"))
            .unwrap_or("unknown")
            .to_string();
        let pending_marker = mapping
            .and_then(|mapping| mapping.get("creation_marker"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let creation_pending = mapping
            .and_then(|mapping| mapping.get("origin"))
            .and_then(Value::as_str)
            == Some("creating")
            && mapping
                .and_then(|mapping| mapping.get("name"))
                .and_then(Value::as_str)
                == Some(space.channel_name.as_str());
        let mapping_archived = mapping
            .and_then(|mapping| mapping.get("archived"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let mapped_channel_id = mapping
            .and_then(|mapping| mapping.get("channel_id"))
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let mut channel_id: Option<String> = if mapping_archived {
            None
        } else {
            mapped_channel_id.clone()
        };
        if mapping_archived {
            match (channel_origin.as_str(), mapped_channel_id) {
                ("created", Some(archived_channel_id)) => {
                    report.actions.push(format!(
                        "{} #{}",
                        if apply {
                            "unarchive"
                        } else {
                            "would unarchive"
                        },
                        space.channel_name
                    ));
                    if !apply {
                        continue;
                    }
                    let Some(writer) = &writer else {
                        return err("cannot unarchive a buzzr-created channel without the bridge credential");
                    };
                    writer.unarchive_channel_idempotent(&archived_channel_id)?;
                    state["channels"][space.workspace_id.as_str()]["archived"] = json!(false);
                    checkpoint_provenance(store, &state)?;
                    channel_readers.insert(archived_channel_id.clone(), WRITER);
                    channel_id = Some(archived_channel_id);
                }
                _ => {
                    report.warnings.push(format!(
                        "preserving archived mapping for #{}: only a buzzr-created channel can be unarchived automatically",
                        space.channel_name
                    ));
                    continue;
                }
            }
        }
        let exact = by_name
            .get(&space.channel_name.to_lowercase())
            .cloned()
            .unwrap_or_default();
        let mut recovered_creation = false;
        if channel_id.is_none() {
            if exact.len() == 1 {
                channel_id = channels_by_id.get(&exact[0]).and_then(channel_id_of);
                if let Some(channel_id) = &channel_id {
                    let marker_matches = pending_marker.as_ref().is_some_and(|marker| {
                        channel_has_creation_marker(&channels_by_id[&exact[0]], marker)
                    });
                    if creation_pending && marker_matches {
                        channel_origin = "created".to_string();
                        recovered_creation = true;
                        report.actions.push(format!(
                            "recovered interrupted creation of #{} ({channel_id})",
                            space.channel_name
                        ));
                    } else if creation_pending {
                        report.warnings.push(format!(
                            "preserving #{}: interrupted creation marker did not match",
                            space.channel_name
                        ));
                        continue;
                    } else {
                        channel_origin = "adopted".to_string();
                        report.actions.push(format!(
                            "adopted existing #{} ({channel_id})",
                            space.channel_name
                        ));
                    }
                }
            } else if exact.len() > 1 {
                report.warnings.push(format!(
                    "multiple Buzz channels exactly match {}; refusing to guess",
                    quoted_repr(&space.channel_name)
                ));
                continue;
            }
        }

        if creation_pending && channel_id.is_none() {
            report.warnings.push(format!(
                "creation of #{} is still unresolved; refusing to issue a duplicate create",
                space.channel_name
            ));
            continue;
        }

        let description = config
            .bridge
            .channel_description
            .replace("{space}", &space.workspace_label)
            .replace("{workspace_id}", &space.workspace_id);
        let mut created_now = false;
        if channel_id.is_none() {
            report.actions.push(format!(
                "{} #{}",
                if apply { "create" } else { "would create" },
                space.channel_name
            ));
            if apply {
                if let Some(writer) = &writer {
                    let creation_marker =
                        channel_creation_marker(&space.workspace_id, bridge_pubkey.as_deref());
                    state["channels"][space.workspace_id.as_str()] = json!({
                        "channel_id": null,
                        "name": space.channel_name,
                        "space_label": space.workspace_label,
                        "origin": "creating",
                        "creation_marker": creation_marker,
                    });
                    checkpoint_provenance(store, &state)?;
                    let marked_description = format!("{description}\n\n[{creation_marker}]");
                    let created = writer.create_channel(
                        &space.channel_name,
                        &config.bridge.channel_type,
                        &config.bridge.channel_visibility,
                        &marked_description,
                    )?;
                    let created_id = channel_id_of(&created).ok_or_else(|| {
                        CommandError(format!(
                            "Buzz did not return a channel id for {}",
                            space.channel_name
                        ))
                    })?;
                    channel_readers.insert(created_id.clone(), WRITER);
                    channel_id = Some(created_id);
                    channel_origin = "created".to_string();
                    created_now = true;
                }
            }
        }

        let channel_id = match channel_id {
            Some(channel_id) => channel_id,
            None => continue,
        };
        state["channels"][space.workspace_id.as_str()] = json!({
            "channel_id": channel_id,
            "name": space.channel_name,
            "space_label": space.workspace_label,
            "origin": channel_origin,
        });
        if created_now {
            if let Some(bridge_pubkey) = &bridge_pubkey {
                record_channel_membership(&mut state, &channel_id, bridge_pubkey, "owner", "added");
            }
        }
        if created_now || recovered_creation {
            checkpoint_provenance(store, &state)?;
            if let Some(writer) = &writer {
                writer.update_channel(&channel_id, &space.channel_name, &description)?;
            }
        }

        let channel_reader = match channel_readers.get(&channel_id) {
            Some(&WRITER) => writer.as_ref(),
            Some(&index) => readers.get(index).map(|(_pubkey, client)| client),
            None => writer.as_ref(),
        };
        let channel_reader = match channel_reader {
            Some(channel_reader) => channel_reader,
            None => {
                report
                    .warnings
                    .push(format!("cannot inspect members of #{}", space.channel_name));
                continue;
            }
        };
        let current_members = match channel_reader.members(&channel_id) {
            Ok(current_members) => current_members,
            Err(error) => {
                report.warnings.push(format!(
                    "cannot inspect members of #{}: {error}",
                    space.channel_name
                ));
                continue;
            }
        };
        let mut current_roles: HashMap<String, String> = HashMap::new();
        for member in &current_members {
            let pubkey = member.get("pubkey").unwrap_or(&Value::Null);
            if json_truthy(pubkey) {
                let role = member
                    .get("role")
                    .map(json_str)
                    .unwrap_or_else(|| "member".to_string());
                current_roles.insert(json_str(pubkey).to_lowercase(), role);
            }
        }

        // An adopted private channel may predate buzzr. Any existing member may
        // invite the bridge as a normal member; after that the bridge can add
        // non-elevated bot identities without the human's private key.
        if let Some(bridge_pubkey) = &bridge_pubkey {
            if !current_roles.contains_key(bridge_pubkey) {
                report.actions.push(format!(
                    "{} buzzr bridge to #{}",
                    if apply { "add" } else { "would add" },
                    space.channel_name
                ));
                if apply {
                    let mut inviter: Option<&BuzzClient> = readers
                        .iter()
                        .find(|(pubkey, _client)| {
                            pubkey
                                .as_ref()
                                .map(|pubkey| current_roles.contains_key(pubkey))
                                .unwrap_or(false)
                        })
                        .map(|(_pubkey, client)| client);
                    // A newly-created channel is already owned by the bridge
                    // even if a stale read omitted it.
                    if inviter.is_none()
                        && writer.is_some()
                        && !channels_by_id.contains_key(&channel_id)
                    {
                        inviter = writer.as_ref();
                    }
                    let inviter = match inviter {
                        Some(inviter) => inviter,
                        None => {
                            report.warnings.push(format!(
                                "no configured member can invite the bridge to #{}",
                                space.channel_name
                            ));
                            continue;
                        }
                    };
                    record_channel_membership(
                        &mut state,
                        &channel_id,
                        bridge_pubkey,
                        "member",
                        "adding",
                    );
                    checkpoint_provenance(store, &state)?;
                    inviter.add_member(&channel_id, bridge_pubkey, "member")?;
                    current_roles.insert(bridge_pubkey.clone(), "member".to_string());
                    record_channel_membership(
                        &mut state,
                        &channel_id,
                        bridge_pubkey,
                        "member",
                        "added",
                    );
                    checkpoint_provenance(store, &state)?;
                }
            }
        }

        if let Some(human_pubkey) = &human_pubkey {
            if !current_roles.contains_key(human_pubkey) {
                report.actions.push(format!(
                    "{} human owner to #{}",
                    if apply { "add" } else { "would add" },
                    space.channel_name
                ));
                if apply {
                    if let Some(writer) = &writer {
                        let bridge_role = current_roles.get(bridge_pubkey.as_deref().unwrap_or(""));
                        let elevated = matches!(
                            bridge_role.map(String::as_str),
                            Some("owner") | Some("admin")
                        );
                        if !elevated {
                            report.warnings.push(format!(
                                "buzzr is not elevated in adopted #{}; it cannot grant human \
                                 ownership",
                                space.channel_name
                            ));
                        } else {
                            record_channel_membership(
                                &mut state,
                                &channel_id,
                                human_pubkey,
                                "owner",
                                "adding",
                            );
                            checkpoint_provenance(store, &state)?;
                            writer.add_member(&channel_id, human_pubkey, "owner")?;
                            current_roles.insert(human_pubkey.clone(), "owner".to_string());
                            record_channel_membership(
                                &mut state,
                                &channel_id,
                                human_pubkey,
                                "owner",
                                "added",
                            );
                            checkpoint_provenance(store, &state)?;
                        }
                    }
                }
            }
        }

        for pubkey in space.member_pubkeys() {
            if current_roles.contains_key(&pubkey) {
                continue;
            }
            let identity_names: BTreeSet<&str> = space
                .agents
                .iter()
                .filter(|agent| agent.public_key.as_deref() == Some(pubkey.as_str()))
                .filter_map(|agent| agent.identity_id.as_deref())
                .filter(|identity_id| !identity_id.is_empty())
                .collect();
            let label = if identity_names.is_empty() {
                pubkey.chars().take(12).collect::<String>()
            } else {
                identity_names.into_iter().collect::<Vec<_>>().join(", ")
            };
            report.actions.push(format!(
                "{} {label} to #{}",
                if apply { "add" } else { "would add" },
                space.channel_name
            ));
            if apply {
                if let Some(writer) = &writer {
                    record_channel_membership(&mut state, &channel_id, &pubkey, "bot", "adding");
                    checkpoint_provenance(store, &state)?;
                    writer.add_member(&channel_id, &pubkey, "bot")?;
                    record_channel_membership(&mut state, &channel_id, &pubkey, "bot", "added");
                    checkpoint_provenance(store, &state)?;
                }
            }
        }

        if config.bridge.remove_departed_agents {
            let desired = space.member_pubkeys();
            let tracked: Vec<(String, String)> = state["managed_resources"]["channel_memberships"]
                .get(&channel_id)
                .and_then(Value::as_object)
                .map(|memberships| {
                    memberships
                        .iter()
                        .filter_map(|(pubkey, record)| {
                            if !has_origin(record, "added") {
                                return None;
                            }
                            let role = record.get("role").and_then(Value::as_str)?;
                            (role == "bot").then(|| (pubkey.clone(), role.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();
            for (pubkey, recorded_role) in tracked {
                if desired.contains(&pubkey) {
                    continue;
                }
                let current_role = current_roles.get(&pubkey).map(String::as_str);
                if current_role.is_none() {
                    forget_channel_membership(&mut state, &channel_id, &pubkey);
                    continue;
                }
                if current_role != Some(recorded_role.as_str()) {
                    report.warnings.push(format!(
                        "preserving departed {} in #{} because its role changed from {} to {}",
                        pubkey.chars().take(12).collect::<String>(),
                        space.channel_name,
                        recorded_role,
                        current_role.unwrap_or_default(),
                    ));
                    continue;
                }
                report.actions.push(format!(
                    "{} departed {} from #{}",
                    if apply { "remove" } else { "would remove" },
                    pubkey.chars().take(12).collect::<String>(),
                    space.channel_name,
                ));
                if apply {
                    let remover = readers
                        .iter()
                        .find(|(reader_pubkey, _)| {
                            reader_pubkey.as_deref() == Some(pubkey.as_str())
                        })
                        .map(|(_, client)| client);
                    match remover {
                        Some(remover) => {
                            remover.remove_member(&channel_id, &pubkey)?;
                            current_roles.remove(&pubkey);
                            forget_channel_membership(&mut state, &channel_id, &pubkey);
                            checkpoint_provenance(store, &state)?;
                        }
                        None => report.warnings.push(format!(
                            "cannot remove departed {} from #{} without its credential",
                            pubkey.chars().take(12).collect::<String>(),
                            space.channel_name,
                        )),
                    }
                }
            }
        }
    }

    if config.bridge.archive_closed_spaces {
        let channel_entries: Vec<(String, Value)> = state
            .get("channels")
            .and_then(Value::as_object)
            .map(|channels| {
                channels
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (workspace_id, mapping) in channel_entries {
            if active_workspace_ids.contains(workspace_id.as_str()) || !mapping.is_object() {
                continue;
            }
            let channel_id = mapping
                .get("channel_id")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty());
            let name = mapping
                .get("name")
                .map(json_str)
                .unwrap_or_else(|| workspace_id.clone());
            let origin = mapping
                .get("origin")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if !has_origin(&mapping, "created") {
                report.warnings.push(format!(
                    "preserving closed #{name}: channel origin is {origin}, not buzzr-created"
                ));
                continue;
            }
            if mapping
                .get("archived")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            if let Some(channel_id) = channel_id {
                report.actions.push(format!(
                    "{} #{name}",
                    if apply { "archive" } else { "would archive" }
                ));
                if apply {
                    if let Some(writer) = &writer {
                        writer.archive_channel_idempotent(channel_id)?;
                        state["channels"][&workspace_id]["archived"] = json!(true);
                        checkpoint_provenance(store, &state)?;
                    }
                }
            }
        }
    }

    let now = now_seconds();
    let nak = NostrTools::new();
    let deps = production_deps(config, &nak);
    let avatar_dir = store.directory.join("avatars");
    sync_identity_profiles(
        config,
        &mut state,
        &mut report,
        apply,
        now,
        Some(&avatar_dir),
        &deps,
    );
    sync_agent_profiles(config, topology, &mut state, &mut report, apply, now, &nak);

    state["last_reconcile_at"] = json!(now_seconds());
    state["last_error"] = Value::Null;
    store
        .save(&state)
        .map_err(|error| CommandError(format!("cannot save state: {error}")))?;
    Ok(report)
}

/// Reconcile while preventing daemon/actions from overwriting newer state.
pub fn reconcile(
    config: &Config,
    topology: &Topology,
    store: &StateStore,
    force_apply: bool,
) -> Result<SyncReport, CommandError> {
    store
        .with_lock(|| reconcile_unlocked(config, topology, store, force_apply))
        .map_err(|error| CommandError(format!("cannot lock state: {error}")))?
}

/// Refresh managed Nostr profiles without an unrelated channel scan.
pub fn refresh_profiles(
    config: &Config,
    topology: &Topology,
    store: &StateStore,
    reupload: bool,
) -> Result<SyncReport, CommandError> {
    let mut report = SyncReport {
        applied: true,
        actions: Vec::new(),
        warnings: topology.warnings.clone(),
    };
    store
        .with_lock(|| -> Result<(), CommandError> {
            let mut state = store
                .load_strict()
                .map_err(|error| CommandError(format!("cannot load state: {error}")))?;
            let profiles_object = state
                .get("identity_profiles")
                .map(Value::is_object)
                .unwrap_or(false);
            if profiles_object {
                if let Some(Value::Object(profiles)) = state.get_mut("identity_profiles") {
                    for cached in profiles.values_mut() {
                        if let Value::Object(cached) = cached {
                            cached.remove("published_at");
                        }
                    }
                }
            } else {
                state["identity_profiles"] = json!({});
            }
            if reupload {
                state["avatar_uploads"] = json!({});
            }

            let now = now_seconds();
            let nak = NostrTools::new();
            let deps = production_deps(config, &nak);
            let avatar_dir = store.directory.join("avatars");
            sync_identity_profiles(
                config,
                &mut state,
                &mut report,
                true,
                now,
                Some(&avatar_dir),
                &deps,
            );
            sync_agent_profiles(config, topology, &mut state, &mut report, true, now, &nak);
            state["last_error"] = Value::Null;
            store
                .save(&state)
                .map_err(|error| CommandError(format!("cannot save state: {error}")))?;
            Ok(())
        })
        .map_err(|error| CommandError(format!("cannot lock state: {error}")))??;
    Ok(report)
}

#[cfg(test)]
mod lifecycle_tests {
    use super::{channel_has_creation_marker, has_origin};
    use serde_json::json;

    #[test]
    fn destructive_reconciliation_requires_exact_provenance() {
        assert!(has_origin(&json!({"origin": "created"}), "created"));
        assert!(has_origin(&json!({"origin": "added"}), "added"));
        assert!(!has_origin(&json!({}), "created"));
        assert!(!has_origin(&json!({"origin": "adopted"}), "created"));
        assert!(!has_origin(&json!({"origin": "manual"}), "added"));
    }

    #[test]
    fn interrupted_creation_requires_the_exact_remote_marker() {
        let channel = json!({"description": "Managed [buzzr-create:ours]"});
        assert!(channel_has_creation_marker(&channel, "buzzr-create:ours"));
        assert!(!channel_has_creation_marker(&channel, "buzzr-create:other"));
        assert!(!channel_has_creation_marker(
            &json!({}),
            "buzzr-create:ours"
        ));
    }
}
