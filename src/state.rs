//! Persistent JSON state with cross-process locking.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde_json::{json, Value};

pub const STATE_VERSION: u64 = 5;
pub const STATE_MARKER: &str = "buzzr-state-v1\n";

/// Fresh state document with all top-level keys present.
pub fn default_state() -> Value {
    json!({
        "version": STATE_VERSION,
        "channels": {},
        "agent_profiles": {},
        "identity_profiles": {},
        "avatar_uploads": {},
        "last_seen": {},
        "processed": [],
        "pending": [],
        "reply_contexts": {},
        "managed_resources": {
            "identities": {},
            "identity_intents": {},
            "relay_members": {},
            "ownerships": {},
            "channel_memberships": {},
        },
        "last_error": null,
        "last_reconcile_at": null,
    })
}

#[derive(Debug, Clone)]
pub struct StateStore {
    pub directory: PathBuf,
    pub path: PathBuf,
}

impl StateStore {
    pub fn new(directory: PathBuf) -> Self {
        let path = directory.join("state.json");
        StateStore { directory, path }
    }

    /// Create and validate the state directory without creating the ownership
    /// marker used by destructive local cleanup.
    pub fn ensure(&self) -> io::Result<()> {
        ensure_private_directory(&self.directory)
    }

    fn ensure_marker(&self) -> io::Result<()> {
        let marker = self.directory.join(".buzzr-state");
        match fs::symlink_metadata(&marker) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.uid() != effective_uid()
                    || fs::read_to_string(&marker)? != STATE_MARKER
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("invalid buzzr state marker: {}", marker.display()),
                    ));
                }
                fs::set_permissions(&marker, fs::Permissions::from_mode(0o600))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&marker)?;
                file.write_all(STATE_MARKER.as_bytes())?;
                file.sync_all()?;
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }

    /// Serialize cross-process read/modify/write state transactions.
    pub fn with_lock<F, T>(&self, f: F) -> io::Result<T>
    where
        F: FnOnce() -> T,
    {
        self.ensure()?;
        let lock_path = self.directory.join("state.lock");
        let lock = open_private_lock(&lock_path)?;
        lock.lock_exclusive()?;
        let result = f();
        lock.unlock()?;
        Ok(result)
    }

    /// Load state leniently: unreadable or corrupt state falls back to
    /// defaults. Destructive lifecycle operations use `load_strict`.
    pub fn load(&self) -> io::Result<Value> {
        if !self.path.exists() {
            return Ok(default_state());
        }
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(_) => return Ok(default_state()),
        };
        let value: Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(_) => return Ok(default_state()),
        };
        Ok(merge_state(value))
    }

    /// Load state without silently discarding provenance. This is required for
    /// deprovisioning, where an unreadable or corrupt file must fail closed.
    pub fn load_strict(&self) -> io::Result<Value> {
        let mut file = match open_private_read(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(default_state()),
            Err(error) => return Err(error),
        };
        validate_private_directory(&self.directory)?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        {
            let value: Value = serde_json::from_str(&text).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("cannot parse {}: {error}", self.path.display()),
                )
            })?;
            if !value.is_object() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{} is not a JSON object", self.path.display()),
                ));
            }
            let version = value
                .get("version")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} has no numeric state version", self.path.display()),
                    )
                })?;
            if version >= 4 {
                let resources = value
                    .get("managed_resources")
                    .and_then(Value::as_object)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "{} has invalid managed-resource provenance",
                                self.path.display()
                            ),
                        )
                    })?;
                let mut required = vec![
                    "identities",
                    "relay_members",
                    "ownerships",
                    "channel_memberships",
                ];
                if version >= 5 {
                    required.push("identity_intents");
                }
                if required
                    .into_iter()
                    .any(|key| !resources.get(key).map(Value::is_object).unwrap_or(false))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{} has invalid managed-resource provenance",
                            self.path.display()
                        ),
                    ));
                }
            }
            Ok(merge_state(value))
        }
    }

    /// Atomically persist state (tempfile + fsync + chmod 0600 + rename).
    pub fn save(&self, state: &Value) -> io::Result<()> {
        self.ensure()?;
        self.ensure_marker()?;
        let mut temporary = tempfile::Builder::new()
            .prefix("state-")
            .suffix(".json")
            .tempfile_in(&self.directory)?;
        let content = serde_json::to_string_pretty(state).map_err(io::Error::other)?;
        temporary.write_all(content.as_bytes())?;
        temporary.write_all(b"\n")?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))?;
        temporary.persist(&self.path).map_err(|error| error.error)?;
        Ok(())
    }
}

fn merge_state(value: Value) -> Value {
    let mut base = default_state();
    if let Value::Object(entries) = value {
        let base_map = base.as_object_mut().expect("default state is an object");
        for (key, entry) in entries {
            base_map.insert(key, entry);
        }
    }
    base.as_object_mut()
        .expect("default state is an object")
        .insert("version".to_string(), json!(STATE_VERSION));
    normalize_managed_resources(&mut base);
    base
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Reject symlinked, non-directory, foreign-owned, or non-private
/// state/runtime roots without changing their permissions.
pub fn validate_private_directory(path: &Path) -> io::Result<()> {
    check_owned_directory(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private directory must not grant group/world permissions: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn check_owned_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "private directory is not a real directory: {}",
                path.display()
            ),
        ));
    }
    if metadata.uid() != effective_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private directory is not owned by this user: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
            validate_private_directory(path)
        }
        Err(error) => Err(error),
    }
}

fn validate_existing_private_file(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != effective_uid()
                || metadata.mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("unsafe private file: {}", path.display()),
                ));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn validate_open_private_file(file: &File, path: &Path) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != effective_uid() || metadata.mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("unsafe private file: {}", path.display()),
        ));
    }
    Ok(())
}

/// Open and validate a private regular file through its descriptor, avoiding
/// path-based validation/read races and final-component symlink traversal.
pub fn open_private_read(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    validate_open_private_file(&file, path)?;
    Ok(file)
}

/// Open a user-owned regular lock file without following a final symlink.
pub fn open_private_lock(path: &Path) -> io::Result<File> {
    validate_existing_private_file(path)?;
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_open_private_file(&file, path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

/// Replace a user-owned regular runtime file without following symlinks.
pub fn write_private_file(path: &Path, content: &[u8]) -> io::Result<()> {
    validate_existing_private_file(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    validate_open_private_file(&file, path)?;
    file.set_len(0)?;
    file.write_all(content)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

/// Repair the provenance container without inferring ownership for legacy
/// resources. Missing provenance deliberately stays unknown and therefore
/// ineligible for destructive cleanup.
pub fn normalize_managed_resources(state: &mut Value) {
    if !state
        .get("managed_resources")
        .map(Value::is_object)
        .unwrap_or(false)
    {
        state["managed_resources"] = json!({});
    }
    for key in [
        "identities",
        "identity_intents",
        "relay_members",
        "ownerships",
        "channel_memberships",
    ] {
        if !state["managed_resources"]
            .get(key)
            .map(Value::is_object)
            .unwrap_or(false)
        {
            state["managed_resources"][key] = json!({});
        }
    }
}

/// Runtime directory: env override, else /tmp/buzzr-<uid>.
pub fn runtime_directory() -> PathBuf {
    if let Some(override_dir) = std::env::var("BUZZR_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            std::env::var("HERDR_BUZZ_RUNTIME_DIR")
                .ok()
                .filter(|value| !value.is_empty())
        })
    {
        return PathBuf::from(override_dir);
    }
    if let Some(directory) = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.is_empty())
    {
        return PathBuf::from(directory).join("buzzr");
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from("/tmp").join(format!("buzzr-{uid}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_has_all_keys() {
        let state = default_state();
        let map = state.as_object().unwrap();
        assert_eq!(map.len(), 12);
        assert_eq!(map["version"], json!(STATE_VERSION));
        assert!(map["last_error"].is_null());
        assert!(map["processed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::new(directory.path().join("nested"));
        let mut state = store.load().unwrap();
        state["channels"] = json!({"abc": {"name": "test"}});
        store.save(&state).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded["channels"]["abc"]["name"], json!("test"));
        assert_eq!(loaded["version"], json!(STATE_VERSION));

        // Corrupt JSON falls back to defaults.
        std::fs::write(&store.path, b"{not json").unwrap();
        assert_eq!(store.load().unwrap(), default_state());
    }

    #[test]
    fn private_runtime_files_never_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let victim = directory.path().join("victim");
        let link = directory.path().join("stop.request");
        fs::write(&victim, "keep\n").unwrap();
        symlink(&victim, &link).unwrap();

        assert!(write_private_file(&link, b"stop\n").is_err());
        assert_eq!(fs::read_to_string(victim).unwrap(), "keep\n");
    }

    #[test]
    fn strict_state_load_requires_private_file_and_directory_modes() {
        let directory = tempfile::tempdir().unwrap();
        let store = StateStore::new(directory.path().join("state"));
        store.save(&default_state()).unwrap();

        fs::set_permissions(&store.path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(store.load_strict().is_err());
        fs::set_permissions(&store.path, fs::Permissions::from_mode(0o600)).unwrap();

        fs::set_permissions(&store.directory, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(store.load_strict().is_err());
    }
}
