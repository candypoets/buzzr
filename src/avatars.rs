//! Avatar pack loading, integrity checking, stable selection, and layered
//! PNG composition.

use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use regex::Regex;
use sha2::{Digest, Sha256};

pub const DEFAULT_AVATAR_PACK: &str = "bees-v2";
pub const COMPOSITOR_VERSION: u64 = 1;
pub const MAX_CANVAS_EDGE: i64 = 2048;

const PNG_SIGNATURE: [u8; 8] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/// Root directory containing the bundled avatar packs.
pub fn avatar_packs_root() -> PathBuf {
    crate::paths::plugin_root().join("assets").join("avatars")
}

fn pack_id_re() -> Regex {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]*$").unwrap()
}

fn sha256_re() -> Regex {
    Regex::new(r"^[0-9a-f]{64}$").unwrap()
}

/// Raised when an avatar pack is malformed or unsafe to use.
#[derive(Debug)]
pub struct AvatarPackError(pub String);

impl fmt::Display for AvatarPackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AvatarPackError {}

fn err<T>(message: impl Into<String>) -> Result<T, AvatarPackError> {
    Err(AvatarPackError(message.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarAsset {
    pub asset_id: String,
    pub collection: String,
    pub path: PathBuf,
    pub sha256: String,
    pub traits: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarTrait {
    pub trait_id: String,
    pub path: Option<PathBuf>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvatarLayer {
    pub layer_id: String,
    pub z_index: i64,
    pub traits: Vec<AvatarTrait>,
}

#[derive(Debug, Clone, Default)]
pub struct AvatarPack {
    pub pack_id: String,
    pub root: PathBuf,
    pub assets: Vec<AvatarAsset>,
    pub layers: Vec<AvatarLayer>,
    pub width: u32,
    pub height: u32,
    pub version: u32,
}

impl AvatarPack {
    pub fn layered(&self) -> bool {
        !self.layers.is_empty()
    }

    pub fn combination_count(&self) -> usize {
        if !self.layered() {
            return self.assets.len();
        }
        self.layers.iter().map(|layer| layer.traits.len()).product()
    }
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut digest = Sha256::new();
    let mut handle = File::open(path)?;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = handle.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

/// Lexically resolve `.` and `..` components without filesystem access or
/// symlink handling.
pub(crate) fn normalize_lexical(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn expanduser(path: &Path) -> Result<PathBuf, AvatarPackError> {
    let text = path.to_string_lossy();
    if text == "~" || text.starts_with("~/") {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| AvatarPackError("cannot expand ~: HOME is not set".to_string()))?;
        let mut expanded = PathBuf::from(home);
        if text.len() > 2 {
            expanded.push(&text[2..]);
        }
        Ok(expanded)
    } else {
        Ok(path.to_path_buf())
    }
}

fn pack_root(pack_id: &str, custom_path: Option<&Path>) -> Result<PathBuf, AvatarPackError> {
    if let Some(custom) = custom_path {
        let resolved = normalize_lexical(&expanduser(custom)?);
        // Follow symlinks when the path exists.
        return Ok(resolved.canonicalize().unwrap_or(resolved));
    }
    if !pack_id_re().is_match(pack_id) {
        return err(format!("invalid bundled avatar pack id: {pack_id:?}"));
    }
    Ok(avatar_packs_root().join(pack_id))
}

fn asset_path(
    root: &Path,
    filename: Option<&serde_json::Value>,
    asset_id: &str,
    suffixes: &[&str],
) -> Result<PathBuf, AvatarPackError> {
    let filename = match filename.and_then(|value| value.as_str()) {
        Some(name) if !name.is_empty() => name,
        _ => return err(format!("avatar {asset_id} has an invalid file")),
    };
    let path = normalize_lexical(&root.join(filename));
    if !path.starts_with(root) {
        return err(format!("avatar {asset_id} escapes its pack directory"));
    }
    // A symlink inside the pack must not be able to escape the pack root.
    if path.is_file() {
        if let Ok(canonical) = path.canonicalize() {
            let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            if !canonical.starts_with(&canonical_root) {
                return err(format!("avatar {asset_id} escapes its pack directory"));
            }
            return Ok(canonical);
        }
    }
    let suffix = path
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if !suffixes.contains(&suffix.as_str()) {
        return err(format!(
            "avatar {asset_id} uses an unsupported image format"
        ));
    }
    if !path.is_file() {
        return err(format!("avatar file does not exist: {}", path.display()));
    }
    Ok(path)
}

/// Stable representation for JSON values that can appear as a pack version.
fn json_value_repr(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => format!("'{text}'"),
        other => other.to_string(),
    }
}

fn load_flat_pack(
    root: &Path,
    manifest_id: &str,
    manifest: &serde_json::Value,
) -> Result<AvatarPack, AvatarPackError> {
    let raw_assets = match manifest.get("assets").and_then(|v| v.as_array()) {
        Some(assets) if !assets.is_empty() => assets,
        _ => return err("avatar pack manifest must contain at least one asset"),
    };

    let mut assets: Vec<AvatarAsset> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    for (index, raw) in raw_assets.iter().enumerate() {
        if !raw.is_object() {
            return err(format!("avatar entry {index} must be an object"));
        }
        let asset_id = raw.get("id").and_then(|v| v.as_str());
        let collection = raw.get("collection").and_then(|v| v.as_str());
        let expected_sha256 = raw.get("sha256").and_then(|v| v.as_str());

        let asset_id = match asset_id {
            Some(id) if pack_id_re().is_match(id) => id.to_string(),
            _ => return err(format!("avatar entry {index} has an invalid id")),
        };
        if seen_ids.contains(&asset_id) {
            return err(format!("duplicate avatar id: {asset_id}"));
        }
        match collection {
            Some(c) if !c.trim().is_empty() => {}
            _ => return err(format!("avatar {asset_id} has an invalid collection")),
        }
        let expected_sha256 = match expected_sha256 {
            Some(s) if sha256_re().is_match(s) => s,
            _ => return err(format!("avatar {asset_id} has an invalid sha256")),
        };

        let asset_path = asset_path(
            root,
            raw.get("file"),
            &asset_id,
            &["png", "jpg", "jpeg", "webp"],
        )?;
        if seen_files.contains(&asset_path) {
            let filename = raw.get("file").and_then(|v| v.as_str()).unwrap_or_default();
            return err(format!("duplicate avatar file: {filename}"));
        }
        let actual_sha256 = sha256_file(&asset_path)
            .map_err(|e| AvatarPackError(format!("cannot hash avatar {asset_id}: {e}")))?;
        if actual_sha256 != expected_sha256 {
            return err(format!(
                "avatar {asset_id} failed its sha256 integrity check"
            ));
        }

        seen_ids.insert(asset_id.clone());
        seen_files.insert(asset_path.clone());
        assets.push(AvatarAsset {
            asset_id,
            collection: collection.unwrap().to_string(),
            path: asset_path,
            sha256: actual_sha256,
            traits: Vec::new(),
        });
    }

    Ok(AvatarPack {
        pack_id: manifest_id.to_string(),
        root: root.to_path_buf(),
        assets,
        ..AvatarPack::default()
    })
}

/// Read only the IHDR of a PNG, enforcing non-interlaced 8-bit RGBA.
fn png_info(path: &Path) -> Result<(u32, u32), AvatarPackError> {
    let encoded = std::fs::read(path)
        .map_err(|e| AvatarPackError(format!("cannot read PNG layer {}: {e}", path.display())))?;
    let decoder = png::Decoder::new(std::io::Cursor::new(encoded));
    let reader = decoder.read_info().map_err(|_| {
        AvatarPackError(format!(
            "avatar layer is not a valid PNG: {}",
            path.display()
        ))
    })?;
    let info = reader.info();
    if info.color_type != png::ColorType::Rgba
        || info.bit_depth != png::BitDepth::Eight
        || info.interlaced
    {
        return err(format!(
            "avatar layer must be a non-interlaced 8-bit RGBA PNG: {}",
            path.display()
        ));
    }
    Ok((info.width, info.height))
}

fn load_layered_pack(
    root: &Path,
    manifest_id: &str,
    manifest: &serde_json::Value,
) -> Result<AvatarPack, AvatarPackError> {
    let canvas = match manifest.get("canvas").and_then(|v| v.as_object()) {
        Some(canvas) => canvas,
        None => return err("layered avatar pack must define a canvas"),
    };
    let width = canvas.get("width").and_then(|v| v.as_i64());
    let height = canvas.get("height").and_then(|v| v.as_i64());
    let (width, height) = match (width, height) {
        (Some(w), Some(h)) if 0 < w && w <= MAX_CANVAS_EDGE && 0 < h && h <= MAX_CANVAS_EDGE => {
            (w as u32, h as u32)
        }
        _ => return err("layered avatar pack has invalid canvas dimensions"),
    };

    let raw_layers = match manifest.get("layers").and_then(|v| v.as_array()) {
        Some(layers) if !layers.is_empty() => layers,
        _ => return err("layered avatar pack must contain at least one layer"),
    };
    let mut layers: Vec<AvatarLayer> = Vec::new();
    let mut seen_layer_ids: HashSet<String> = HashSet::new();
    let mut seen_files: HashSet<PathBuf> = HashSet::new();
    for (layer_index, raw_layer) in raw_layers.iter().enumerate() {
        if !raw_layer.is_object() {
            return err(format!("avatar layer {layer_index} must be an object"));
        }
        let layer_id = raw_layer.get("id").and_then(|v| v.as_str());
        let z_value = raw_layer.get("z");
        let raw_traits = raw_layer.get("traits").and_then(|v| v.as_array());
        let layer_id = match layer_id {
            Some(id) if pack_id_re().is_match(id) => id.to_string(),
            _ => return err(format!("avatar layer {layer_index} has an invalid id")),
        };
        if seen_layer_ids.contains(&layer_id) {
            return err(format!("duplicate avatar layer id: {layer_id}"));
        }
        let z_index = match z_value {
            None => layer_index as i64,
            Some(value) => match value.as_i64() {
                Some(z) => z,
                None => return err(format!("avatar layer {layer_id} has an invalid z index")),
            },
        };
        let raw_traits = match raw_traits {
            Some(traits) if !traits.is_empty() => traits,
            _ => return err(format!("avatar layer {layer_id} has no traits")),
        };

        let mut traits: Vec<AvatarTrait> = Vec::new();
        let mut seen_trait_ids: HashSet<String> = HashSet::new();
        for (trait_index, raw_trait) in raw_traits.iter().enumerate() {
            if !raw_trait.is_object() {
                return err(format!(
                    "trait {trait_index} in avatar layer {layer_id} must be an object"
                ));
            }
            let trait_id = raw_trait.get("id").and_then(|v| v.as_str());
            let trait_id = match trait_id {
                Some(id) if pack_id_re().is_match(id) => id.to_string(),
                _ => {
                    return err(format!(
                        "trait {trait_index} in avatar layer {layer_id} has an invalid id"
                    ))
                }
            };
            if seen_trait_ids.contains(trait_id.as_str()) {
                return err(format!("duplicate trait {layer_id}/{trait_id}"));
            }

            let filename = raw_trait.get("file");
            let expected_sha256 = raw_trait.get("sha256");
            let trait_entry = if filename.is_none() || filename == Some(&serde_json::Value::Null) {
                if expected_sha256.is_some() && expected_sha256 != Some(&serde_json::Value::Null) {
                    return err(format!(
                        "empty trait {layer_id}/{trait_id} cannot have a sha256"
                    ));
                }
                AvatarTrait {
                    trait_id: trait_id.clone(),
                    path: None,
                    sha256: None,
                }
            } else {
                let expected_sha256 = match expected_sha256.and_then(|v| v.as_str()) {
                    Some(s) if sha256_re().is_match(s) => s,
                    _ => return err(format!("trait {layer_id}/{trait_id} has an invalid sha256")),
                };
                let path = asset_path(root, filename, &format!("{layer_id}/{trait_id}"), &["png"])?;
                if seen_files.contains(&path) {
                    let name = filename.and_then(|v| v.as_str()).unwrap_or_default();
                    return err(format!("duplicate avatar layer file: {name}"));
                }
                let actual_sha256 = sha256_file(&path).map_err(|e| {
                    AvatarPackError(format!("cannot hash trait {layer_id}/{trait_id}: {e}"))
                })?;
                if actual_sha256 != expected_sha256 {
                    return err(format!(
                        "trait {layer_id}/{trait_id} failed its sha256 integrity check"
                    ));
                }
                if png_info(&path)? != (width, height) {
                    return err(format!(
                        "trait {layer_id}/{trait_id} does not match the {width}x{height} canvas"
                    ));
                }
                seen_files.insert(path.clone());
                AvatarTrait {
                    trait_id: trait_id.clone(),
                    path: Some(path),
                    sha256: Some(actual_sha256),
                }
            };

            seen_trait_ids.insert(trait_id);
            traits.push(trait_entry);
        }

        seen_layer_ids.insert(layer_id.clone());
        layers.push(AvatarLayer {
            layer_id,
            z_index,
            traits,
        });
    }

    layers.sort_by_key(|layer| layer.z_index);
    Ok(AvatarPack {
        pack_id: manifest_id.to_string(),
        root: root.to_path_buf(),
        layers,
        width,
        height,
        version: 2,
        ..AvatarPack::default()
    })
}

/// Load and integrity-check a bundled or user-supplied avatar pack.
pub fn load_avatar_pack(
    pack_id: &str,
    custom_path: Option<&Path>,
) -> Result<AvatarPack, AvatarPackError> {
    let root = pack_root(pack_id, custom_path)?;
    let manifest_path = root.join("manifest.json");
    let raw = match std::fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return err(format!(
                "avatar pack manifest does not exist: {}",
                manifest_path.display()
            ));
        }
        Err(e) => {
            return err(format!(
                "cannot read avatar pack manifest {}: {e}",
                manifest_path.display()
            ));
        }
    };
    let manifest: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(value) => value,
        Err(e) => {
            return err(format!(
                "cannot read avatar pack manifest {}: {e}",
                manifest_path.display()
            ));
        }
    };
    if !manifest.is_object() {
        return err(format!(
            "avatar pack manifest must be an object: {}",
            manifest_path.display()
        ));
    }

    let manifest_id = manifest.get("id").and_then(|v| v.as_str());
    let manifest_id = match manifest_id {
        Some(id) if pack_id_re().is_match(id) => id.to_string(),
        _ => return err("avatar pack manifest has an invalid id"),
    };
    let version = manifest
        .get("version")
        .cloned()
        .unwrap_or(serde_json::json!(1));
    if version == serde_json::json!(2) {
        return load_layered_pack(&root, &manifest_id, &manifest);
    }
    if version != serde_json::json!(1) {
        return err(format!(
            "unsupported avatar pack version: {}",
            json_value_repr(&version)
        ));
    }
    load_flat_pack(&root, &manifest_id, &manifest)
}

/// Select from a legacy pack of complete avatars.
pub fn select_avatar(
    pack: &AvatarPack,
    public_key: &str,
    excluded_ids: &HashSet<String>,
) -> Result<AvatarAsset, AvatarPackError> {
    if pack.layered() {
        return err("select_avatar cannot select from a layered avatar pack");
    }
    let candidates: Vec<&AvatarAsset> = pack
        .assets
        .iter()
        .filter(|asset| !excluded_ids.contains(&asset.asset_id))
        .collect();
    let candidates: Vec<&AvatarAsset> = if candidates.is_empty() {
        pack.assets.iter().collect()
    } else {
        candidates
    };
    if candidates.is_empty() {
        return err(format!("avatar pack {} contains no assets", pack.pack_id));
    }
    let seed = format!(
        "buzzr-avatar-v1:{}:{}:",
        pack.pack_id,
        public_key.to_lowercase()
    );
    Ok(candidates
        .into_iter()
        .max_by_key(|asset| {
            let mut digest = Sha256::new();
            digest.update(seed.as_bytes());
            digest.update(asset.asset_id.as_bytes());
            digest.finalize()
        })
        .expect("candidate list is not empty")
        .clone())
}

/// Independently and deterministically select one trait in every layer.
pub fn select_avatar_traits<'a>(
    pack: &'a AvatarPack,
    public_key: &str,
) -> Result<Vec<(&'a AvatarLayer, &'a AvatarTrait)>, AvatarPackError> {
    if !pack.layered() {
        return err(format!("avatar pack {} is not layered", pack.pack_id));
    }
    let mut selected = Vec::new();
    for layer in &pack.layers {
        let seed = format!(
            "buzzr-avatar-v2:{}:{}:{}",
            pack.pack_id,
            public_key.to_lowercase(),
            layer.layer_id
        );
        let digest = Sha256::digest(seed.as_bytes());
        // int.from_bytes(digest, "big") % len(layer.traits), folded bytewise.
        let count = layer.traits.len();
        let mut index = 0usize;
        for byte in digest {
            index = (index * 256 + byte as usize) % count;
        }
        selected.push((layer, &layer.traits[index]));
    }
    Ok(selected)
}

/// Decode a non-interlaced 8-bit RGBA PNG into raw pixels.
fn decode_png(path: &Path) -> Result<(u32, u32, Vec<u8>), AvatarPackError> {
    let encoded = std::fs::read(path)
        .map_err(|e| AvatarPackError(format!("cannot read PNG layer {}: {e}", path.display())))?;
    let decoder = png::Decoder::new(std::io::Cursor::new(encoded));
    let mut reader = decoder.read_info().map_err(|_| {
        AvatarPackError(format!(
            "avatar layer is not a valid PNG: {}",
            path.display()
        ))
    })?;
    let (width, height) = {
        let info = reader.info();
        if info.color_type != png::ColorType::Rgba
            || info.bit_depth != png::BitDepth::Eight
            || info.interlaced
        {
            return err(format!(
                "avatar layer must be a non-interlaced 8-bit RGBA PNG: {}",
                path.display()
            ));
        }
        (info.width, info.height)
    };
    let mut buffer = vec![0u8; reader.output_buffer_size()];
    let frame = reader.next_frame(&mut buffer).map_err(|_| {
        AvatarPackError(format!(
            "avatar layer has invalid compressed pixels: {}",
            path.display()
        ))
    })?;
    buffer.truncate(frame.buffer_size());
    Ok((width, height, buffer))
}

/// Alpha-composite `source` over `destination` (straight-alpha "over").
fn alpha_over(destination: &mut [u8], source: &[u8]) {
    for index in (0..destination.len()).step_by(4) {
        let source_alpha = source[index + 3] as u32;
        if source_alpha == 0 {
            continue;
        }
        let destination_alpha = destination[index + 3] as u32;
        if source_alpha == 255 || destination_alpha == 0 {
            destination[index..index + 4].copy_from_slice(&source[index..index + 4]);
            continue;
        }
        let inverse_alpha = 255 - source_alpha;
        if destination_alpha == 255 {
            for channel in 0..3 {
                destination[index + channel] = ((source[index + channel] as u32 * source_alpha
                    + destination[index + channel] as u32 * inverse_alpha
                    + 127)
                    / 255) as u8;
            }
            continue;
        }

        let output_alpha_scaled = source_alpha * 255 + destination_alpha * inverse_alpha;
        for channel in 0..3 {
            destination[index + channel] = ((source[index + channel] as u32 * source_alpha * 255
                + destination[index + channel] as u32 * destination_alpha * inverse_alpha
                + output_alpha_scaled / 2)
                / output_alpha_scaled) as u8;
        }
        destination[index + 3] = ((output_alpha_scaled + 127) / 255) as u8;
    }
}

/// Encode raw RGBA pixels deterministically: filter-0 scanlines, one IDAT with
/// zlib level 9, and CRC-32 checksummed chunks.
fn encode_png(width: u32, height: u32, pixels: &[u8]) -> Result<Vec<u8>, AvatarPackError> {
    use std::io::Write;

    fn chunk(chunk_type: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 12);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(chunk_type);
        out.extend_from_slice(data);
        let mut digest = crc32fast::Hasher::new();
        digest.update(chunk_type);
        digest.update(data);
        out.extend_from_slice(&digest.finalize().to_be_bytes());
        out
    }

    let stride = width as usize * 4;
    let mut scanlines = vec![0u8; (stride + 1) * height as usize];
    for row in 0..height as usize {
        let destination = row * (stride + 1);
        scanlines[destination] = 0;
        scanlines[destination + 1..destination + 1 + stride]
            .copy_from_slice(&pixels[row * stride..row * stride + stride]);
    }
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]);
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    encoder
        .write_all(&scanlines)
        .map_err(|e| AvatarPackError(format!("cannot encode PNG: {e}")))?;
    let compressed = encoder
        .finish()
        .map_err(|e| AvatarPackError(format!("cannot encode PNG: {e}")))?;

    let mut encoded = Vec::new();
    encoded.extend_from_slice(&PNG_SIGNATURE);
    encoded.extend_from_slice(&chunk(b"IHDR", &header));
    encoded.extend_from_slice(&chunk(b"IDAT", &compressed));
    encoded.extend_from_slice(&chunk(b"IEND", &[]));
    Ok(encoded)
}

/// Write `data` to `path` atomically (tempfile + fsync + chmod 0600 + rename).
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), AvatarPackError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let io_err = |e: std::io::Error| AvatarPackError(e.to_string());
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::DirBuilder::new()
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
    temporary.write_all(data).map_err(io_err)?;
    temporary.flush().map_err(io_err)?;
    temporary.as_file().sync_all().map_err(io_err)?;
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o600))
        .map_err(io_err)?;
    temporary
        .persist(path)
        .map_err(|e| AvatarPackError(e.error.to_string()))?;
    Ok(())
}

/// Compose a layered pack into one stable PNG derived from a public key.
pub fn compose_avatar(
    pack: &AvatarPack,
    public_key: &str,
    output_directory: Option<&Path>,
) -> Result<AvatarAsset, AvatarPackError> {
    let selected = select_avatar_traits(pack, public_key)?;
    let traits: Vec<(String, String)> = selected
        .iter()
        .map(|(layer, trait_entry)| (layer.layer_id.clone(), trait_entry.trait_id.clone()))
        .collect();
    let composition = serde_json::to_string(&serde_json::json!({
        "compositor": COMPOSITOR_VERSION,
        "pack": pack.pack_id,
        "canvas": [pack.width, pack.height],
        "traits": selected
            .iter()
            .map(|(layer, trait_entry)| serde_json::json!([
                layer.layer_id,
                trait_entry.trait_id,
                trait_entry.sha256,
            ]))
            .collect::<Vec<_>>(),
    }))
    .expect("composition serializes");
    let composition_id = &hex::encode(Sha256::digest(composition.as_bytes()))[..20];
    let asset_id = format!("{}-{composition_id}", pack.pack_id);
    let path = match output_directory {
        Some(directory) => directory.join(format!("{asset_id}.png")),
        None => pack.root.join(".composed").join(format!("{asset_id}.png")),
    };
    if output_directory.is_some() && path.is_file() {
        if let Ok((width, height)) = png_info(&path) {
            if (width, height) == (pack.width, pack.height) {
                let sha256 = sha256_file(&path)
                    .map_err(|e| AvatarPackError(format!("cannot hash avatar {asset_id}: {e}")))?;
                return Ok(AvatarAsset {
                    asset_id,
                    collection: "composed".to_string(),
                    path,
                    sha256,
                    traits,
                });
            }
        }
    }

    let mut canvas = vec![0u8; pack.width as usize * pack.height as usize * 4];
    for (_layer, trait_entry) in &selected {
        let trait_path = match &trait_entry.path {
            Some(path) => path,
            None => continue,
        };
        let (width, height, pixels) = decode_png(trait_path)?;
        if (width, height) != (pack.width, pack.height) {
            return err(format!(
                "trait {} changed dimensions after pack validation",
                trait_entry.trait_id
            ));
        }
        alpha_over(&mut canvas, &pixels);
    }
    let encoded = encode_png(pack.width, pack.height, &canvas)?;
    let digest = hex::encode(Sha256::digest(&encoded));
    if output_directory.is_some() {
        atomic_write(&path, &encoded)?;
    }
    Ok(AvatarAsset {
        asset_id,
        collection: "composed".to_string(),
        path,
        sha256: digest,
        traits,
    })
}

/// Build a layered avatar or select a legacy complete avatar.
pub fn build_avatar(
    pack: &AvatarPack,
    public_key: &str,
    output_directory: Option<&Path>,
    excluded_ids: &HashSet<String>,
) -> Result<AvatarAsset, AvatarPackError> {
    if pack.layered() {
        compose_avatar(pack, public_key, output_directory)
    } else {
        select_avatar(pack, public_key, excluded_ids)
    }
}
