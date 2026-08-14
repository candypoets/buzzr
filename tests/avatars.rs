//! Avatar pack and composition tests.

use std::collections::HashSet;
use std::path::Path;

use buzzr::avatars::{
    compose_avatar, load_avatar_pack, select_avatar, select_avatar_traits, DEFAULT_AVATAR_PACK,
};
use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[test]
fn bundled_recraft_pack_is_layered_and_selection_is_stable() {
    let pack = load_avatar_pack(DEFAULT_AVATAR_PACK, None).expect("bundled pack loads");
    assert_eq!(pack.pack_id, "bees-v2");
    assert!(pack.layered());
    assert_eq!((pack.width, pack.height), (512, 512));
    assert_eq!(pack.combination_count(), 12_348);
    let layer_ids: Vec<&str> = pack.layers.iter().map(|l| l.layer_id.as_str()).collect();
    assert_eq!(
        layer_ids,
        ["background", "body", "neck", "eyewear", "headwear"]
    );

    let key = "a".repeat(64);
    let selected: Vec<(String, String)> = select_avatar_traits(&pack, &key)
        .expect("traits selected")
        .iter()
        .map(|(layer, t)| (layer.layer_id.clone(), t.trait_id.clone()))
        .collect();
    let again: Vec<(String, String)> = select_avatar_traits(&pack, &key)
        .expect("traits selected")
        .iter()
        .map(|(layer, t)| (layer.layer_id.clone(), t.trait_id.clone()))
        .collect();
    assert_eq!(selected, again);
    let expected: Vec<(String, String)> = [
        ("background", "confetti"),
        ("body", "coral"),
        ("neck", "flower-collar"),
        ("eyewear", "hearts"),
        ("headwear", "mushroom"),
    ]
    .iter()
    .map(|(l, t)| (l.to_string(), t.to_string()))
    .collect();
    assert_eq!(selected, expected);
}

#[test]
fn layered_avatar_is_composed_once_as_a_stable_rgba_png() {
    let pack = load_avatar_pack(DEFAULT_AVATAR_PACK, None).expect("bundled pack loads");
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path();
    let key = "a".repeat(64);
    let first = compose_avatar(&pack, &key, Some(output)).expect("first composition");
    let second = compose_avatar(&pack, &key, Some(output)).expect("second composition");

    assert_eq!(first, second);
    assert!(first.path.is_file());
    assert_eq!(first.path.extension().and_then(|e| e.to_str()), Some("png"));
    let bytes = std::fs::read(&first.path).unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    assert_eq!(first.traits.len(), 5);
}

#[test]
fn legacy_complete_image_pack_selection_remains_supported() {
    let pack = load_avatar_pack("bees-v1", None).expect("legacy pack loads");
    assert!(!pack.layered());
    assert_eq!(pack.assets.len(), 24);
    let key = "a".repeat(64);
    let selected = select_avatar(&pack, &key, &HashSet::new()).expect("selection");
    assert_eq!(
        selected,
        select_avatar(&pack, &key, &HashSet::new()).expect("selection")
    );

    let mut assigned: HashSet<String> = HashSet::new();
    for number in 0..24u64 {
        let public_key = format!("{number:064x}");
        let avatar = select_avatar(&pack, &public_key, &assigned).expect("selection");
        assigned.insert(avatar.asset_id);
    }
    assert_eq!(assigned.len(), 24);
}

#[test]
fn custom_pack_checks_asset_integrity() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let asset = root.join("bee.webp");
    std::fs::write(&asset, b"test-image").unwrap();
    let manifest = serde_json::json!({
        "id": "custom-bees",
        "assets": [{
            "id": "bee-01",
            "collection": "test",
            "file": "bee.webp",
            "sha256": sha256_hex(b"test-image"),
        }],
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();

    let pack = load_avatar_pack("ignored", Some(root)).expect("custom pack loads");
    assert_eq!(pack.assets[0].path, asset);

    std::fs::write(&asset, b"tampered").unwrap();
    assert!(load_avatar_pack("ignored", Some(root)).is_err());
}

#[test]
fn pack_files_cannot_escape_the_pack_directory() {
    let container = tempfile::tempdir().unwrap();
    let root = container.path().join("pack");
    std::fs::create_dir(&root).unwrap();
    let outside = container.path().join("outside.webp");
    std::fs::write(&outside, b"image").unwrap();

    let manifest = serde_json::json!({
        "id": "unsafe",
        "assets": [{
            "id": "escape",
            "collection": "test",
            "file": "../outside.webp",
            "sha256": sha256_hex(b"image"),
        }],
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();

    assert!(load_avatar_pack("ignored", Some(Path::new(&root))).is_err());
}

#[test]
#[cfg(unix)]
fn pack_files_cannot_escape_through_symlinks() {
    let container = tempfile::tempdir().unwrap();
    let root = container.path().join("pack");
    std::fs::create_dir(&root).unwrap();
    let outside = container.path().join("outside.webp");
    std::fs::write(&outside, b"image").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link.webp")).unwrap();

    let manifest = serde_json::json!({
        "id": "unsafe-link",
        "assets": [{
            "id": "escape",
            "collection": "test",
            "file": "link.webp",
            "sha256": sha256_hex(b"image"),
        }],
    });
    std::fs::write(
        root.join("manifest.json"),
        serde_json::to_string(&manifest).unwrap(),
    )
    .unwrap();

    let result = load_avatar_pack("ignored", Some(Path::new(&root)));
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("escapes its pack directory"));
}
