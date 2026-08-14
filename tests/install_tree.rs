//! Relocated-install-tree test: the compiled binary must resolve the plugin
//! root from its own location, with no build-time path baked in.

use std::path::Path;

#[cfg(unix)]
#[test]
fn relocated_install_tree_resolves_plugin_root_from_executable() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let tree = tempfile::tempdir().unwrap();
    let root = tree.path();

    // Assemble a minimal installed plugin tree elsewhere on disk.
    std::fs::copy(
        source_root.join("herdr-plugin.toml"),
        root.join("herdr-plugin.toml"),
    )
    .unwrap();
    std::fs::copy(
        source_root.join("config.example.toml"),
        root.join("config.example.toml"),
    )
    .unwrap();
    let bin = root.join("bin");
    std::fs::create_dir(&bin).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_buzzr"), bin.join("buzzr-bin")).unwrap();

    // No HERDR_PLUGIN_ROOT, no config-dir override: the binary must find the
    // tree through its own location.
    let output = std::process::Command::new(bin.join("buzzr-bin"))
        .arg("init-config")
        .env_remove("HERDR_PLUGIN_ROOT")
        .env_remove("HERDR_PLUGIN_CONFIG_DIR")
        .env_remove("BUZZR_STATE_DIR")
        .env_remove("HERDR_BUZZ_STATE_DIR")
        .env_remove("HERDR_PLUGIN_STATE_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "init-config failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let created = root.join("config.toml");
    assert!(created.is_file(), "config.toml not created in the tree");
    let expected = std::fs::read(source_root.join("config.example.toml")).unwrap();
    assert_eq!(std::fs::read(&created).unwrap(), expected);

    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        created.metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
}
