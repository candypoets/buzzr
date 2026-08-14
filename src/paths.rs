//! Plugin root resolution for installed and development layouts.
//!
//! Resolution order (first hit wins):
//!
//! 1. `HERDR_PLUGIN_ROOT` — set by Herdr for installed plugins.
//! 2. The first ancestor of the running executable that contains the
//!    `herdr-plugin.toml` marker. This covers the installed layout
//!    (`<root>/bin/buzzr-bin`) and cargo build locations
//!    (`<repo>/target/{debug,release,debug/deps}/...`) alike.
//! 3. The first ancestor of the process working directory with the marker
//!    (running from inside a checkout or tree).
//! 4. The process working directory, as a deterministic last resort.
//!
//! No build-time paths are baked into the binary.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Marker file every buzzr plugin tree carries.
const PLUGIN_MARKER: &str = "herdr-plugin.toml";

fn marked_ancestor(start: &Path) -> Option<PathBuf> {
    start
        .ancestors()
        .find(|ancestor| ancestor.join(PLUGIN_MARKER).is_file())
        .map(Path::to_path_buf)
}

/// Pure resolution, injectable for tests. Returns `None` when no marker is
/// found anywhere.
pub(crate) fn resolve_plugin_root(
    env_root: Option<&OsStr>,
    executable: Option<&Path>,
    current_dir: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(root) = env_root.filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(root));
    }
    if let Some(exe) = executable {
        if let Some(root) = exe.parent().and_then(marked_ancestor) {
            return Some(root);
        }
    }
    if let Some(dir) = current_dir {
        if let Some(root) = marked_ancestor(dir) {
            return Some(root);
        }
    }
    None
}

/// The plugin root for this process.
pub fn plugin_root() -> PathBuf {
    let current_dir = std::env::current_dir().ok();
    resolve_plugin_root(
        std::env::var_os("HERDR_PLUGIN_ROOT").as_deref(),
        std::env::current_exe().ok().as_deref(),
        current_dir.as_deref(),
    )
    .or(current_dir)
    .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_with_marker() -> tempfile::TempDir {
        let tree = tempfile::tempdir().unwrap();
        std::fs::write(tree.path().join(PLUGIN_MARKER), "").unwrap();
        tree
    }

    #[test]
    fn env_root_wins() {
        let root = resolve_plugin_root(Some(OsStr::new("/installed/buzzr")), None, None);
        assert_eq!(root, Some(PathBuf::from("/installed/buzzr")));
    }

    #[test]
    fn installed_layout_walks_executable_ancestors() {
        let tree = tree_with_marker();
        let bin = tree.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let exe = bin.join("buzzr-bin");
        let root = resolve_plugin_root(None, Some(&exe), None);
        assert_eq!(root, Some(tree.path().to_path_buf()));
    }

    #[test]
    fn cargo_target_layouts_walk_executable_ancestors() {
        let tree = tree_with_marker();
        for exe in [
            tree.path().join("target/debug/buzzr"),
            tree.path().join("target/release/buzzr"),
            tree.path().join("target/debug/deps/buzzr-0123456789abcdef"),
        ] {
            let root = resolve_plugin_root(None, Some(&exe), None);
            assert_eq!(
                root,
                Some(tree.path().to_path_buf()),
                "exe: {}",
                exe.display()
            );
        }
    }

    #[test]
    fn working_directory_ancestors_are_the_next_fallback() {
        let tree = tree_with_marker();
        let nested = tree.path().join("deep/nested/dir");
        std::fs::create_dir_all(&nested).unwrap();
        let exe = Path::new("/unrelated/location/buzzr");
        let root = resolve_plugin_root(None, Some(exe), Some(&nested));
        assert_eq!(root, Some(tree.path().to_path_buf()));
    }

    #[test]
    fn no_marker_anywhere_resolves_to_none() {
        let tree = tempfile::tempdir().unwrap();
        let exe = tree.path().join("bin/buzzr-bin");
        let cwd = tree.path().join("elsewhere");
        assert_eq!(resolve_plugin_root(None, Some(&exe), Some(&cwd)), None);
    }
}
