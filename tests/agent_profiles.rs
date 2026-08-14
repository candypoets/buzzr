//! Agent declaration and profile synchronization tests.
//!
//! External effects are replaced through `ProfilePublisher`, the uploader
//! factory, and the `ProfileSyncDeps` pack-loader closure.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use buzzr::agent_profiles::build_agent_profile_declarations;
use buzzr::avatars::{load_avatar_pack, AvatarAsset, AvatarPack, AvatarPackError};
use buzzr::clients::{CommandError, FileUploader, ProfilePublisher};
use buzzr::config::{BridgeConfig, Config, IdentityConfig};
use buzzr::sync::{
    sync_agent_profiles, sync_identity_profiles, ProfileSyncDeps, SyncReport,
    IDENTITY_PROFILE_REFRESH_SECONDS,
};
use buzzr::topology::{AgentBinding, SpaceBinding, Topology};
use serde_json::{json, Value};

fn human() -> String {
    "c".repeat(64)
}

fn sol_public() -> String {
    "a".repeat(64)
}

fn k3_public() -> String {
    "b".repeat(64)
}

fn sol_private() -> String {
    "1".repeat(64)
}

fn identity_config(respond_to: &str) -> Config {
    let mut identities = HashMap::new();
    identities.insert(
        "sol".to_string(),
        IdentityConfig {
            identity_id: "sol".to_string(),
            display_name: "Sol".to_string(),
            aliases: vec!["sol".to_string()],
            public_key: sol_public(),
            private_key_env: "SOL_KEY".to_string(),
            auth_tag_env: None,
        },
    );
    identities.insert(
        "k3".to_string(),
        IdentityConfig {
            identity_id: "k3".to_string(),
            display_name: "K3".to_string(),
            aliases: vec!["k3".to_string()],
            public_key: k3_public(),
            private_key_env: "K3_KEY".to_string(),
            auth_tag_env: None,
        },
    );
    Config {
        bridge: BridgeConfig {
            human_pubkey: Some(human()),
            respond_to: respond_to.to_string(),
            respond_to_allowlist: vec!["d".repeat(64)],
            ..BridgeConfig::default()
        },
        identities,
        secrets: HashMap::from([("SOL_KEY".to_string(), sol_private())]),
    }
}

/// `config.identities = {"sol": config.identities["sol"]}`.
fn sol_only(mut config: Config) -> Config {
    let sol = config.identities["sol"].clone();
    config.identities = HashMap::from([("sol".to_string(), sol)]);
    config
}

fn sol_binding(workspace_id: &str, channel_name: &str, pane_id: &str) -> AgentBinding {
    AgentBinding {
        workspace_id: workspace_id.to_string(),
        workspace_label: channel_name.to_string(),
        channel_name: channel_name.to_string(),
        pane_id: pane_id.to_string(),
        terminal_id: format!("term-{pane_id}"),
        tab_id: format!("{workspace_id}:t1"),
        tab_label: "sol".to_string(),
        runtime: "codex".to_string(),
        status: "idle".to_string(),
        agent_name: Some("sol".to_string()),
        display_label: "sol".to_string(),
        identity_id: Some("sol".to_string()),
        public_key: Some(sol_public()),
    }
}

fn report() -> SyncReport {
    SyncReport::new(true)
}

/// Records `publish_profile` (name, about, picture) and `publish_agent_profile`
/// (content) calls.
#[derive(Default)]
struct RecordingPublisher {
    profiles: RefCell<Vec<(String, String, Option<String>)>>,
    agent_profiles: RefCell<Vec<Value>>,
}

impl ProfilePublisher for RecordingPublisher {
    fn publish_profile(
        &self,
        _relay_url: &str,
        _private_key: &str,
        name: &str,
        about: &str,
        picture: Option<&str>,
    ) -> Result<(), CommandError> {
        self.profiles.borrow_mut().push((
            name.to_string(),
            about.to_string(),
            picture.map(str::to_string),
        ));
        Ok(())
    }

    fn publish_agent_profile(
        &self,
        _relay_url: &str,
        _private_key: &str,
        content: &Value,
    ) -> Result<(), CommandError> {
        self.agent_profiles.borrow_mut().push(content.clone());
        Ok(())
    }
}

/// Records uploaded paths and answers with a fixed descriptor. Instances built
/// by the factory share one call log.
#[derive(Clone)]
struct RecordingUploader {
    uploads: Rc<RefCell<Vec<PathBuf>>>,
    result: Value,
}

impl FileUploader for RecordingUploader {
    fn upload_file(&self, path: &Path) -> Result<Value, CommandError> {
        self.uploads.borrow_mut().push(path.to_path_buf());
        Ok(self.result.clone())
    }
}

#[allow(clippy::type_complexity)] // the shared log plus its factory closure
fn uploader_factory(
    result: Value,
) -> (
    Rc<RefCell<Vec<PathBuf>>>,
    impl Fn(&str, Option<&str>) -> RecordingUploader,
) {
    let uploads: Rc<RefCell<Vec<PathBuf>>> = Rc::new(RefCell::new(Vec::new()));
    let factory = {
        let uploads = uploads.clone();
        move |_private_key: &str, _auth_tag: Option<&str>| RecordingUploader {
            uploads: uploads.clone(),
            result: result.clone(),
        }
    };
    (uploads, factory)
}

// --- AgentProfileDeclarationTests ---

#[test]
fn channels_are_aggregated_and_owner_gate_becomes_human_allowlist() {
    let topology = Topology {
        spaces: vec![
            SpaceBinding {
                workspace_id: "w1".to_string(),
                workspace_label: "Alpha".to_string(),
                channel_name: "alpha".to_string(),
                number: 1,
                agents: vec![sol_binding("w1", "alpha", "w1:p1")],
            },
            SpaceBinding {
                workspace_id: "w2".to_string(),
                workspace_label: "Beta".to_string(),
                channel_name: "beta".to_string(),
                number: 2,
                agents: vec![sol_binding("w2", "beta", "w2:p1")],
            },
        ],
        warnings: Vec::new(),
    };
    let channel_state = json!({
        "w1": {
            "channel_id": "11111111-1111-1111-1111-111111111111",
            "name": "alpha",
        },
        "w2": {
            "channel_id": "22222222-2222-2222-2222-222222222222",
            "name": "beta",
        },
    });
    let declarations =
        build_agent_profile_declarations(&identity_config("owner-only"), &topology, &channel_state);
    let by_identity: HashMap<&str, &buzzr::agent_profiles::AgentProfileDeclaration> = declarations
        .iter()
        .map(|declaration| (declaration.identity_id.as_str(), declaration))
        .collect();

    let sol = &by_identity["sol"].content;
    assert_eq!(sol["channels"], json!(["alpha", "beta"]));
    assert_eq!(
        sol["channel_ids"],
        json!([
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        ])
    );
    assert_eq!(sol["respond_to"], json!("allowlist"));
    assert_eq!(sol["respond_to_allowlist"], json!([human()]));
    assert_eq!(sol["status"], json!("online"));
    assert_eq!(sol["agent_type"], json!("codex"));

    let k3 = &by_identity["k3"].content;
    assert_eq!(k3["channel_ids"], json!([]));
    assert_eq!(k3["status"], json!("offline"));
}

#[test]
fn explicit_allowlist_includes_the_human_like_runtime_routing() {
    let declarations = build_agent_profile_declarations(
        &identity_config("allowlist"),
        &Topology::default(),
        &json!({}),
    );
    assert_eq!(
        declarations[0].content["respond_to_allowlist"],
        json!([human(), "d".repeat(64)])
    );
}

#[test]
fn nobody_is_a_valid_empty_allowlist_for_desktop() {
    let declarations = build_agent_profile_declarations(
        &identity_config("nobody"),
        &Topology::default(),
        &json!({}),
    );
    assert_eq!(declarations[0].content["respond_to"], json!("allowlist"));
    assert_eq!(declarations[0].content["respond_to_allowlist"], json!([]));
}

// --- sync tests from AgentProfilePublishingTests ---

#[test]
fn sync_publishes_changed_content_once_and_caches_it() {
    let config = sol_only(identity_config("owner-only"));
    let topology = Topology {
        spaces: vec![SpaceBinding {
            workspace_id: "w1".to_string(),
            workspace_label: "Alpha".to_string(),
            channel_name: "alpha".to_string(),
            number: 1,
            agents: vec![sol_binding("w1", "alpha", "w1:p1")],
        }],
        warnings: Vec::new(),
    };
    let mut state = json!({
        "channels": {
            "w1": {
                "channel_id": "11111111-1111-1111-1111-111111111111",
                "name": "alpha",
            }
        },
        "agent_profiles": {},
    });
    let publisher = RecordingPublisher::default();
    sync_agent_profiles(
        &config,
        &topology,
        &mut state,
        &mut report(),
        true,
        1_000,
        &publisher,
    );
    sync_agent_profiles(
        &config,
        &topology,
        &mut state,
        &mut report(),
        true,
        1_001,
        &publisher,
    );

    assert_eq!(publisher.agent_profiles.borrow().len(), 1);
    assert!(state["agent_profiles"].get("sol").is_some());
    assert_eq!(
        state["agent_profiles"]["sol"]["channel_ids"],
        json!(["11111111-1111-1111-1111-111111111111"])
    );
}

#[test]
fn identity_profile_uploads_recraft_avatar_once_and_reuses_its_url() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bee.webp");
    std::fs::write(&path, b"bee").unwrap();
    let pack = AvatarPack {
        pack_id: "test-bees".to_string(),
        root: path.parent().unwrap().to_path_buf(),
        assets: vec![AvatarAsset {
            asset_id: "bee-01".to_string(),
            collection: "test".to_string(),
            path: path.clone(),
            sha256: "e".repeat(64),
            traits: Vec::new(),
        }],
        ..AvatarPack::default()
    };
    let config = sol_only(identity_config("owner-only"));
    let mut state = json!({"identity_profiles": {}, "avatar_uploads": {}});
    let (uploads, make_uploader) =
        uploader_factory(json!({"url": "https://relay.example/media/bee"}));
    let publisher = RecordingPublisher::default();
    let deps = ProfileSyncDeps {
        publisher: &publisher,
        load_pack: move |_pack_id: &str, _path: Option<&Path>| {
            Ok::<AvatarPack, AvatarPackError>(pack.clone())
        },
        make_uploader,
    };
    sync_identity_profiles(&config, &mut state, &mut report(), true, 1_000, None, &deps);
    sync_identity_profiles(
        &config,
        &mut state,
        &mut report(),
        true,
        1_000 + IDENTITY_PROFILE_REFRESH_SECONDS,
        None,
        &deps,
    );

    assert_eq!(*uploads.borrow(), vec![path]);
    assert_eq!(publisher.profiles.borrow().len(), 2);
    assert_eq!(
        publisher.profiles.borrow().last().unwrap().2.as_deref(),
        Some("https://relay.example/media/bee")
    );
    assert_eq!(
        state["identity_profiles"]["sol"]["avatar_id"],
        json!("bee-01")
    );
}

#[test]
fn identity_profile_composes_layer_traits_from_the_pubkey() {
    let directory = tempfile::tempdir().unwrap();
    let config = sol_only(identity_config("owner-only"));
    let mut state = json!({"identity_profiles": {}, "avatar_uploads": {}});
    let (uploads, make_uploader) =
        uploader_factory(json!({"url": "https://relay.example/media/composed-bee"}));
    let publisher = RecordingPublisher::default();
    let deps = ProfileSyncDeps {
        publisher: &publisher,
        load_pack: load_avatar_pack,
        make_uploader,
    };
    sync_identity_profiles(
        &config,
        &mut state,
        &mut report(),
        true,
        1_000,
        Some(directory.path()),
        &deps,
    );

    let uploads = uploads.borrow();
    assert_eq!(uploads.len(), 1);
    let uploaded_path = &uploads[0];
    assert!(uploaded_path.is_file());
    assert_eq!(
        uploaded_path.extension().and_then(|ext| ext.to_str()),
        Some("png")
    );
    let traits = state["identity_profiles"]["sol"]["avatar_traits"]
        .as_object()
        .expect("avatar_traits is an object");
    let trait_names: HashSet<&str> = traits.keys().map(String::as_str).collect();
    assert_eq!(
        trait_names,
        HashSet::from(["background", "body", "neck", "eyewear", "headwear"])
    );
    assert_eq!(
        publisher.profiles.borrow().last().unwrap().2.as_deref(),
        Some("https://relay.example/media/composed-bee")
    );
}

#[test]
fn identity_profile_can_disable_avatars() {
    let mut config = sol_only(identity_config("owner-only"));
    config.bridge = BridgeConfig {
        human_pubkey: Some(human()),
        avatars_enabled: false,
        ..BridgeConfig::default()
    };
    let mut state = json!({"identity_profiles": {}, "avatar_uploads": {}});
    let uploader_builds: Rc<RefCell<usize>> = Rc::new(RefCell::new(0));
    let make_uploader = {
        let uploader_builds = uploader_builds.clone();
        move |_private_key: &str, _auth_tag: Option<&str>| {
            *uploader_builds.borrow_mut() += 1;
            RecordingUploader {
                uploads: Rc::new(RefCell::new(Vec::new())),
                result: json!({}),
            }
        }
    };
    let publisher = RecordingPublisher::default();
    let deps = ProfileSyncDeps {
        publisher: &publisher,
        load_pack: |_pack_id: &str, _path: Option<&Path>| {
            unreachable!("avatars are disabled, the pack is never loaded")
        },
        make_uploader,
    };
    sync_identity_profiles(&config, &mut state, &mut report(), true, 1_000, None, &deps);

    assert_eq!(*uploader_builds.borrow(), 0);
    assert_eq!(publisher.profiles.borrow().last().unwrap().2, None);
}
