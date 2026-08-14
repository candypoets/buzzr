//! Provisioning integration tests: key generation/persistence, relay
//! membership and ownership commands, idempotence, and failures — all against
//! a fake `docker` executable, no Docker or network.

use std::path::{Path, PathBuf};

use buzzr::clients::LocalBuzzAdmin;
use buzzr::config::load_config;
use buzzr::provisioning::{
    ensure_bridge_identity, provision_local_with_admin, provision_local_with_admin_and_store,
    resolve_identity_intents,
};
use buzzr::state::{default_state, StateStore};
use serde_json::{json, Value};

const HUMAN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    config_path: PathBuf,
    admin: LocalBuzzAdmin,
    calls_log: PathBuf,
    members_file: PathBuf,
    owners_file: PathBuf,
}

fn write_fake_docker(dir: &Path) -> PathBuf {
    let script = dir.join("fake-docker");
    let body = r#"#!/usr/bin/env bash
set -euo pipefail
FIXTURE_DIR="$1"
shift
printf '%s\n' "$*" >> "$FIXTURE_DIR/calls.log"
if [ -f "$FIXTURE_DIR/fail" ]; then
    echo "fake docker exploded" >&2
    exit 1
fi
# Shift past: compose -f FILE exec -T SERVICE
service="${6}"
shift 6 || true
case "$service" in
    relay)
        if [ "${1:-}" = "buzz-admin" ] && [ "${2:-}" = "list-members" ]; then
            cat "$FIXTURE_DIR/members.txt" 2>/dev/null || true
        elif [ "${1:-}" = "buzz-admin" ] && [ "${2:-}" = "add-member" ]; then
            pubkey=""
            while [ $# -gt 0 ]; do
                if [ "$1" = "--pubkey" ]; then pubkey="$2"; shift 2; else shift; fi
            done
            echo "$pubkey" >> "$FIXTURE_DIR/members.txt"
        else
            echo "unexpected relay command: $*" >&2
            exit 1
        fi
        ;;
    postgres)
        sql="${*: -1}"
        case "$sql" in
            *"INSERT INTO users"*)
                if [ -f "$FIXTURE_DIR/fail-ownership" ]; then
                    echo "fake ownership failure" >&2
                    exit 1
                fi
                agent=$(printf '%s' "$sql" | grep -oE "decode\('[0-9a-f]{64}'" | sed -n 1p | grep -oE "[0-9a-f]{64}")
                human=$(printf '%s' "$sql" | grep -oE "decode\('[0-9a-f]{64}'" | sed -n 2p | grep -oE "[0-9a-f]{64}")
                owner=""
                if [ -f "$FIXTURE_DIR/owners.txt" ]; then
                    owner=$(grep "^$agent " "$FIXTURE_DIR/owners.txt" | cut -d' ' -f2 || true)
                fi
                if [ -n "$owner" ] && [ "$owner" != "$human" ]; then
                    echo "$owner"
                else
                    grep -v "^$agent " "$FIXTURE_DIR/owners.txt" 2>/dev/null > "$FIXTURE_DIR/owners.tmp" || true
                    echo "$agent $human" >> "$FIXTURE_DIR/owners.tmp"
                    mv "$FIXTURE_DIR/owners.tmp" "$FIXTURE_DIR/owners.txt"
                    echo "$human"
                fi
                ;;
            *"community_id"*)
                echo "11111111-2222-3333-4444-555555555555"
                ;;
            *)
                echo "unexpected sql: $sql" >&2
                exit 1
                ;;
        esac
        ;;
    *)
        echo "unexpected service: $service" >&2
        exit 1
        ;;
esac
"#;
    std::fs::write(&script, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    script
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let fixture_dir = root.join("fixture");
    std::fs::create_dir(&fixture_dir).unwrap();
    let fake_docker = write_fake_docker(&fixture_dir);

    // The fake needs its fixture dir; wrap the binary to inject it.
    let wrapper = fixture_dir.join("docker");
    std::fs::write(
        &wrapper,
        format!(
            "#!/usr/bin/env bash\nexec {} {} \"$@\"\n",
            fake_docker.display(),
            fixture_dir.display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    std::fs::write(root.join("docker-compose.yml"), "services: {}\n").unwrap();
    let secrets = root.join("secrets.env");
    std::fs::write(&secrets, "").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let config_path = root.join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            "[bridge]\nhuman_pubkey = \"{HUMAN}\"\ncompose_file = \"{}\"\n\
             bridge_private_key_env = \"BUZZR_BRIDGE_PRIVATE_KEY\"\n\
             managed_secrets_file = \"secrets.env\"\nsecrets_files = [\"secrets.env\"]\n",
            root.join("docker-compose.yml").display()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let mut admin = LocalBuzzAdmin::new(root.join("docker-compose.yml"));
    admin.docker_binary = wrapper.display().to_string();

    Fixture {
        root: root.clone(),
        config_path,
        admin,
        calls_log: fixture_dir.join("calls.log"),
        members_file: fixture_dir.join("members.txt"),
        owners_file: fixture_dir.join("owners.txt"),
        _dir: dir,
    }
}

fn snapshot() -> Value {
    json!({
        "workspaces": [
            {"workspace_id": "w1", "label": "Alpha", "number": 1},
        ],
        "tabs": [
            {"tab_id": "w1:t1", "label": "sol"},
        ],
        "agents": [
            {
                "workspace_id": "w1",
                "tab_id": "w1:t1",
                "name": "sol",
                "agent": "codex",
                "pane_id": "w1:p1",
                "terminal_id": "term-1",
                "agent_status": "idle",
            },
        ],
    })
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn provision_generates_persists_and_is_idempotent() {
    let fx = fixture();
    let store = StateStore::new(fx.root.join("state"));
    let (config, _topology, report) =
        provision_local_with_admin_and_store(&fx.config_path, &snapshot(), &fx.admin, &store)
            .expect("first provisioning run");

    // Key generation + persistence.
    assert!(report.bridge_created);
    assert_eq!(report.identities_created, vec!["sol".to_string()]);
    assert_eq!(report.relay_members_added, 2);
    assert_eq!(report.relay_member_pubkeys_added.len(), 2);
    assert_eq!(report.ownership_bound, 2);

    let secrets = read(&fx.root.join("secrets.env"));
    assert!(secrets.contains("BUZZR_BRIDGE_PRIVATE_KEY="));
    assert!(secrets.contains("BUZZR_AGENT_SOL_PRIVATE_KEY="));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fx
            .root
            .join("secrets.env")
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secrets.env must stay private");
    }

    let config_text = read(&fx.config_path);
    assert!(config_text.contains("bridge_public_key"));
    assert!(config_text.contains("[identities.sol]"));
    let sol = config.identities.get("sol").expect("sol identity");
    assert!(sol.public_key.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(sol.public_key.len(), 64);
    let bridge_key = config.bridge.bridge_public_key.clone().unwrap();

    let state = store.load().unwrap();
    assert_eq!(
        state["managed_resources"]["identities"][&bridge_key]["origin"],
        json!("generated")
    );
    assert_eq!(
        state["managed_resources"]["identities"][&bridge_key]["identity_kind"],
        json!("bridge")
    );
    assert_eq!(
        state["managed_resources"]["identities"][&sol.public_key]["identity_id"],
        json!("sol")
    );
    assert_eq!(
        state["managed_resources"]["identities"][&sol.public_key]["identity_kind"],
        json!("agent")
    );
    assert_eq!(
        state["managed_resources"]["relay_members"][&sol.public_key]["origin"],
        json!("added")
    );

    // Membership and ownership commands hit the fake relay/admin.
    let calls = read(&fx.calls_log);
    assert!(calls.contains(&format!(
        "buzz-admin add-member --pubkey {bridge_key} --role member"
    )));
    assert!(calls.contains(&format!(
        "buzz-admin add-member --pubkey {} --role member",
        sol.public_key
    )));
    assert!(calls.contains("INSERT INTO users"));

    let members = read(&fx.members_file);
    assert!(members.contains(&bridge_key));
    assert!(members.contains(&sol.public_key));

    // Idempotence: a second run changes nothing.
    let (_config2, _topology2, report2) =
        provision_local_with_admin_and_store(&fx.config_path, &snapshot(), &fx.admin, &store)
            .expect("second provisioning run");
    assert!(!report2.bridge_created);
    assert!(report2.identities_created.is_empty());
    assert_eq!(report2.relay_members_added, 0);
    assert_eq!(read(&fx.root.join("secrets.env")), secrets);
    assert_eq!(read(&fx.config_path), config_text);
}

#[test]
fn provenance_survives_failure_after_remote_membership_changes() {
    let fx = fixture();
    let store = StateStore::new(fx.root.join("state"));
    let fail_ownership = fx.calls_log.parent().unwrap().join("fail-ownership");
    std::fs::write(&fail_ownership, "1\n").unwrap();

    let error =
        provision_local_with_admin_and_store(&fx.config_path, &snapshot(), &fx.admin, &store)
            .unwrap_err();
    assert!(error.to_string().contains("fake ownership failure"));

    let failed_state = store.load_strict().unwrap();
    let identities = failed_state["managed_resources"]["identities"]
        .as_object()
        .unwrap();
    assert_eq!(identities.len(), 2);
    assert_eq!(
        failed_state["managed_resources"]["relay_members"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    assert!(!failed_state["managed_resources"]["ownerships"]
        .as_object()
        .unwrap()
        .is_empty());

    std::fs::remove_file(fail_ownership).unwrap();
    provision_local_with_admin_and_store(&fx.config_path, &snapshot(), &fx.admin, &store)
        .expect("retry completes from checkpointed provenance");
    let recovered = store.load_strict().unwrap();
    assert_eq!(
        recovered["managed_resources"]["ownerships"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn generated_identity_is_recovered_from_write_ahead_intent() {
    let fx = fixture();
    let (config, created) =
        ensure_bridge_identity(&fx.config_path, &load_config(&fx.config_path).unwrap()).unwrap();
    assert!(created);
    let pubkey = config.bridge.bridge_public_key.clone().unwrap();
    let mut state = default_state();
    state["managed_resources"]["identity_intents"]["bridge:bridge"] = json!({
        "identity_kind": "bridge",
        "identity_id": "bridge",
        "private_key_env": "BUZZR_BRIDGE_PRIVATE_KEY",
        "expected_pubkey": pubkey.clone(),
    });

    assert!(resolve_identity_intents(&config, &mut state));
    assert_eq!(
        state["managed_resources"]["identities"][&pubkey]["origin"],
        json!("generated")
    );
    assert_eq!(state["managed_resources"]["identity_intents"], json!({}));
}

#[test]
fn identity_intent_does_not_claim_a_different_valid_import() {
    let fx = fixture();
    let (config, created) =
        ensure_bridge_identity(&fx.config_path, &load_config(&fx.config_path).unwrap()).unwrap();
    assert!(created);
    let actual_pubkey = config.bridge.bridge_public_key.clone().unwrap();
    let mut state = default_state();
    state["managed_resources"]["identity_intents"]["bridge:bridge"] = json!({
        "identity_kind": "bridge",
        "identity_id": "bridge",
        "private_key_env": "BUZZR_BRIDGE_PRIVATE_KEY",
        "expected_pubkey": "a".repeat(64),
    });

    assert!(!resolve_identity_intents(&config, &mut state));
    assert!(state["managed_resources"]["identities"]
        .get(&actual_pubkey)
        .is_none());
    assert!(state["managed_resources"]["identity_intents"]
        .get("bridge:bridge")
        .is_some());
}

#[test]
fn provision_refuses_a_mismatched_bridge_public_key() {
    let fx = fixture();
    // Pre-seed a bridge keypair, then corrupt the configured public key.
    let config = load_config(&fx.config_path).unwrap();
    let (_config, created) = ensure_bridge_identity(&fx.config_path, &config).unwrap();
    assert!(created);
    let wrong = "d".repeat(64);
    buzzr::config::update_bridge_settings(
        &fx.config_path,
        &[("bridge_public_key".to_string(), Some(json!(wrong)))],
    )
    .unwrap();
    let corrupted = load_config(&fx.config_path).unwrap();
    let error = ensure_bridge_identity(&fx.config_path, &corrupted).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("bridge_public_key does not match"),
        "unexpected error: {error}"
    );
}

#[test]
fn provision_surfaces_admin_command_failures() {
    let fx = fixture();
    std::fs::write(fx.calls_log.parent().unwrap().join("fail"), "").unwrap();
    let error =
        provision_local_with_admin(&fx.config_path, &snapshot(), Some(&fx.admin)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("local Buzz admin command failed"),
        "unexpected error: {error}"
    );
}

#[test]
fn provision_refuses_to_steal_another_owners_agent() {
    let fx = fixture();
    let (config, _topology, report) =
        provision_local_with_admin(&fx.config_path, &snapshot(), Some(&fx.admin))
            .expect("first provisioning run");
    assert_eq!(report.ownership_bound, 2);

    // The relay database now claims the sol identity belongs to someone else.
    let sol_key = &config.identities["sol"].public_key;
    let other_owner = "e".repeat(64);
    let rewritten: Vec<String> = read(&fx.owners_file)
        .lines()
        .map(|line| {
            if line.starts_with(sol_key) {
                format!("{sol_key} {other_owner}")
            } else {
                line.to_string()
            }
        })
        .collect();
    std::fs::write(&fx.owners_file, rewritten.join("\n") + "\n").unwrap();

    let error =
        provision_local_with_admin(&fx.config_path, &snapshot(), Some(&fx.admin)).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("already owned by another pubkey"),
        "unexpected error: {error}"
    );
}
