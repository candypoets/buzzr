//! Persistent roles with fake transport/launcher: no native agents or relay writes.
#![cfg(unix)]
use buzzr::{
    config::{BridgeConfig, Config, IdentityConfig},
    roles::{self, PersistentRole},
    service::BridgeService,
    state::{default_state, StateStore},
    topology::build_topology,
};
use serde_json::{json, Value};
use std::{collections::HashMap, fs, os::unix::fs::PermissionsExt};

fn executable(path: &std::path::Path, body: &str) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
struct Fixture {
    dir: tempfile::TempDir,
    service: BridgeService,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let launcher = root.join("launcher");
        executable(
            &launcher,
            &format!(
                r#"#!/usr/bin/env python3
import json,sys,pathlib,os
p=pathlib.Path({root:?})
r=json.load(sys.stdin)
assert not any(k.startswith(('BUZZ','NOSTR','PAPERCLIP')) for k in os.environ)
with (p/'calls').open('a') as f: f.write(json.dumps(r)+'\n')
mode=(p/'mode').read_text()
if mode=='failure': sys.exit(2)
if r['op']=='ensure': answer={{'state':'ready','session':{{'pane_id':'w1:p1','terminal_id':'term','kind':'codex'}}}} if mode in ('deliver','uncertain') else {{'state':mode,'reason':'quota' if mode=='blocked' else 'busy'}}
elif r['op']=='resolve': answer={{'state':'queued' if r['disposition']=='retry' else 'delivered'}}
else: answer={{'state':'uncertain' if mode=='uncertain' else 'delivered'}}
print(json.dumps({{'version':1,**answer}}))
"#,
                root = root.to_str().unwrap()
            ),
        );
        let buzz = root.join("buzz");
        executable(
            &buzz,
            &format!(
                r#"#!/usr/bin/env python3
import json,sys,pathlib
p=pathlib.Path({root:?})
if sys.argv[1:3]==['messages','get']: print((p/'events').read_text())
else:
 with (p/'notices').open('a') as f: f.write(json.dumps([sys.argv[1:],sys.stdin.read()])+'\n')
 print('{{}}')
"#,
                root = root.to_str().unwrap()
            ),
        );
        let role = PersistentRole {
            project: "dev".into(),
            role: "studio-lead".into(),
            channel_id: "channel-dev".into(),
            channel_name: "dev".into(),
            launcher: vec![launcher.to_str().unwrap().into()],
            since: Some(1),
            tasks: None,
            additional_task_repositories: vec![],
            default_for_channel: false,
        };
        let config = Config {
            bridge: BridgeConfig {
                persistent_roles: [("dev-lead".into(), role)].into(),
                buzz_bin: buzz.to_str().unwrap().into(),
                human_pubkey: Some("a".repeat(64)),
                respond_to: "owner-only".into(),
                ..Default::default()
            },
            identities: [(
                "dev-lead".into(),
                IdentityConfig {
                    identity_id: "dev-lead".into(),
                    display_name: "Dev Lead".into(),
                    aliases: vec![],
                    public_key: "b".repeat(64),
                    private_key_env: "TEST_ROLE_KEY".into(),
                    auth_tag_env: None,
                },
            )]
            .into(),
            secrets: HashMap::from([("TEST_ROLE_KEY".into(), "2".repeat(64))]),
        };
        fs::write(root.join("mode"), "busy").unwrap();
        fs::write(root.join("events"), "[]").unwrap();
        let service = BridgeService::with_runtime_dir(
            config,
            StateStore::new(root.join("state")),
            root.into(),
            None,
            root.join("runtime"),
        )
        .unwrap();
        Self { dir, service }
    }
    fn mode(&self, mode: &str) {
        fs::write(self.dir.path().join("mode"), mode).unwrap();
    }
    fn events(&self, events: Value) {
        fs::write(self.dir.path().join("events"), events.to_string()).unwrap();
    }
    fn calls(&self) -> Vec<Value> {
        fs::read_to_string(self.dir.path().join("calls"))
            .unwrap_or_default()
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
    fn event(id: &str) -> Value {
        json!({"id":id,"pubkey":"a".repeat(64),"created_at":100,"tags":[["p","b".repeat(64)]],"content":"exact task\n$(literal) 'quotes'"})
    }
}
#[test]
fn offline_identity_and_explicit_channel_survive_empty_snapshot() {
    let f = Fixture::new();
    let t = build_topology(&json!({}), &f.service.config);
    assert_eq!(t.agents().len(), 1);
    assert_eq!(t.agents()[0].identity_id.as_deref(), Some("dev-lead"));
    assert_eq!(t.agents()[0].status, "offline");
    let mut state = default_state();
    roles::bind_channels(&f.service.config, &mut state);
    assert_eq!(
        state["channels"]["buzzr-role:dev"]["channel_id"],
        "channel-dev"
    );
}

#[test]
fn default_channel_routes_new_owner_messages_without_replaying_history_or_bots() {
    let mut f = Fixture::new();
    f.service
        .config
        .bridge
        .persistent_roles
        .get_mut("dev-lead")
        .unwrap()
        .default_for_channel = true;
    let mut old = Fixture::event("old");
    old["tags"] = json!([]);
    f.events(json!([old]));
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(state["role_requests"].as_object().unwrap().len(), 0);
    let enrolled = state["role_cursors"]["default:dev-lead"].as_i64().unwrap();
    let mut owner = Fixture::event("plain-owner");
    owner["created_at"] = json!(enrolled);
    owner["tags"] = json!([]);
    let mut other = owner.clone();
    other["id"] = json!("other");
    other["pubkey"] = json!("c".repeat(64));
    let mut bot = owner.clone();
    bot["id"] = json!("bot");
    bot["pubkey"] = json!("b".repeat(64));
    let mut addressed_elsewhere = owner.clone();
    addressed_elsewhere["id"] = json!("elsewhere");
    addressed_elsewhere["tags"] = json!([["p", "c".repeat(64)]]);
    f.events(json!([owner, other, bot, addressed_elsewhere]));
    // Even an otherwise broad bridge policy never routes bots as default-owner input.
    f.service.config.bridge.respond_to = "anyone".into();
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(state["role_requests"].as_object().unwrap().len(), 1);
    f.mode("deliver");
    let id = roles::request_id("dev-lead", "channel-dev", "plain-owner");
    state["role_requests"][&id]["not_before"] = json!(0);
    f.service.poll_roles(&mut state).unwrap();
    state = f.service.store.load_strict().unwrap();
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(f.calls().iter().filter(|v| v["op"] == "deliver").count(), 1);
    let role = f
        .service
        .config
        .bridge
        .persistent_roles
        .get_mut("dev-lead")
        .unwrap();
    role.default_for_channel = false;
    f.service.poll_roles(&mut state).unwrap();
    assert!(state["role_cursors"].get("default:dev-lead").is_none());
}

#[test]
fn disabling_default_channel_holds_a_queued_plain_message() {
    let mut f = Fixture::new();
    f.service
        .config
        .bridge
        .persistent_roles
        .get_mut("dev-lead")
        .unwrap()
        .default_for_channel = true;
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    let mut event = Fixture::event("plain");
    event["created_at"] = state["role_cursors"]["default:dev-lead"].clone();
    event["tags"] = json!([]);
    f.events(json!([event]));
    f.service.poll_roles(&mut state).unwrap();
    f.service
        .config
        .bridge
        .persistent_roles
        .get_mut("dev-lead")
        .unwrap()
        .default_for_channel = false;
    f.mode("deliver");
    let id = roles::request_id("dev-lead", "channel-dev", "plain");
    state["role_requests"][&id]["not_before"] = json!(0);
    f.service.poll_roles(&mut state).unwrap();
    assert!(!f.calls().iter().any(|v| v["op"] == "deliver"));
    assert_eq!(
        state["role_status"]["dev-lead"]["reason"],
        "authorization_changed"
    );
}
#[test]
fn authorized_mentions_only_busy_retention_and_restart_replay_dedup() {
    let f = Fixture::new();
    let mut stranger = Fixture::event("stranger");
    stranger["pubkey"] = json!("c".repeat(64));
    let mut unmentioned = Fixture::event("untagged");
    unmentioned["tags"] = json!([]);
    f.events(json!([
        Fixture::event("one"),
        Fixture::event("two"),
        stranger,
        unmentioned
    ]));
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(state["role_requests"].as_object().unwrap().len(), 2);
    assert_eq!(f.calls().len(), 1); // one activation attempt, regardless of simultaneous mentions
    assert!(state["role_requests"]
        .as_object()
        .unwrap()
        .values()
        .all(|r| r["status"] == "queued"));
    let mut restarted = f.service.store.load_strict().unwrap();
    f.service.poll_roles(&mut restarted).unwrap();
    assert_eq!(restarted["role_requests"].as_object().unwrap().len(), 2);
    f.mode("deliver");
    f.service
        .advance_roles(&mut restarted, i64::MAX - 100)
        .unwrap();
    assert_eq!(f.calls().iter().filter(|c| c["op"] == "deliver").count(), 1);
    let delivery = f
        .calls()
        .into_iter()
        .find(|c| c["op"] == "deliver")
        .unwrap();
    assert!(delivery["content"]
        .as_str()
        .unwrap()
        .contains("exact task\n$(literal) 'quotes'"));
    assert!(!delivery.to_string().contains(&"2".repeat(64)));
    assert_eq!(
        restarted["reply_contexts"]
            .as_object()
            .unwrap()
            .values()
            .next()
            .unwrap()["identity_id"],
        "dev-lead"
    );
    f.service
        .advance_roles(&mut restarted, i64::MAX - 100)
        .unwrap();
    f.service.poll_roles(&mut restarted).unwrap();
    assert_eq!(f.calls().iter().filter(|c| c["op"] == "deliver").count(), 2);
}
#[test]
fn failures_and_ambiguous_delivery_are_retained_without_resubmission() {
    let f = Fixture::new();
    f.events(json!([Fixture::event("one")]));
    f.mode("failure");
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    let id = roles::request_id("dev-lead", "channel-dev", "one");
    assert_eq!(state["role_requests"][&id]["status"], "queued");
    f.mode("blocked");
    f.service.advance_roles(&mut state, i64::MAX - 100).unwrap();
    assert_eq!(state["role_status"]["dev-lead"]["reason"], "quota");
    state["role_requests"][&id]["not_before"] = json!(0);
    f.mode("uncertain");
    f.service.advance_roles(&mut state, 1000).unwrap();
    assert_eq!(state["role_requests"][&id]["status"], "uncertain");
    let calls = f.calls().len();
    f.service.advance_roles(&mut state, 2000).unwrap();
    assert_eq!(f.calls().len(), calls);
    state["role_requests"][&id]["status"] = json!("sending");
    f.service.advance_roles(&mut state, 2000).unwrap();
    assert_eq!(state["role_requests"][&id]["status"], "uncertain");
}
#[test]
fn project_isolation_and_authorization_rechecked_at_delivery() {
    let f = Fixture::new();
    let mut state = default_state();
    f.events(json!([Fixture::event("one")]));
    f.service.poll_roles(&mut state).unwrap();
    let id = roles::request_id("dev-lead", "channel-dev", "one");
    assert_ne!(
        id,
        roles::request_id("paperclip-lead", "channel-paperclip", "one")
    );
    state["role_requests"][&id]["project"] = json!("paperclip");
    f.mode("deliver");
    f.service.advance_roles(&mut state, i64::MAX - 100).unwrap();
    assert_eq!(
        state["role_status"]["dev-lead"]["reason"],
        "authorization_changed"
    );
    assert_eq!(f.calls().len(), 1);
}
#[test]
fn bounded_poll_gap_and_invalid_response_remain_visible() {
    let f = Fixture::new();
    f.events(json!((0..200)
        .map(|n| Fixture::event(&n.to_string()))
        .collect::<Vec<_>>()));
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(state["role_poll_errors"]["dev-lead"], "history_gap");
    assert_eq!(state["role_cursors"]["dev-lead"], 1);
    f.events(json!({}));
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(state["role_poll_errors"]["dev-lead"], "relay_unavailable");
}
#[test]
fn role_config_rejects_channel_sharing_across_projects() {
    let raw:toml::Value=toml::from_str("[a]\nproject='dev'\nrole='lead'\nchannel_id='same'\nchannel_name='dev'\nlauncher=['launch']\n[b]\nproject='paperclip'\nrole='lead'\nchannel_id='same'\nchannel_name='dev'\nlauncher=['launch']").unwrap();
    assert!(roles::parse(Some(&raw)).is_err());
}

#[test]
fn late_reply_confirms_uncertain_delivery_under_stable_role_identity() {
    let f = Fixture::new();
    f.events(json!([Fixture::event("one")]));
    f.mode("uncertain");
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    let id = roles::request_id("dev-lead", "channel-dev", "one");
    let token = state["role_requests"][&id]["reply_token"]
        .as_str()
        .unwrap()
        .to_string();
    fs::write(
        f.service.outbox_dir.join("progress.request.json"),
        json!({"token":token,"content":"Writer and QA started","progress":true}).to_string(),
    )
    .unwrap();
    f.service.process_outbox(&mut state).unwrap();
    assert!(state["reply_contexts"].get(&token).is_some());
    assert_eq!(state["role_requests"][&id]["status"], "delivered");
    fs::write(
        f.service.outbox_dir.join("reply.request.json"),
        json!({"token":token,"content":"Completed"}).to_string(),
    )
    .unwrap();
    f.service.process_outbox(&mut state).unwrap();
    assert_eq!(state["role_requests"][&id]["status"], "delivered");
    assert!(state["reply_contexts"].get(&token).is_none());
    let sent = fs::read_to_string(f.dir.path().join("notices")).unwrap();
    assert!(sent.contains("channel-dev"));
    assert!(sent.contains("Completed"));
    assert!(sent.contains("Writer and QA started"));
}

#[test]
fn channel_default_is_unique_even_with_multiple_roles_in_a_project() {
    let raw: toml::Value = toml::from_str("[a]\nproject='dev'\nrole='lead'\nchannel_id='same'\nchannel_name='dev'\nlauncher=['launch']\ndefault_for_channel=true\n[b]\nproject='dev'\nrole='qa'\nchannel_id='same'\nchannel_name='dev'\nlauncher=['launch']\ndefault_for_channel=true").unwrap();
    assert!(roles::parse(Some(&raw)).is_err());
}

#[test]
fn persistent_channel_is_not_archived_when_old_workspace_closes() {
    let mut f = Fixture::new();
    f.service.config.bridge.archive_closed_spaces = true;
    f.service.config.bridge.avatars_enabled = false;
    executable(
        std::path::Path::new(&f.service.config.bridge.buzz_bin),
        "#!/bin/sh\nprintf '%s\\n' '[]'\n",
    );
    let mut state = default_state();
    state["channels"]["old-workspace"] =
        json!({"channel_id":"channel-dev","name":"dev","origin":"created"});
    f.service.store.save(&state).unwrap();
    let topology = build_topology(&json!({}), &f.service.config);
    let report =
        buzzr::sync::reconcile(&f.service.config, &topology, &f.service.store, false).unwrap();
    assert!(!report
        .actions
        .iter()
        .any(|a| a.contains("archive") || a.contains("create #")));
}

#[test]
fn enrollment_is_durable_even_before_identity_is_provisioned() {
    let mut f = Fixture::new();
    f.service.config.identities.clear();
    let mut state = default_state();
    f.service.poll_roles(&mut state).unwrap();
    assert_eq!(state["role_cursors"]["dev-lead"], 1);
    assert_eq!(
        state["role_poll_errors"]["dev-lead"],
        "identity_unavailable"
    );
    assert_eq!(
        f.service.store.load_strict().unwrap()["role_cursors"]["dev-lead"],
        1
    );
    assert!(f.calls().is_empty());
}
