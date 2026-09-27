use std::os::unix::fs::PermissionsExt;
use std::{collections::HashMap, fs, net::TcpListener, path::PathBuf, thread};

use buzzr::{
    clients::nostr::query_events,
    config::{BridgeConfig, Config, IdentityConfig},
    roles::PersistentRole,
    service::BridgeService,
    state::StateStore,
    tasks::{build, Request, TaskRepo},
};
use nostr::{Keys, SecretKey};
use serde_json::{json, Value};
use tokio_tungstenite::tungstenite::{accept, Message};

fn key() -> String {
    format!("{:064x}", 1)
}
fn pubkey() -> String {
    Keys::new(SecretKey::from_hex(&key()).unwrap())
        .public_key()
        .to_hex()
}
fn repo() -> TaskRepo {
    TaskRepo {
        owner: pubkey(),
        id: "demo".into(),
    }
}
fn read(socket: &mut tokio_tungstenite::tungstenite::WebSocket<std::net::TcpStream>) -> Value {
    serde_json::from_str(socket.read().unwrap().to_text().unwrap()).unwrap()
}
fn send(socket: &mut tokio_tungstenite::tungstenite::WebSocket<std::net::TcpStream>, frame: Value) {
    socket
        .send(Message::Text(frame.to_string().into()))
        .unwrap();
}

#[test]
fn authenticated_query_resubscribes_and_requires_complete_scoped_results() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let event = build(
        &key(),
        None,
        &repo(),
        &Request::Create {
            request_id: "test".into(),
            repository: None,
            title: "Test".into(),
            content: "Body".into(),
            labels: vec![],
        },
        None,
    )
    .unwrap();
    let expected = event.id;
    let server = thread::spawn(move || {
        let mut socket = accept(listener.accept().unwrap().0).unwrap();
        let initial = read(&mut socket);
        assert_eq!(initial[0], "REQ");
        send(&mut socket, json!(["AUTH", "challenge"]));
        let auth = read(&mut socket);
        assert_eq!(auth[0], "AUTH");
        send(
            &mut socket,
            json!(["NOTICE", "auth-required: authenticate before subscribing"]),
        );
        send(
            &mut socket,
            json!(["CLOSED", initial[1], "auth-required: authenticate"]),
        );
        send(&mut socket, json!(["OK", auth[1]["id"], true, ""]));
        let retry = read(&mut socket);
        assert_ne!(initial[1], retry[1]);
        // A late completion for the unauthenticated subscription cannot hide tasks.
        send(&mut socket, json!(["EOSE", initial[1]]));
        send(&mut socket, json!(["EVENT", retry[1], event]));
        send(&mut socket, json!(["EOSE", retry[1]]));
    });
    let result = query_events(
        &url,
        &key(),
        json!({"kinds":[1621],"#a":[repo().coordinate()],"limit":200}),
    )
    .unwrap();
    assert_eq!(result[0].id, expected);
    server.join().unwrap();
}

#[test]
fn disconnected_query_is_not_an_empty_success() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut socket = accept(listener.accept().unwrap().0).unwrap();
        let _ = read(&mut socket);
    });
    assert!(query_events(&url, &key(), json!({"kinds":[1621],"limit":200})).is_err());
    server.join().unwrap();
}

#[test]
fn non_auth_notice_is_not_silently_ignored() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut socket = accept(listener.accept().unwrap().0).unwrap();
        let _ = read(&mut socket);
        send(
            &mut socket,
            json!(["NOTICE", "restricted: insufficient scope"]),
        );
    });
    let result = query_events(&url, &key(), json!({"kinds":[1621],"limit":200}));
    assert!(result.unwrap_err().to_string().contains("refused"));
    server.join().unwrap();
}

#[test]
fn event_from_another_repository_is_rejected_even_with_valid_signature() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let event = build(
        &key(),
        None,
        &repo(),
        &Request::Create {
            request_id: "one".into(),
            repository: None,
            title: "Task".into(),
            content: String::new(),
            labels: vec![],
        },
        None,
    )
    .unwrap();
    let server = thread::spawn(move || {
        let mut socket = accept(listener.accept().unwrap().0).unwrap();
        let req = read(&mut socket);
        send(&mut socket, json!(["EVENT", req[1], event]));
    });
    let result = query_events(
        &url,
        &key(),
        json!({"kinds":[1621],"#a":[format!("30617:{}:other", pubkey())],"limit":200}),
    );
    assert!(result.unwrap_err().to_string().contains("scope mismatch"));
    server.join().unwrap();
}

fn service(root: &std::path::Path, relay: String) -> BridgeService {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
    let role = PersistentRole {
        project: "demo".into(),
        role: "lead".into(),
        channel_id: "channel".into(),
        channel_name: "demo".into(),
        launcher: vec!["unused".into()],
        since: None,
        tasks: Some(repo()),
        additional_task_repositories: vec![],
        default_for_channel: false,
    };
    let config = Config {
        bridge: BridgeConfig {
            relay_url: relay,
            human_pubkey: Some("a".repeat(64)),
            persistent_roles: [("demo-lead".into(), role)].into(),
            ..Default::default()
        },
        identities: [(
            "demo-lead".into(),
            IdentityConfig {
                identity_id: "demo-lead".into(),
                display_name: "Demo lead".into(),
                aliases: vec![],
                public_key: pubkey(),
                private_key_env: "TASK_TEST_KEY".into(),
                auth_tag_env: None,
            },
        )]
        .into(),
        secrets: HashMap::from([("TASK_TEST_KEY".into(), key())]),
    };
    BridgeService::with_runtime_dir(
        config,
        StateStore::new(root.join("state")),
        PathBuf::from("/plugin"),
        None,
        root.to_path_buf(),
    )
    .unwrap()
}
fn state() -> Value {
    let mut state = buzzr::state::default_state();
    state["reply_contexts"] = json!({"token":{"identity_id":"demo-lead","channel_id":"channel","role_request_id":"original"}});
    state["role_requests"] = json!({"original":{"role_id":"demo-lead","project":"demo","channel_id":"channel","event":{"pubkey":"a".repeat(64)}}});
    state
}
fn operation(
    service: &BridgeService,
    root: &std::path::Path,
    state: &mut Value,
    payload: Value,
) -> Value {
    let outbox = root.join("outbox");
    fs::write(
        outbox.join("op.request.json"),
        json!({"token":"token","task":payload}).to_string(),
    )
    .unwrap();
    service.process_outbox(state).unwrap();
    serde_json::from_str(&fs::read_to_string(outbox.join("op.result.json")).unwrap()).unwrap()
}

#[test]
fn publish_retry_reuses_signed_event_after_lost_ack_and_survives_restart() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut first = accept(listener.accept().unwrap().0).unwrap();
        let original = read(&mut first);
        drop(first);
        let mut second = accept(listener.accept().unwrap().0).unwrap();
        let retry = read(&mut second);
        assert_eq!(original, retry);
        send(&mut second, json!(["OK", retry[1]["id"], true, ""]));
    });
    let service1 = service(root.path(), url.clone());
    let mut s = state();
    let payload = json!({"op":"create","request_id":"stable-id","title":"Task","content":"Body"});
    assert_eq!(
        operation(&service1, root.path(), &mut s, payload.clone())["ok"],
        false
    );
    // Restart from the durable checkpoint, not from the in-memory value.
    s = StateStore::new(root.path().join("state"))
        .load_strict()
        .unwrap();
    let service2 = service(root.path(), url);
    let confirmed = operation(&service2, root.path(), &mut s, payload.clone());
    assert_eq!(confirmed["ok"], true);
    assert_eq!(
        operation(&service2, root.path(), &mut s, payload.clone()),
        confirmed
    );
    let mut changed = payload;
    changed["content"] = json!("Different");
    assert_eq!(
        operation(&service2, root.path(), &mut s, changed)["ok"],
        false
    );
    assert!(!confirmed.to_string().contains(&key()));
    server.join().unwrap();
}

#[test]
fn revoked_author_and_wrong_channel_cannot_mutate_tasks() {
    let root = tempfile::tempdir().unwrap();
    let service = service(root.path(), "ws://127.0.0.1:1".into());
    for changed in ["author", "channel"] {
        let mut s = state();
        if changed == "author" {
            s["role_requests"]["original"]["event"]["pubkey"] = json!("b".repeat(64));
        } else {
            s["reply_contexts"]["token"]["channel_id"] = json!("other");
        }
        let result = operation(&service, root.path(), &mut s, json!({"op":"list"}));
        assert_eq!(result["error"], "task context is no longer authorized");
    }
}

#[test]
fn creates_can_select_only_an_explicit_project_repository() {
    let root = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let second = TaskRepo {
        id: "web".into(),
        ..repo()
    };
    let expected = second.coordinate();
    let server = thread::spawn(move || {
        let mut socket = accept(listener.accept().unwrap().0).unwrap();
        let event = read(&mut socket);
        assert!(event[1]["tags"]
            .as_array()
            .unwrap()
            .contains(&json!(["a", expected])));
        send(&mut socket, json!(["OK", event[1]["id"], true, ""]));
    });
    let mut service = service(root.path(), url);
    service
        .config
        .bridge
        .persistent_roles
        .get_mut("demo-lead")
        .unwrap()
        .additional_task_repositories
        .push(second.clone());
    let mut state = state();
    let payload = json!({"op":"create","request_id":"web-task","repository":second.coordinate(),"title":"Task","content":"Body"});
    assert_eq!(
        operation(&service, root.path(), &mut state, payload)["ok"],
        true
    );
    let payload = json!({"op":"create","request_id":"foreign-task","repository":format!("30617:{}:foreign", pubkey()),"title":"Task","content":"Body"});
    assert_eq!(
        operation(&service, root.path(), &mut state, payload)["ok"],
        false
    );
    server.join().unwrap();
}

#[test]
#[ignore = "explicit read-only live relay qualification; no events are published"]
fn live_read_only() {
    let config =
        buzzr::config::load_config(&PathBuf::from(std::env::var("BUZZR_TEST_CONFIG").unwrap()))
            .unwrap();
    let role = std::env::var("BUZZR_TEST_ROLE").unwrap();
    let configured = &config.bridge.persistent_roles[&role];
    let repos: Vec<_> = configured
        .tasks
        .iter()
        .chain(&configured.additional_task_repositories)
        .collect();
    let (key, _) = config.identity_credentials(&role).unwrap();
    let result =
        buzzr::tasks::list_repositories(&config.bridge.relay_url, &key.unwrap(), &repos).unwrap();
    println!(
        "Live read-only native tasks: {} across {} repositories",
        result["tasks"].as_array().unwrap().len(),
        repos.len()
    );
}
