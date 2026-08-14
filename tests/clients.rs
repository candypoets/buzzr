//! Pure and mockable client construction tests.

use std::path::Path;

use buzzr::clients::nostr::{build_agent_profile_event, build_auth_event, build_profile_event};
use buzzr::clients::{BuzzClient, HerdrClient, NostrTools};
use nostr::{JsonUtil, Kind};

const SOL_PRIVATE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

fn tools() -> NostrTools {
    NostrTools::new()
}

#[test]
fn buzz_upload_uses_the_identity_key_without_putting_it_in_argv() {
    let client = BuzzClient::new("buzz", "https://relay.example", SOL_PRIVATE, None);
    let (args, env) = client.build_upload_command(Path::new("/tmp/bee.webp"));

    assert_eq!(args, ["buzz", "upload", "file", "--file", "/tmp/bee.webp"]);
    assert!(!args.iter().any(|arg| arg == SOL_PRIVATE));
    let env: std::collections::HashMap<&str, &str> = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    assert_eq!(env.get("BUZZ_PRIVATE_KEY"), Some(&SOL_PRIVATE));
    assert_eq!(env.get("BUZZ_RELAY_URL"), Some(&"https://relay.example"));
    assert!(!env.contains_key("BUZZ_AUTH_TAG"));
}

#[cfg(unix)]
#[test]
fn buzz_cleanup_commands_use_supported_cli_shapes_without_key_argv_leaks() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-buzz");
    let calls = directory.path().join("calls");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nprintf '%s\\n' '{{}}'\n",
            calls.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let client = BuzzClient::new(
        executable.to_string_lossy(),
        "wss://relay.example",
        SOL_PRIVATE,
        None,
    );
    let pubkey = "a".repeat(64);
    client
        .remove_member("11111111-2222-3333-4444-555555555555", &pubkey)
        .unwrap();
    client
        .unarchive_channel_idempotent("11111111-2222-3333-4444-555555555555")
        .unwrap();
    client.archive_identity(&pubkey).unwrap();

    let recorded = std::fs::read_to_string(calls).unwrap();
    assert!(recorded.contains(&format!(
        "channels remove-member --channel 11111111-2222-3333-4444-555555555555 --pubkey {pubkey}"
    )));
    assert!(recorded.contains("channels unarchive --channel 11111111-2222-3333-4444-555555555555"));
    assert!(recorded.contains(&format!(
        "agents archive {pubkey} --reason retired --content Deprovisioned by buzzr"
    )));
    assert!(!recorded.contains(SOL_PRIVATE));
}

#[cfg(unix)]
#[test]
fn repeated_channel_archive_is_idempotent_without_projection_state() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-buzz");
    std::fs::write(
        &executable,
        "#!/bin/sh\nprintf '%s\n' 'channel already archived' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let client = BuzzClient::new(
        executable.to_string_lossy(),
        "wss://relay.example",
        SOL_PRIVATE,
        None,
    );

    client
        .archive_channel_idempotent("11111111-2222-3333-4444-555555555555")
        .expect("Buzz's explicit already-archived response is a successful retry");
}

#[cfg(unix)]
#[test]
fn repeated_channel_unarchive_is_idempotent_without_projection_state() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-buzz");
    std::fs::write(
        &executable,
        "#!/bin/sh\nprintf '%s\n' 'channel is not archived' >&2\nexit 1\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let client = BuzzClient::new(
        executable.to_string_lossy(),
        "wss://relay.example",
        SOL_PRIVATE,
        None,
    );

    client
        .unarchive_channel_idempotent("11111111-2222-3333-4444-555555555555")
        .expect("Buzz's explicit not-archived response is a successful retry");
}

#[test]
fn profile_event_includes_the_picture_without_leaking_the_secret() {
    // Mirrors test_nak_profile_includes_the_picture_without_putting_secret_in_argv.
    let event = build_profile_event(
        SOL_PRIVATE,
        "Sol",
        "Agent",
        Some("https://relay.example/media/bee"),
    )
    .expect("profile event builds");

    assert_eq!(event.kind, Kind::Metadata);
    assert_eq!(
        event.content,
        "{\"about\":\"Agent\",\"display_name\":\"Sol\",\"name\":\"Sol\",\
         \"picture\":\"https://relay.example/media/bee\"}"
    );
    let content: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(content["picture"], "https://relay.example/media/bee");
    assert_eq!(content["name"], "Sol");
    assert_eq!(content["display_name"], "Sol");
    assert_eq!(content["about"], "Agent");

    // Signed for the right key, and the signature verifies natively.
    assert_eq!(
        event.pubkey.to_hex(),
        tools().public_key(SOL_PRIVATE).unwrap()
    );
    event.verify().expect("signature verifies");

    // The secret appears in no serialized or loggable representation.
    assert!(!event.as_json().contains(SOL_PRIVATE));
    assert!(!format!("{event:?}").contains(SOL_PRIVATE));

    // Without a picture, the field is omitted.
    let no_picture = build_profile_event(SOL_PRIVATE, "Sol", "Agent", None).unwrap();
    assert_eq!(
        no_picture.content,
        "{\"about\":\"Agent\",\"display_name\":\"Sol\",\"name\":\"Sol\"}"
    );
}

#[test]
fn agent_profile_event_is_kind_10100_without_leaking_the_secret() {
    // Mirrors test_nak_publishes_kind_10100_without_putting_secret_in_argv.
    let content = serde_json::json!({"name": "Sol", "channel_ids": ["channel-id"]});
    let event = build_agent_profile_event(SOL_PRIVATE, &content).expect("agent event builds");

    assert_eq!(event.kind, Kind::Custom(10100));
    assert_eq!(
        event.content,
        "{\"channel_ids\":[\"channel-id\"],\"name\":\"Sol\"}"
    );
    let parsed: serde_json::Value = serde_json::from_str(&event.content).unwrap();
    assert_eq!(parsed["channel_ids"], serde_json::json!(["channel-id"]));

    assert_eq!(
        event.pubkey.to_hex(),
        tools().public_key(SOL_PRIVATE).unwrap()
    );
    event.verify().expect("signature verifies");
    assert!(!event.as_json().contains(SOL_PRIVATE));
    assert!(!format!("{event:?}").contains(SOL_PRIVATE));
}

#[test]
fn keypair_generation_and_derivation_are_consistent() {
    let (private_key, public_key) = tools().generate_keypair().unwrap();
    assert_eq!(private_key.len(), 64);
    assert_eq!(public_key.len(), 64);
    assert_eq!(tools().public_key(&private_key).unwrap(), public_key);
}

#[test]
fn invalid_keys_are_rejected_with_stable_messages() {
    let error = tools().public_key("not-a-key").unwrap_err();
    assert_eq!(error.to_string(), "invalid secret key");

    let error = build_profile_event("xyz", "Sol", "Agent", None).unwrap_err();
    assert_eq!(
        error.to_string(),
        "refusing to publish with an invalid private key"
    );

    let error = build_agent_profile_event("", &serde_json::json!({})).unwrap_err();
    assert_eq!(
        error.to_string(),
        "refusing to publish with an invalid private key"
    );

    // Uppercase hex is not accepted either (HEX64_RE is lowercase-only).
    let uppercase = "a".repeat(64).to_uppercase();
    assert!(tools().public_key(&uppercase).is_err());
}

#[test]
fn auth_event_answers_a_nip42_challenge() {
    let event = build_auth_event(SOL_PRIVATE, "challenge-token", "wss://relay.example")
        .expect("auth event builds");

    assert_eq!(event.kind, Kind::Custom(22242));
    assert_eq!(
        event.pubkey.to_hex(),
        tools().public_key(SOL_PRIVATE).unwrap()
    );
    event.verify().expect("signature verifies");

    let tags: Vec<Vec<String>> = event
        .tags
        .iter()
        .map(|tag| tag.as_slice().to_vec())
        .collect();
    assert_eq!(
        tags,
        [
            vec!["challenge".to_string(), "challenge-token".to_string()],
            vec!["relay".to_string(), "wss://relay.example".to_string()],
        ]
    );
    assert!(!event.as_json().contains(SOL_PRIVATE));
}

#[cfg(unix)]
#[test]
fn herdr_plugin_action_invocation_uses_the_manifest_action_surface() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("fake-herdr");
    let arguments = directory.path().join("arguments");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nprintf '%s\\n' \
             '{{\"id\":\"test\",\"result\":{{}}}}'\n",
            arguments.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

    HerdrClient::new(executable.to_string_lossy())
        .invoke_plugin_action("buzzr", "start")
        .expect("action invocation succeeds");

    assert_eq!(
        std::fs::read_to_string(arguments).unwrap(),
        "plugin\naction\ninvoke\nstart\n--plugin\nbuzzr\n"
    );
}
