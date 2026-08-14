//! Deterministic fake-relay tests for the native Nostr publisher
//! (`src/clients/nostr.rs`): NIP-42 sequencing and wire-frame shapes.

use std::net::TcpListener as StdTcpListener;
use std::thread::JoinHandle;

use buzzr::clients::nostr::NostrTools;
use serde_json::{json, Value};

const PRIVATE_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const CHALLENGE: &str = "test-challenge";

type FrameLog = Vec<Value>;

/// Run one scripted fake relay connection on a background thread.
///
/// `script` maps each incoming client frame to the frames the relay sends
/// back. `on_connect` frames are sent right after the websocket handshake.
/// Returns the relay URL and a handle resolving to the recorded client frames
/// once the connection closes.
fn fake_relay<F>(on_connect: Vec<Value>, script: F) -> (String, JoinHandle<FrameLog>)
where
    F: FnMut(&Value) -> Vec<Value> + Send + 'static,
{
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind fake relay");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("relay runtime");
        runtime.block_on(async move {
            use futures_util::{SinkExt, StreamExt};
            let (stream, _) = tokio::net::TcpListener::from_std(listener)
                .unwrap()
                .accept()
                .await
                .expect("accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("ws upgrade");
            let mut script = script;
            let mut log: FrameLog = Vec::new();
            for frame in on_connect {
                socket
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        frame.to_string().into(),
                    ))
                    .await
                    .expect("send on_connect");
            }
            while let Some(message) = socket.next().await {
                let Ok(message) = message else { break };
                let text = match message {
                    tokio_tungstenite::tungstenite::Message::Text(text) => text,
                    _ => continue,
                };
                let Ok(frame) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                log.push(frame.clone());
                for reply in script(&frame) {
                    if socket
                        .send(tokio_tungstenite::tungstenite::Message::Text(
                            reply.to_string().into(),
                        ))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            log
        })
    });
    (format!("ws://127.0.0.1:{port}"), handle)
}

fn frame_kind(frame: &Value) -> &str {
    frame[0].as_str().unwrap_or_default()
}

fn frame_event_id(frame: &Value) -> String {
    frame[1]["id"].as_str().unwrap_or_default().to_string()
}

fn ok_frame(id: &str, accepted: bool, notice: &str) -> Value {
    json!(["OK", id, accepted, notice])
}

fn publish(url: &str) -> Result<(), String> {
    NostrTools::new()
        .publish_profile(
            url,
            PRIVATE_KEY,
            "Sol",
            "Agent",
            Some("https://relay.example/media/bee"),
        )
        .map_err(|error| error.to_string())
}

#[test]
fn publish_without_auth_sends_one_event_object() {
    let (url, relay) = fake_relay(Vec::new(), |frame| {
        vec![ok_frame(&frame_event_id(frame), true, "")]
    });
    publish(&url).expect("publish succeeds");
    let log = relay.join().expect("relay thread");
    assert_eq!(log.len(), 1);
    assert_eq!(frame_kind(&log[0]), "EVENT");
    assert!(log[0][1].is_object(), "event must be an embedded object");
    assert_eq!(log[0][1]["kind"], 0);
    let content = log[0][1]["content"].as_str().unwrap();
    let profile: Value = serde_json::from_str(content).unwrap();
    assert_eq!(profile["picture"], "https://relay.example/media/bee");
}

#[test]
fn auth_challenge_before_rejection_authenticates_then_resends_once() {
    let mut event_count = 0u32;
    let (url, relay) = fake_relay(
        vec![json!(["AUTH", CHALLENGE])],
        move |frame| match frame_kind(frame) {
            "EVENT" => {
                event_count += 1;
                if event_count == 1 {
                    vec![ok_frame(
                        &frame_event_id(frame),
                        false,
                        "auth-required: we only serve auth'd",
                    )]
                } else {
                    vec![ok_frame(&frame_event_id(frame), true, "")]
                }
            }
            "AUTH" => vec![ok_frame(&frame_event_id(frame), true, "")],
            _ => Vec::new(),
        },
    );
    publish(&url).expect("publish succeeds after auth");
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH", "EVENT"]);
    assert!(
        log[1][1].is_object(),
        "auth event must be an embedded object"
    );
    assert_eq!(log[1][1]["kind"], 22242);
    assert_eq!(log[1][1]["tags"][0], json!(["challenge", CHALLENGE]));
    // Same original event resent exactly once.
    assert_eq!(frame_event_id(&log[0]), frame_event_id(&log[2]));
}

#[test]
fn auth_challenge_after_rejection_authenticates_then_resends_once() {
    let mut event_count = 0u32;
    let (url, relay) = fake_relay(Vec::new(), move |frame| match frame_kind(frame) {
        "EVENT" => {
            event_count += 1;
            if event_count == 1 {
                vec![
                    ok_frame(
                        &frame_event_id(frame),
                        false,
                        "auth-required: we only serve auth'd",
                    ),
                    json!(["AUTH", CHALLENGE]),
                ]
            } else {
                vec![ok_frame(&frame_event_id(frame), true, "")]
            }
        }
        "AUTH" => vec![ok_frame(&frame_event_id(frame), true, "")],
        _ => Vec::new(),
    });
    publish(&url).expect("publish succeeds after auth");
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH", "EVENT"]);
}

#[test]
fn delayed_initial_rejection_before_auth_ok_does_not_fail_pending_flow() {
    // The relay rejects the original EVENT with auth-required only after the
    // client has already sent its AUTH: the pending auth flow must still win.
    let mut first_event_id = String::new();
    let mut event_count = 0u32;
    let (url, relay) = fake_relay(vec![json!(["AUTH", CHALLENGE])], move |frame| {
        match frame_kind(frame) {
            "EVENT" => {
                event_count += 1;
                if event_count == 1 {
                    first_event_id = frame_event_id(frame);
                    Vec::new()
                } else {
                    vec![ok_frame(&frame_event_id(frame), true, "")]
                }
            }
            "AUTH" => vec![
                // Delayed duplicate rejection for the *original* event.
                ok_frame(
                    &first_event_id,
                    false,
                    "auth-required: we only serve auth'd",
                ),
                ok_frame(&frame_event_id(frame), true, ""),
            ],
            _ => Vec::new(),
        }
    });
    publish(&url).expect("publish succeeds");
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH", "EVENT"]);
}

#[test]
fn delayed_initial_rejection_after_resend_is_ignored_once() {
    // Required ordering: AUTH challenge, client AUTH, OK(auth,true), client
    // resends EVENT, then the relay delivers the delayed OK(false,
    // auth-required) for the initial EVENT (same id), then OK(true).
    let mut event_count = 0u32;
    let (url, relay) = fake_relay(
        vec![json!(["AUTH", CHALLENGE])],
        move |frame| match frame_kind(frame) {
            "EVENT" => {
                event_count += 1;
                if event_count == 1 {
                    Vec::new()
                } else {
                    vec![
                        ok_frame(
                            &frame_event_id(frame),
                            false,
                            "auth-required: we only serve auth'd",
                        ),
                        ok_frame(&frame_event_id(frame), true, ""),
                    ]
                }
            }
            "AUTH" => vec![ok_frame(&frame_event_id(frame), true, "")],
            _ => Vec::new(),
        },
    );
    publish(&url).expect("publish succeeds");
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH", "EVENT"]);
    assert_eq!(frame_event_id(&log[0]), frame_event_id(&log[2]));
}

#[test]
fn auth_rejection_is_terminal_and_never_resends_the_event() {
    let (url, relay) = fake_relay(vec![json!(["AUTH", CHALLENGE])], |frame| {
        match frame_kind(frame) {
            "AUTH" => vec![ok_frame(
                &frame_event_id(frame),
                false,
                "restricted: unknown pubkey",
            )],
            "EVENT" => vec![ok_frame(
                &frame_event_id(frame),
                false,
                "auth-required: nope",
            )],
            _ => Vec::new(),
        }
    });
    let error = publish(&url).expect_err("publish must fail");
    assert!(
        error.contains("relay rejected the authentication: restricted: unknown pubkey"),
        "unexpected error: {error}"
    );
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH"]);
}

#[test]
fn event_rejection_after_successful_auth_is_terminal() {
    let mut event_count = 0u32;
    let (url, relay) = fake_relay(
        vec![json!(["AUTH", CHALLENGE])],
        move |frame| match frame_kind(frame) {
            "EVENT" => {
                event_count += 1;
                if event_count == 1 {
                    vec![ok_frame(
                        &frame_event_id(frame),
                        false,
                        "auth-required: we only serve auth'd",
                    )]
                } else {
                    vec![ok_frame(
                        &frame_event_id(frame),
                        false,
                        "blocked: not allowed",
                    )]
                }
            }
            "AUTH" => vec![ok_frame(&frame_event_id(frame), true, "")],
            _ => Vec::new(),
        },
    );
    let error = publish(&url).expect_err("publish must fail");
    assert!(
        error.contains("relay rejected the event: blocked: not allowed"),
        "unexpected error: {error}"
    );
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH", "EVENT"]);
}

#[test]
fn repeated_auth_required_after_resend_is_terminal() {
    let (url, relay) = fake_relay(vec![json!(["AUTH", CHALLENGE])], |frame| {
        match frame_kind(frame) {
            "AUTH" => vec![ok_frame(&frame_event_id(frame), true, "")],
            "EVENT" => vec![ok_frame(
                &frame_event_id(frame),
                false,
                "auth-required: still no",
            )],
            _ => Vec::new(),
        }
    });
    let error = publish(&url).expect_err("publish must fail");
    assert!(
        error.contains("relay rejected the event: auth-required: still no"),
        "unexpected error: {error}"
    );
    let log = relay.join().expect("relay thread");
    let kinds: Vec<&str> = log.iter().map(frame_kind).collect();
    assert_eq!(kinds, ["EVENT", "AUTH", "EVENT"]);
}

#[test]
fn relay_closing_mid_handshake_fails() {
    let listener = StdTcpListener::bind("127.0.0.1:0").expect("bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().unwrap().port();
    let url = format!("ws://127.0.0.1:{port}");
    let closer: JoinHandle<()> = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            use futures_util::StreamExt;
            let (stream, _) = tokio::net::TcpListener::from_std(listener)
                .unwrap()
                .accept()
                .await
                .unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            // Read one frame, then close politely without any OK.
            let _ = socket.next().await;
            let _ = socket.close(None).await;
        });
    });
    let error = publish(&url).expect_err("publish must fail");
    assert!(
        error.contains("relay closed the connection"),
        "unexpected error: {error}"
    );
    closer.join().expect("closer thread");
}

#[test]
fn tls_crypto_provider_is_selected_for_wss_relays() {
    let _ = rustls::ClientConfig::builder();
    assert!(rustls::crypto::CryptoProvider::get_default().is_some());
}
