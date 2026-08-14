//! Native Nostr key handling and profile publishing (replaces `nak`).
//!
//! Events are built and signed with the `nostr` crate and published
//! over a minimal websocket relay client (with NIP-42 auth), run on a private
//! tokio runtime since the rest of the crate is synchronous.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr::{Event, EventBuilder, JsonUtil, Keys, Kind, SecretKey, Tag, TagKind};
use serde_json::Value;

use super::{err, CommandError, ProfilePublisher};

/// Overall relay interaction budget, like nak's default publish timeout.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(45);

/// NIP-42 relay authentication event kind.
const KIND_AUTH: u16 = 22242;

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `json.dumps(value, separators=(",", ":"), sort_keys=True)` for any JSON.
///
/// Object keys are sorted explicitly, so the output does not depend on
/// serde_json's map representation.
pub(crate) fn dump_compact_sorted(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => dump_json_string(text),
        Value::Array(items) => {
            let rendered: Vec<String> = items.iter().map(dump_compact_sorted).collect();
            format!("[{}]", rendered.join(","))
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let rendered: Vec<String> = entries
                .into_iter()
                .map(|(key, entry)| {
                    format!("{}:{}", dump_json_string(key), dump_compact_sorted(entry))
                })
                .collect();
            format!("{{{}}}", rendered.join(","))
        }
    }
}

/// ASCII-only JSON string escaping: control characters use short escapes where
/// available, while other non-printable or non-ASCII values use `\uXXXX`
/// sequences (non-BMP values become UTF-16 surrogate pairs).
pub fn dump_json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c if (c as u32) < 0x7f => out.push(c),
            c => {
                let mut buffer = [0u16; 2];
                for unit in c.encode_utf16(&mut buffer) {
                    out.push_str(&format!("\\u{:04x}", unit));
                }
            }
        }
    }
    out.push('"');
    out
}

fn parse_keys(private_key: &str, message: &str) -> Result<Keys, CommandError> {
    if !is_hex64(private_key) {
        return err(message);
    }
    let secret = SecretKey::from_hex(private_key).map_err(|_| CommandError(message.to_string()))?;
    Ok(Keys::new(secret))
}

/// Build the kind:0 profile event, without any I/O.
pub fn build_profile_event(
    private_key: &str,
    name: &str,
    about: &str,
    picture: Option<&str>,
) -> Result<Event, CommandError> {
    let keys = parse_keys(
        private_key,
        "refusing to publish with an invalid private key",
    )?;
    let mut profile = serde_json::Map::new();
    profile.insert("name".to_string(), Value::String(name.to_string()));
    profile.insert("display_name".to_string(), Value::String(name.to_string()));
    profile.insert("about".to_string(), Value::String(about.to_string()));
    if let Some(picture) = picture {
        if !picture.is_empty() {
            profile.insert("picture".to_string(), Value::String(picture.to_string()));
        }
    }
    let content = dump_compact_sorted(&Value::Object(profile));
    EventBuilder::new(Kind::Metadata, content)
        .sign_with_keys(&keys)
        .map_err(|error| CommandError(format!("failed to sign profile event: {error}")))
}

/// Build the kind:10100 agent-directory event, without any I/O.
pub fn build_agent_profile_event(
    private_key: &str,
    content: &Value,
) -> Result<Event, CommandError> {
    let keys = parse_keys(
        private_key,
        "refusing to publish with an invalid private key",
    )?;
    EventBuilder::new(Kind::Custom(10100), dump_compact_sorted(content))
        .sign_with_keys(&keys)
        .map_err(|error| CommandError(format!("failed to sign agent profile event: {error}")))
}

/// Build the NIP-42 auth response event for a relay challenge.
pub fn build_auth_event(
    private_key: &str,
    challenge: &str,
    relay_url: &str,
) -> Result<Event, CommandError> {
    let keys = parse_keys(
        private_key,
        "refusing to publish with an invalid private key",
    )?;
    let tags = vec![
        Tag::custom(TagKind::Challenge, [challenge.to_string()]),
        Tag::custom(TagKind::Relay, [relay_url.to_string()]),
    ];
    EventBuilder::new(Kind::Custom(KIND_AUTH), "")
        .tags(tags)
        .sign_with_keys(&keys)
        .map_err(|error| CommandError(format!("failed to sign auth event: {error}")))
}

/// Send one frame and return an error with relay context on failure.
async fn send_frame<S>(socket: &mut S, frame: String) -> Result<(), CommandError>
where
    S: futures_util::Sink<
            tokio_tungstenite::tungstenite::Message,
            Error = tokio_tungstenite::tungstenite::Error,
        > + Unpin,
{
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(frame.into()))
        .await
        .map_err(|error| CommandError(format!("failed to send to relay: {error}")))
}

/// Render a NIP-01 relay frame with the event embedded as a JSON object.
fn relay_frame(kind: &str, event: &Event) -> Result<String, CommandError> {
    let object: Value = serde_json::from_str(&event.as_json())
        .map_err(|error| CommandError(format!("failed to encode relay frame: {error}")))?;
    Ok(serde_json::json!([kind, object]).to_string())
}

/// Publish a signed event to a relay, following the NIP-42 auth handshake.
///
/// Sequence: send EVENT once. An AUTH challenge is answered with only the
/// kind-22242 auth event; the original EVENT is resent exactly once, after
/// the relay confirms the auth event with OK(auth_id, true). A delayed
/// OK(event_id, false, "auth-required: ...") never aborts a pending auth
/// flow. All retries are bounded.
async fn publish_async(
    relay_url: &str,
    event: &Event,
    private_key: &str,
) -> Result<(), CommandError> {
    let (mut socket, _response) =
        tokio_tungstenite::connect_async(relay_url)
            .await
            .map_err(|error| {
                CommandError(format!("failed to connect to relay {relay_url}: {error}"))
            })?;

    let event_frame = relay_frame("EVENT", event)?;
    send_frame(&mut socket, event_frame.clone()).await?;
    let event_id = event.id.to_hex();
    let mut challenge: Option<String> = None;
    let mut auth_id: Option<String> = None;
    let mut auth_confirmed = false;
    let mut event_resent = false;
    // Whether the relay's auth-required rejection of the initial EVENT has
    // been observed. A single late duplicate of it may arrive after the auth
    // flow completed (the initial EVENT and the resent one share an id) and
    // must not fail the publish.
    let mut initial_rejection_seen = false;

    while let Some(message) = socket.next().await {
        let message =
            message.map_err(|error| CommandError(format!("relay connection failed: {error}")))?;
        let text = match message {
            tokio_tungstenite::tungstenite::Message::Text(text) => text,
            _ => continue,
        };
        let frame: Vec<Value> = match serde_json::from_str(&text) {
            Ok(frame) => frame,
            Err(_) => continue,
        };
        match frame.first().and_then(Value::as_str) {
            Some("OK") if frame.len() >= 4 => {
                let id = frame[1].as_str().unwrap_or_default();
                let accepted = frame[2].as_bool().unwrap_or(false);
                let notice = frame[3].as_str().unwrap_or_default();
                if auth_id
                    .as_deref()
                    .is_some_and(|auth_id| id.eq_ignore_ascii_case(auth_id))
                {
                    // Auth OKs are never ignored: they gate the EVENT resend.
                    if accepted {
                        auth_confirmed = true;
                        if !event_resent {
                            send_frame(&mut socket, event_frame.clone()).await?;
                            event_resent = true;
                        }
                    } else {
                        return err(format!("relay rejected the authentication: {notice}"));
                    }
                } else if id.eq_ignore_ascii_case(&event_id) {
                    if accepted {
                        return Ok(());
                    }
                    if notice.starts_with("auth-required") {
                        if auth_confirmed || event_resent {
                            if initial_rejection_seen {
                                // The initial rejection was already handled;
                                // this is the relay rejecting the resent event.
                                return err(format!("relay rejected the event: {notice}"));
                            }
                            // At most one late duplicate of the initial
                            // auth-required rejection: ignore it and keep
                            // waiting for the resent event's OK.
                            initial_rejection_seen = true;
                            continue;
                        }
                        initial_rejection_seen = true;
                        if let Some(challenge) = challenge.clone() {
                            if auth_id.is_none() {
                                // Challenge arrived before the rejection:
                                // authenticate, then wait for the auth OK.
                                let auth_event =
                                    build_auth_event(private_key, &challenge, relay_url)?;
                                auth_id = Some(auth_event.id.to_hex());
                                send_frame(&mut socket, relay_frame("AUTH", &auth_event)?).await?;
                            }
                            // Auth already sent: the pending flow may still
                            // succeed — keep waiting for OK(auth_id).
                        }
                        // No challenge yet: keep waiting for the AUTH frame.
                        continue;
                    }
                    return err(format!("relay rejected the event: {notice}"));
                }
                // OKs for unrelated events do not need handling.
            }
            Some("AUTH") if frame.len() >= 2 => {
                challenge = Some(frame[1].as_str().unwrap_or_default().to_string());
                if auth_id.is_none() {
                    let auth_event = build_auth_event(
                        private_key,
                        challenge.as_deref().unwrap_or_default(),
                        relay_url,
                    )?;
                    auth_id = Some(auth_event.id.to_hex());
                    send_frame(&mut socket, relay_frame("AUTH", &auth_event)?).await?;
                }
            }
            Some("NOTICE") => {
                let notice = frame.get(1).and_then(Value::as_str).unwrap_or_default();
                return err(format!("relay refused the connection: {notice}"));
            }
            _ => {}
        }
    }
    err("relay closed the connection before accepting the event")
}

fn publish_event(relay_url: &str, event: &Event, private_key: &str) -> Result<(), CommandError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CommandError(format!("failed to start relay runtime: {error}")))?;
    runtime.block_on(async {
        tokio::time::timeout(
            PUBLISH_TIMEOUT,
            publish_async(relay_url, event, private_key),
        )
        .await
        .map_err(|_| {
            CommandError(format!(
                "relay did not accept the event within {} seconds",
                PUBLISH_TIMEOUT.as_secs()
            ))
        })?
    })
}

/// Key and profile helpers; a native, secret-safe replacement for `nak`.
///
/// The private key is only ever used for in-process signing — it never
/// appears in argv, logs, or error strings.
#[derive(Debug, Clone, Copy, Default)]
pub struct NostrTools;

impl NostrTools {
    pub fn new() -> Self {
        NostrTools
    }

    /// Generate a fresh (private, public) hex keypair.
    pub fn generate_keypair(&self) -> Result<(String, String), CommandError> {
        let keys = Keys::generate();
        let private_key = keys.secret_key().to_secret_hex();
        if !is_hex64(&private_key) {
            return err("nostr generated an invalid secret key");
        }
        let public_key = keys.public_key().to_hex();
        Ok((private_key, public_key))
    }

    /// Derive the hex public key for a hex secret key.
    pub fn public_key(&self, private_key: &str) -> Result<String, CommandError> {
        let keys = parse_keys(private_key, "invalid secret key")?;
        Ok(keys.public_key().to_hex())
    }
}

impl ProfilePublisher for NostrTools {
    /// Publish a kind:0 profile with NIP-42 auth, like `nak event --auth`.
    fn publish_profile(
        &self,
        relay_url: &str,
        private_key: &str,
        name: &str,
        about: &str,
        picture: Option<&str>,
    ) -> Result<(), CommandError> {
        let event = build_profile_event(private_key, name, about, picture)?;
        publish_event(relay_url, &event, private_key)
    }

    /// Publish a replaceable Buzz agent-directory event (kind:10100).
    fn publish_agent_profile(
        &self,
        relay_url: &str,
        private_key: &str,
        content: &Value,
    ) -> Result<(), CommandError> {
        let event = build_agent_profile_event(private_key, content)?;
        publish_event(relay_url, &event, private_key)
    }
}

impl NostrTools {
    /// Inherent wrappers so callers do not need the trait in scope.
    pub fn publish_profile(
        &self,
        relay_url: &str,
        private_key: &str,
        name: &str,
        about: &str,
        picture: Option<&str>,
    ) -> Result<(), CommandError> {
        <Self as ProfilePublisher>::publish_profile(
            self,
            relay_url,
            private_key,
            name,
            about,
            picture,
        )
    }

    pub fn publish_agent_profile(
        &self,
        relay_url: &str,
        private_key: &str,
        content: &Value,
    ) -> Result<(), CommandError> {
        <Self as ProfilePublisher>::publish_agent_profile(self, relay_url, private_key, content)
    }
}
