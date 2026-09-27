//! Native Buzz task operations. The bridge owns signing keys and repository
//! scope. Signed writes are journaled before publish and safely replay by id.
use nostr::{Event, EventBuilder, Keys, Kind, SecretKey, Tag};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::clients::nostr::{publish_event, query_events};

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRepo {
    pub owner: String,
    pub id: String,
}

fn hex64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl TaskRepo {
    pub fn validate(&self) -> Result<(), String> {
        if !hex64(&self.owner)
            || self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err("invalid persistent role task repository".into());
        }
        Ok(())
    }

    pub fn coordinate(&self) -> String {
        format!("30617:{}:{}", self.owner, self.id)
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    List {},
    Create {
        request_id: String,
        #[serde(default)]
        repository: Option<String>,
        title: String,
        content: String,
        #[serde(default)]
        labels: Vec<String>,
    },
    Status {
        request_id: String,
        issue: String,
        status: String,
        content: String,
    },
}

pub fn tag_values(event: &Event, name: &str) -> Vec<String> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            let v = tag.as_slice();
            (v.first().map(String::as_str) == Some(name))
                .then(|| v.get(1).cloned())
                .flatten()
        })
        .collect()
}

fn is_issue(event: &Event, repo: &TaskRepo) -> bool {
    event.kind.as_u16() == 1621 && tag_values(event, "a") == [repo.coordinate()]
}

fn status_name(kind: u16) -> Option<&'static str> {
    match kind {
        1630 => Some("open"),
        1631 => Some("resolved"),
        1632 => Some("closed"),
        1633 => Some("draft"),
        _ => None,
    }
}

fn status_root(event: &Event) -> Option<String> {
    let tags: Vec<_> = event
        .tags
        .iter()
        .map(|t| t.as_slice())
        .filter(|v| v.first().map(String::as_str) == Some("e"))
        .collect();
    let marked: Vec<_> = tags
        .iter()
        .filter(|v| v.get(3).map(String::as_str) == Some("root"))
        .collect();
    if marked.len() == 1 {
        return marked[0].get(1).cloned();
    }
    if !marked.is_empty() {
        return None;
    }
    tags.first().and_then(|t| t.get(1).cloned())
}

/// NIP-34 defaults to open. Only the issue author or configured repo owner can
/// change status; unrelated users' status events never drive project work.
pub fn snapshot(repo: &TaskRepo, issues: &[Event], statuses: &[Event]) -> Result<Value, String> {
    let mut result = Vec::new();
    for issue in issues {
        if !is_issue(issue, repo) || issue.verify().is_err() {
            return Err("task scope or signature mismatch".into());
        }
        let id = issue.id.to_hex();
        let newest = statuses
            .iter()
            .filter(|event| {
                status_name(event.kind.as_u16()).is_some()
                    && event.verify().is_ok()
                    && (event.pubkey == issue.pubkey || event.pubkey.to_hex() == repo.owner)
                    && status_root(event).as_deref() == Some(&id)
                    && (tag_values(event, "a").is_empty()
                        || tag_values(event, "a").contains(&repo.coordinate()))
            })
            .max_by_key(|event| (event.created_at, event.id));
        result.push(json!({"id":id, "repository":repo.coordinate(), "title":tag_values(issue,"subject").first(),
            "content":issue.content, "author":issue.pubkey.to_hex(), "labels":tag_values(issue,"t"),
            "status":newest.and_then(|e|status_name(e.kind.as_u16())).unwrap_or("open"),
            "status_event":newest.map(|e|e.id.to_hex())}));
    }
    Ok(json!({"repository":repo.coordinate(),"tasks":result}))
}

pub fn list(relay: &str, key: &str, repo: &TaskRepo) -> Result<Value, String> {
    list_repositories(relay, key, &[repo])
}

pub fn list_repositories(relay: &str, key: &str, repos: &[&TaskRepo]) -> Result<Value, String> {
    if repos.is_empty() || repos.len() > 8 {
        return Err("task reads require one to eight configured repositories".into());
    }
    let coordinates: Vec<_> = repos.iter().map(|r| r.coordinate()).collect();
    let issues = query_events(
        relay,
        key,
        json!({"kinds":[1621],"#a":coordinates,"limit":200}),
    )
    .map_err(|e| e.to_string())?;
    if issues.is_empty() {
        return aggregate_snapshot(repos, &[], &[]);
    }
    let ids: Vec<_> = issues.iter().map(|e| e.id.to_hex()).collect();
    let statuses = query_events(
        relay,
        key,
        json!({"kinds":[1630,1631,1632,1633],"#e":ids,"limit":200}),
    )
    .map_err(|e| e.to_string())?;
    aggregate_snapshot(repos, &issues, &statuses)
}

pub fn aggregate_snapshot(
    repos: &[&TaskRepo],
    issues: &[Event],
    statuses: &[Event],
) -> Result<Value, String> {
    if repos.is_empty() || issues.iter().any(|e| !repos.iter().any(|r| is_issue(e, r))) {
        return Err("task repository scope mismatch".into());
    }
    let mut tasks = Vec::new();
    for repo in repos {
        let selected: Vec<_> = issues
            .iter()
            .filter(|e| is_issue(e, repo))
            .cloned()
            .collect();
        tasks.extend(
            snapshot(repo, &selected, statuses)?["tasks"]
                .as_array()
                .unwrap()
                .clone(),
        );
    }
    Ok(json!({"repository":repos[0].coordinate(),
        "repositories":repos.iter().map(|r|r.coordinate()).collect::<Vec<_>>(),"tasks":tasks}))
}

pub fn select_repository<'a>(
    repos: &[&'a TaskRepo],
    coordinate: &str,
) -> Result<&'a TaskRepo, String> {
    repos
        .iter()
        .copied()
        .find(|r| r.coordinate() == coordinate)
        .ok_or_else(|| "task repository is not configured for this project".into())
}

pub fn operation_key(identity: &str, request: &Request) -> Result<Option<String>, String> {
    let id = match request {
        Request::List {} => return Ok(None),
        Request::Create { request_id, .. } | Request::Status { request_id, .. } => request_id,
    };
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err("task request_id must be a stable 1-128 character identifier".into());
    }
    Ok(Some(hex::encode(Sha256::digest(format!(
        "{identity}\0{id}"
    )))))
}

fn tag(values: Vec<String>) -> Result<Tag, String> {
    Tag::parse(values).map_err(|_| "invalid task tag".into())
}

/// Build once, then persist the signed event before invoking publish().
pub fn build(
    key: &str,
    auth: Option<&str>,
    repo: &TaskRepo,
    request: &Request,
    issue: Option<&Event>,
) -> Result<Event, String> {
    repo.validate()?;
    let keys = Keys::new(SecretKey::from_hex(key).map_err(|_| "task signing key unavailable")?);
    let mut tags = vec![tag(vec!["a".into(), repo.coordinate()])?];
    let (kind, content) = match request {
        Request::Create {
            title,
            content,
            labels,
            ..
        } => {
            if title.trim().is_empty()
                || title.len() > 256
                || labels.len() > 20
                || labels.iter().any(|l| l.is_empty() || l.len() > 128)
            {
                return Err("invalid task title or labels".into());
            }
            tags.push(tag(vec!["subject".into(), title.clone()])?);
            tags.push(tag(vec!["p".into(), repo.owner.clone()])?);
            for label in labels {
                tags.push(tag(vec!["t".into(), label.clone()])?);
            }
            (1621, content)
        }
        Request::Status {
            issue: id,
            status,
            content,
            ..
        } => {
            let issue = issue.ok_or("task does not exist")?;
            if !hex64(id)
                || issue.id.to_hex() != *id
                || !is_issue(issue, repo)
                || issue.verify().is_err()
            {
                return Err("task does not belong to this project repository".into());
            }
            if keys.public_key() != issue.pubkey && keys.public_key().to_hex() != repo.owner {
                return Err("only the task author or repository owner can change this task".into());
            }
            tags.push(tag(vec![
                "e".into(),
                id.clone(),
                String::new(),
                "root".into(),
            ])?);
            tags.push(tag(vec!["p".into(), issue.pubkey.to_hex()])?);
            let kind = match status.as_str() {
                "open" => 1630,
                "resolved" => 1631,
                "closed" => 1632,
                "draft" => 1633,
                _ => return Err("invalid native task status".into()),
            };
            (kind, content)
        }
        Request::List {} => return Err("list has no signed event".into()),
    };
    if content.len() > 65535 {
        return Err("task content exceeds 65,535 bytes".into());
    }
    if let Some(auth) = auth {
        let values: Vec<String> =
            serde_json::from_str(auth).map_err(|_| "invalid task owner attestation")?;
        if values.first().map(String::as_str) != Some("auth") {
            return Err("invalid task owner attestation".into());
        }
        tags.push(tag(values)?);
    }
    EventBuilder::new(Kind::Custom(kind), content)
        .tags(tags)
        .sign_with_keys(&keys)
        .map_err(|_| "cannot sign task event".into())
}

pub fn get_issue(relay: &str, key: &str, id: &str) -> Result<Option<Event>, String> {
    if !hex64(id) {
        return Err("invalid task event id".into());
    }
    let mut events = query_events(relay, key, json!({"kinds":[1621],"ids":[id],"limit":2}))
        .map_err(|e| e.to_string())?;
    Ok(events.pop())
}

pub fn publish(relay: &str, key: &str, event: &Event) -> Result<Value, String> {
    publish_event(relay, event, key).map_err(|_| {
        "task publish not confirmed; retry the same request_id to reconcile".to_string()
    })?;
    Ok(json!({"event_id":event.id.to_hex(),"kind":event.kind.as_u16()}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(n: u8) -> String {
        format!("{n:064x}")
    }
    fn repo() -> TaskRepo {
        TaskRepo {
            owner: Keys::new(SecretKey::from_hex(&key(2)).unwrap())
                .public_key()
                .to_hex(),
            id: "demo".into(),
        }
    }
    fn create() -> Request {
        Request::Create {
            request_id: "one".into(),
            repository: None,
            title: "Task".into(),
            content: "Body".into(),
            labels: vec![],
        }
    }

    #[test]
    fn native_task_and_status_roundtrip() {
        let r = repo();
        let issue = build(&key(1), None, &r, &create(), None).unwrap();
        let request = Request::Status {
            request_id: "done".into(),
            issue: issue.id.to_hex(),
            status: "resolved".into(),
            content: "Test passed".into(),
        };
        let done = build(&key(1), None, &r, &request, Some(&issue)).unwrap();
        assert_eq!(
            snapshot(&r, &[issue], &[done]).unwrap()["tasks"][0]["status"],
            "resolved"
        );
    }

    #[test]
    fn multi_repo_snapshot_keeps_source_scope_and_rejects_unconfigured_repo() {
        let api = repo();
        let web = TaskRepo {
            id: "web".into(),
            ..api.clone()
        };
        let one = build(&key(1), None, &api, &create(), None).unwrap();
        let two = build(&key(1), None, &web, &create(), None).unwrap();
        let snapshot = aggregate_snapshot(&[&api, &web], &[one.clone(), two.clone()], &[]).unwrap();
        assert_eq!(snapshot["tasks"].as_array().unwrap().len(), 2);
        assert_eq!(snapshot["tasks"][0]["repository"], api.coordinate());
        assert_eq!(snapshot["tasks"][1]["repository"], web.coordinate());
        assert!(aggregate_snapshot(&[&api], &[one, two], &[]).is_err());
        assert!(select_repository(&[&api], &web.coordinate()).is_err());
        assert_eq!(
            select_repository(&[&api, &web], &web.coordinate()).unwrap(),
            &web
        );
    }
    #[test]
    fn scope_and_ownership_fail_closed() {
        let r = repo();
        let issue = build(&key(1), None, &r, &create(), None).unwrap();
        let request = Request::Status {
            request_id: "done".into(),
            issue: issue.id.to_hex(),
            status: "closed".into(),
            content: String::new(),
        };
        assert!(build(&key(3), None, &r, &request, Some(&issue)).is_err());
        let other = TaskRepo {
            id: "other".into(),
            ..r
        };
        assert!(build(&key(1), None, &other, &request, Some(&issue)).is_err());
    }
    #[test]
    fn forged_status_is_ignored() {
        let r = repo();
        let issue = build(&key(1), None, &r, &create(), None).unwrap();
        let rogue = EventBuilder::new(Kind::Custom(1631), "")
            .tags([tag(vec!["e".into(), issue.id.to_hex()]).unwrap()])
            .sign_with_keys(&Keys::new(SecretKey::from_hex(&key(3)).unwrap()))
            .unwrap();
        assert_eq!(
            snapshot(&r, &[issue], &[rogue]).unwrap()["tasks"][0]["status"],
            "open"
        );
    }
    #[test]
    fn request_scope_and_validation() {
        assert_ne!(
            operation_key("a", &create()).unwrap(),
            operation_key("b", &create()).unwrap()
        );
        assert!(serde_json::from_value::<Request>(json!({"op":"list","project":"other"})).is_err());
        assert!(TaskRepo {
            owner: "bad".into(),
            id: "demo".into()
        }
        .validate()
        .is_err());
    }
}
