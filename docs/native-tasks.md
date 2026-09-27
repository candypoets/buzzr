# Native Buzz tasks for persistent roles

Opt in on a persistent role with an explicit NIP-34 repository:

```toml
[persistent_roles.demo-lead.tasks]
owner = "<64-character repository owner public key>"
id = "demo"
```

The repository must already exist. Different projects cannot share a task
repository, even when they share a source-code checkout. This does not copy code
or change repository/channel permissions. Existing live-session mirrors and
roles without `tasks` keep their current behavior.

For a project with multiple repositories, keep `tasks` as the default repository
and add explicit additional members. Up to eight repositories total are allowed:

```toml
[[persistent_roles.demo-lead.additional_task_repositories]]
owner = "<64-character repository owner public key>"
id = "demo-web"
```

`list` aggregates the entire configured set in bounded queries. Every returned
task includes its repository coordinate. A create request may specify
`"repository":"30617:<owner>:demo-web"`; omitting it uses the primary repository.
Status changes infer the repository from the signed issue. Neither operation
can select an unconfigured repository, and two projects cannot share any member
of their task repository sets. Keep this allowlist aligned with the native Buzz
project's repository membership; no automatic discovery expands write authority.

An authorized role mention includes a `buzzr task --token TOKEN --request -`
command with the explicit runtime directory. Send JSON through stdin. The token
selects the role and repository; requests cannot override the project, signing
identity or relay. Run task operations before the final reply, which consumes
the token. No signing key appears in the prompt or command arguments.

Read native tasks and their current trusted status:

```json
{"op":"list"}
```

Create a task:

```json
{"op":"create","request_id":"request-123-task-1","title":"Repair startup","content":"Acceptance criteria and context","labels":["issue"]}
```

Record an explicit status change:

```json
{"op":"status","request_id":"request-123-task-1-completed","issue":"<event id>","status":"resolved","content":"Verified result and evidence link"}
```

Native statuses are `open`, `resolved`, `closed`, and `draft`. Herdr's working,
blocked and review states are execution detail, not invented native Buzz status
values. Preserve their evidence in the task/thread context. A queued message,
successful delivery or exited process is not proof of completion.

The bridge reads verified Nostr events and accepts status changes from the task
author or repository owner. It can update tasks only when the role identity is
one of those signers. It refuses another project's issue ID. Unknown tokens,
removed roles and revoked mention-author permissions also fail closed.

Writes require a stable `request_id`. The bridge persists the exact signed
event before publishing. After a disconnect or timeout, retry the identical
request with the same ID; Nostr deduplicates the event. Reusing an ID with changed
content fails. The durable ledger survives restarts. A failed publication does
not remove the request or claim completion.

Reads require relay end-of-results, have a 20-second limit per query, and refuse
a full 200-event page. They never report a truncated list as complete. Status
history can hit this limit before the issue list does; pagination remains a
rollout limit for larger repositories. Relay errors leave existing Herdr task
context intact.

## Herdr Projects workflow

The project lead reads native tasks when handling a user request, keeps Buzz
event IDs alongside its Herdr task/thread references, and records verified
completion back to Buzz. Herdr Projects continues to own worker lifecycle,
thread reports and local coordination. Imported external tasks retain their
source IDs and owners until execution ownership is reconciled.

Task creation or assignment alone does not wake a role in this version. Mention
the project lead to ask it to work on a task. There is no second scheduler and
no automatic conversion of arbitrary task text into launch authorization.

The local bridge's reply token authorizes task operations only while that
authorized request remains open. Workers report to their project lead through
Herdr Projects; they do not receive the lead's signing credentials or token.
