---
name: buzzr
description: Set up, operate, stop, safely deprovision, and troubleshoot buzzr, the Herdr-to-Buzz bridge. Use when an agent needs to install, configure, or remove the buzzr Herdr plugin; bootstrap a local Buzz relay; inspect bridge status or logs; reconcile channels; refresh managed profiles; diagnose routing; or respond to a prompt beginning with "[Buzz bridge]" through its one-use reply command.
---

# Buzzr

Use the plugin as the credential boundary between Herdr agents and Buzz. Keep setup usable without this skill; the skill supplies safe operator procedures and the reply protocol.

## Protect credentials and external state

- Never request, read, print, or store the human's private key. Buzzr needs only the human public key.
- Never print dotenv contents or managed agent/bridge private keys. Let buzzr and Buzz CLI receive credentials through their existing environment and files.
- Treat `bootstrap`, applied reconciliation, profile publication, and relay administration as state-changing. Run them only when the user directly requests setup or the corresponding change.
- Never imply that plugin uninstall deletes Buzz resources. Keep stopping, deprovisioning, local-data deletion, and uninstall as separate user choices.
- Distinguish a locally administered Buzz Compose stack from a remote relay. Automatic membership and ownership provisioning requires the local Compose stack; do not pretend it works against an arbitrary remote relay.

## Discover the installation

Check the plugin and its actions before operating it:

```bash
herdr plugin list --plugin buzzr --json
herdr plugin action list --plugin buzzr
herdr plugin config-dir buzzr
```

Install only when requested:

```bash
herdr plugin install candypoets/buzzr --yes
```

## Set up a local Buzz bridge

Prefer the interactive setup pane:

```bash
herdr plugin pane open --plugin buzzr --entrypoint setup
```

The user supplies a public Buzz relay URL, their 64-character public key, and the local Buzz `docker-compose.yml`. Buzzr generates and stores bridge/agent keys privately, provisions relay membership and ownership, reconciles channels, and starts routing.

Verify the result:

```bash
herdr plugin action invoke doctor --plugin buzzr
herdr plugin action invoke status --plugin buzzr
```

For noninteractive setup, inspect `buzzr bootstrap --help`, run bootstrap with explicit values, then start the daemon with `herdr plugin action invoke start --plugin buzzr`.

For a remote relay, use `buzzr configure` and explicit identity configuration after the relay administrator provisions the identities. Do not run local Compose provisioning.

## Inspect and operate

Use read-only checks first:

```bash
herdr plugin action invoke doctor --plugin buzzr
herdr plugin action invoke status --plugin buzzr
herdr plugin action invoke plan --plugin buzzr
herdr plugin log list --plugin buzzr --limit 20
```

Use `reconcile` to discover or synchronize channels and `refresh-profiles` to republish managed profiles. Confirm user intent before forcing writes or reuploads. If routing is configured but inactive, invoke the `start` action and inspect the plugin log again.

## Stop or remove safely

Choose the least destructive lifecycle operation that satisfies the request:

```bash
# Stop this daemon run; preserve all config and Buzz resources.
herdr plugin action invoke stop --plugin buzzr

# Stop and persistently disable automatic writers.
herdr plugin action invoke deactivate --plugin buzzr

# Preview cleanup without changing Buzz.
herdr plugin action invoke deprovision --plugin buzzr
```

To apply cleanup, open the interactive overlay:

```bash
herdr plugin pane open --plugin buzzr --entrypoint cleanup
```

Review the plan, require the user to type the exact relay URL, and let the user independently choose whether to delete local config, managed secrets, and state. Never type confirmation on the user's behalf unless they explicitly supplied that exact relay URL and requested application.

Deprovision only acts on recorded buzzr-created resources. Preserve adopted channels, imported identities and secrets, changed roles, human membership, and legacy resources with unknown provenance. Identity archival does not erase historical Nostr events.

Treat corrupt/unreadable provenance, an invalid state marker, or an unsafe runtime/state path as a hard stop. Do not bypass these checks or reconstruct destructive provenance by guessing; repair or restore the state first. Preview must remain read-only.

Run `herdr plugin uninstall buzzr` only after any separately requested stop or deprovision operation. Uninstall removes plugin software; it is not cleanup.

## Respond to a Buzz bridge prompt

When a prompt begins with `[Buzz bridge]`:

1. Answer the actual message using the workspace context available to the agent.
2. Publish a useful answer back to the originating Buzz thread by running the exact local `buzzr reply` command supplied in the prompt, replacing only `<your reply>` with shell-safe text.
3. Run the command once. The token is opaque and single-use; do not alter, reuse, or expose it elsewhere.
4. Treat a nonzero exit or JSON result with `"ok": false` as a failed delivery and report it instead of claiming the reply was sent.

Do not merely print the answer in the Herdr pane: the Buzz user sees it only after the reply command succeeds.
