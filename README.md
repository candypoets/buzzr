# buzzr

`buzzr` is the dumb Herdr plugin that mirrors the herd you already run:

```text
Herdr Space          Buzz channel
    ├─ live agent  ↔  bot member
    ├─ live agent  ↔  bot member
    └─ @mention    →  that agent pane → threaded Buzz reply
```

It does not launch or replace agents. It discovers the current Herdr topology,
creates one private Buzz channel per project Space, gives the configured human
pubkey ownership, and binds each live agent name to a stable Nostr identity.

## The whole local setup

For a self-hosted Buzz relay, the only human credential is a **public key**:

```bash
herdr plugin install candypoets/buzzr --yes
herdr plugin pane open --plugin buzzr --entrypoint setup
```

For a non-interactive source checkout:

```bash
git clone https://github.com/candypoets/buzzr.git
cd buzzr
herdr plugin link "$PWD"
./bin/buzzr --config "$(herdr plugin config-dir buzzr)/config.toml" bootstrap \
  --human-pubkey <64-hex-pubkey> \
  --relay wss://buzz.example.com \
  --compose-file ~/buzz/docker-compose.yml
herdr plugin action invoke start --plugin buzzr
```

The setup overlay and `bootstrap` command perform the same provisioning flow.

`bootstrap` does the rest:

1. generates a dedicated bridge key and keys for unmapped Herdr agents with
   `nak`;
2. stores generated secrets in `secrets.env` beside the plugin config, mode
   `0600`;
3. registers those pubkeys as relay members through the local Buzz admin tool;
4. records every bridge/agent identity as belonging to the human pubkey in the
   local relay database, without changing an identity already owned by someone
   else;
5. assigns Recraft bee avatars, uploads them to Buzz, and publishes their Nostr
   profiles and Buzz agent-directory declarations;
6. creates/adopts the Space channels, adds the human as owner and agents as
   bots; and
7. enables reconciliation, automatic provisioning, and mention routing.

The human private key is never requested, read, or stored. Existing agent keys
can be imported from another mode-`0600` dotenv file with
`--agent-secrets-file`; missing identities are generated automatically.

## Ongoing behavior

The Herdr startup hook runs `buzzr daemon`. It reloads config every pass, notices
new live agents, provisions their identities, and reconciles channel membership.
Only messages signed by `human_pubkey` are routed by default, and only explicit
Nostr `p`-tag mentions target an agent. The agent sees an opaque one-use reply
command; no Buzz private key enters its prompt.

On every reconciliation, buzzr also aggregates every live identity's complete
set of mirrored channels into its replaceable Nostr `kind:10100` declaration.
This is what makes those bots mentionable in Buzz Desktop. The declaration
mirrors the bridge's response policy and lists the configured human public key
when access is owner-only; it never requires the human private key. Unchanged
declarations are cached and refreshed at most once per day.

## Recraft bee profiles

Buzzr ships with `bees-v1`, a pack of 24 anime bee avatars generated ahead of
time with Recraft. There is no image API, Recraft account, prompt, or extra
Python dependency at runtime. Each random Nostr identity deterministically
ranks the pack; Buzzr preserves existing assignments and avoids duplicates
until every avatar has been used.

The first profile reconciliation uploads each selected WebP to the relay's
Blossom store and publishes its public URL in that identity's signed Nostr
`kind:0` `picture` field. Upload URLs and assignments are cached, so routine
daily profile refreshes do not upload the image again. This covers the bridge
and every configured agent identity without using the human private key.

The defaults need no configuration:

```toml
[bridge]
avatars_enabled = true
avatar_pack = "bees-v1"
```

To backfill or force profile metadata to refresh immediately:

```bash
herdr plugin action invoke refresh-profiles --plugin buzzr
# Also discard cached Blossom URLs and upload the selected files again:
./bin/buzzr refresh-profiles --reupload
```

Set `avatars_enabled = false` for text-only profiles. A custom pack can be
selected with `avatar_pack_path`; its `manifest.json` uses the same `id`,
`collection`, `file`, and `sha256` fields as
[`assets/avatars/bees-v1/manifest.json`](assets/avatars/bees-v1/manifest.json).
The generation provenance and four Recraft prompt families are documented in
[`assets/avatars/bees-v1/README.md`](assets/avatars/bees-v1/README.md).

Useful checks:

```bash
herdr plugin action invoke doctor --plugin buzzr
herdr plugin action invoke plan --plugin buzzr
herdr plugin action invoke status --plugin buzzr
herdr plugin log list --plugin buzzr --limit 20
```

Source lives at [candypoets/buzzr](https://github.com/candypoets/buzzr), with a
maintainer fork at [sotach1/buzzr](https://github.com/sotach1/buzzr).

## Remote relay mode

Automatic relay registration and ownership binding require operator access to
the local Buzz Compose stack. For a remote relay, provision those identities
through that relay's administrator and use `buzzr configure` plus explicit
identity tables. The bridge still never needs the human private key.

## Safety

- The personal `~` Space is excluded.
- Closed Spaces are not archived and departed agents are not removed by
  default.
- Secrets are rejected if their file is group/world accessible.
- Agent ownership writes are idempotent and refuse to replace another owner.
- A runtime lock prevents duplicate routing daemons.
