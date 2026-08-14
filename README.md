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

For a self-hosted Buzz relay, the only human credential is a **public key**.

From the checkout you want to run — including a local checkout with unpushed
changes — build once, link it, and let the setup pane run inside Herdr's
managed config and state directories:

```bash
cd /path/to/buzzr
cargo build --release --locked
herdr plugin link "$PWD"
herdr plugin pane open --plugin buzzr --entrypoint setup
```

The setup pane asks for the relay URL, your `npub` (or 64-character hex public key), and the
local Buzz `docker-compose.yml`. It also offers an optional existing mode-`0600`
agent dotenv; press Enter to generate every missing identity. It provisions the
bridge, starts the routing daemon, and finishes by telling you to open Buzz and
`@mention` one of the mirrored agents. Verify it at any time with:

```bash
herdr plugin action invoke doctor --plugin buzzr
```

For a published release, installation is one command before opening the same
setup pane:

```bash
herdr plugin install candypoets/buzzr --yes
herdr plugin pane open --plugin buzzr --entrypoint setup
```

GitHub installation requires the repository version, Git tag, and release
assets to match. Until a matching release exists, use the source-checkout flow
above; the installer intentionally fails closed instead of using another
version. `herdr plugin install` runs the manifest build step
([`scripts/install.sh`](scripts/install.sh)), which downloads the matching
prebuilt release binary into the plugin tree, so no language toolchain is
needed at runtime. On a version tag, release CI publishes macOS binaries for
x86_64 and aarch64 and fully static musl Linux binaries for x86_64 and aarch64
(no glibc or libz baseline requirement).

The setup overlay uses `bootstrap` internally and starts the daemon. For
standalone automation, direct `bootstrap` remains available, but both paths
must be explicit and every subsequent direct command must reuse the same pair:

```bash
./bin/buzzr --config /path/to/config.toml --state-dir /path/to/state bootstrap \
  --human-pubkey <npub-or-64-hex-pubkey> \
  --relay wss://buzz.example.com \
  --compose-file ~/buzz/docker-compose.yml
./bin/buzzr --config /path/to/config.toml --state-dir /path/to/state daemon
```

Do not bootstrap into one state directory and then start through a Herdr action
that uses another; cleanup provenance belongs to the state directory where the
external mutations were recorded.

`bin/buzzr` is a tiny shim: it execs the installed `bin/buzzr-bin` when
present and the local `target/release/buzzr` build otherwise.

The setup overlay and `bootstrap` command perform the same provisioning flow.
The interactive setup starts the routing daemon automatically; direct
`bootstrap` leaves daemon supervision to the caller.

`bootstrap` does the rest:

1. generates a dedicated bridge key and keys for unmapped Herdr agents
   natively (Rust `nostr` crate; no external Nostr tools);
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

The Herdr startup hook runs `buzzr daemon`; a deactivated bridge exits
immediately. An active daemon reloads config every pass, notices new live
agents, provisions their identities, and reconciles channel membership.
Only messages signed by `human_pubkey` are routed by default, and only explicit
Nostr `p`-tag mentions target an agent. The agent sees an opaque one-use reply
command; no Buzz private key enters its prompt.

On every reconciliation, buzzr also aggregates every live identity's complete
set of mirrored channels into its replaceable Nostr `kind:10100` declaration.
This is what makes those bots mentionable in Buzz Desktop. The declaration
mirrors the bridge's response policy and lists the configured human public key
when access is owner-only; it never requires the human private key. Unchanged
declarations are cached and refreshed at most once per day.

## Layered Recraft bee profiles

Buzzr ships with `bees-v2`, an NFT-style layer pack made with Recraft. It uses
one canonical bee rig and independently selects a background, body palette,
neck accessory, eyewear, and headwear from the identity's Nostr public key.
The 6 × 6 × 7 × 7 × 7 traits provide 12,348 stable combinations.

Generated source art can have any dimensions. Pack preparation trims and
positions every part on the same transparent 512×512 canvas, and the manifest
records that normalized geometry. At runtime, buzzr validates every layer,
alpha-composites the selected PNGs in z-order, and caches the finished image.
The compositor is built into the Rust binary; it needs no Recraft account,
image API, or image tooling on the installed machine.

The first profile reconciliation uploads the composed PNG to the relay's
Blossom store and publishes its public URL in that identity's signed Nostr
`kind:0` `picture` field. Upload URLs, selected traits, and compositions are
cached, so routine daily profile refreshes do not upload the image again. This
covers the bridge and every configured agent identity without using the human
private key.

The defaults need no configuration:

```toml
[bridge]
avatars_enabled = true
avatar_pack = "bees-v2"
```

To backfill or force profile metadata to refresh immediately:

```bash
herdr plugin action invoke refresh-profiles --plugin buzzr
# Also discard cached Blossom URLs and upload the selected files again:
./bin/buzzr --config /path/to/config.toml --state-dir /path/to/state \
  refresh-profiles --reupload
```

For the direct form, use the exact config and state directories belonging to
the installation; cached avatar URLs and profile fingerprints live in state.

Set `avatars_enabled = false` for text-only profiles. A custom layered pack can
be selected with `avatar_pack_path`; its categories and integrity hashes follow
[`assets/avatars/bees-v2/manifest.json`](assets/avatars/bees-v2/manifest.json).
Legacy `bees-v1`-style complete-image manifests remain supported. The Recraft
prompts, layer preparation, and coordinate contract are documented in
[`assets/avatars/bees-v2/README.md`](assets/avatars/bees-v2/README.md).

Useful checks:

```bash
herdr plugin action invoke doctor --plugin buzzr
herdr plugin action invoke plan --plugin buzzr
herdr plugin action invoke status --plugin buzzr
herdr plugin log list --plugin buzzr --limit 20
```

## Stop, deactivate, and remove

These are intentionally separate operations:

```bash
# Stop the current daemon. Config, state, channels, and identities remain.
herdr plugin action invoke stop --plugin buzzr

# Stop it and persistently disable sync, routing, and automatic provisioning.
herdr plugin action invoke deactivate --plugin buzzr

# Preview provenance-safe external cleanup. This never applies changes.
herdr plugin action invoke deprovision --plugin buzzr

# Apply from a terminal with typed confirmation and an independent local-data choice.
herdr plugin pane open --plugin buzzr --entrypoint cleanup
```

`herdr plugin uninstall buzzr` only removes the plugin registration/software. It
does not stop or deprovision Buzz resources; stop or deprovision first when that
is the intended outcome.

Deprovisioning archives channels that state proves buzzr created, removes
tracked generated identities from adopted channels, archives generated
identities through Buzz, clears ownership links assigned by buzzr, and removes
relay memberships added by buzzr. Adopted channels, imported identities,
legacy resources without provenance, the human's membership, and imported
secrets files are preserved. Published Nostr events remain relay history;
identity archival is not cryptographic erasure.

The preview is filesystem-read-only: it does not create a state directory or
cleanup marker. Applied cleanup fails closed on corrupt/unreadable provenance,
foreign-owned or symlinked runtime/state paths, and an invalid cleanup marker.
Provisioning and reconciliation checkpoint destructive provenance around each
external mutation so an interrupted run can be retried safely.

For automation, invoke the binary with the same explicit config and state
directories used by the Herdr installation. Both are required so provenance is
loaded from the correct state. Apply only with the exact configured relay URL:

```bash
./bin/buzzr --config /path/to/config.toml --state-dir /path/to/state \
  deprovision --json
./bin/buzzr --config /path/to/config.toml --state-dir /path/to/state \
  deprovision --apply --confirm-relay wss://buzz.example.com
# Also delete config, the managed secrets file, and marked state:
./bin/buzzr --config /path/to/config.toml --state-dir /path/to/state \
  deprovision --apply --confirm-relay wss://buzz.example.com --delete-local-data
```

State created before provenance tracking is deliberately treated as unknown
and will be reported but not deleted. A successful reconciliation records
`created` versus `adopted` channel origin for future cleanup.

## Optional agent skill

Buzzr includes an agent skill for setup, safe operation, troubleshooting, and
the one-use reply protocol:

```bash
# Unreleased/local checkout (run from the repository root):
npx skills add "$PWD" --skill buzzr -g -y

# Published repository version:
npx skills add candypoets/buzzr --skill buzzr -g
```

The skill is optional and is not silently installed into any agent. Routed
messages are self-contained: every `[Buzz bridge]` prompt already gives the
agent the credential-free command it must run to publish its answer back to
the originating thread. The remote installation command reads the published
repository, so use the local form while testing unpushed changes. The
repository copy is [`skills/buzzr/SKILL.md`](skills/buzzr/SKILL.md).

Source lives at [candypoets/buzzr](https://github.com/candypoets/buzzr), with a
maintainer fork at [sotach1/buzzr](https://github.com/sotach1/buzzr).

## Remote relay mode

Automatic relay registration and ownership binding require operator access to
the local Buzz Compose stack. For a remote relay, provision those identities
through that relay's administrator, then use `buzzr configure` plus explicit
bridge and identity tables. `configure` deliberately does not enable writers;
complete the identity tables in the plugin config (see
[`config.example.toml`](config.example.toml)), verify the credentials, then set:

```toml
[bridge]
sync_enabled = true
routing_enabled = true
auto_provision_agents = false
```

Start the daemon only after `doctor` succeeds:

```bash
herdr plugin action invoke doctor --plugin buzzr
herdr plugin action invoke plan --plugin buzzr
herdr plugin action invoke start --plugin buzzr
```

The relay administrator must provision every bridge/agent membership and
ownership relationship that local Compose mode would otherwise create. The
bridge still never needs the human private key.

## Safety

- The personal `~` Space is excluded.
- Closed Spaces are not archived and departed agents are not removed by
  default.
- If a buzzr-created archived Space reappears, its original channel is
  unarchived; it is never reclassified as adopted by name.
- If `remove_departed_agents = true`, only bot memberships previously recorded
  as added by buzzr are eligible; role changes are preserved for review.
- Secrets are rejected if their file is group/world accessible.
- Agent ownership writes are idempotent and refuse to replace another owner.
- A runtime lock prevents duplicate routing daemons.
- Uninstall is never an external-resource deletion hook.
