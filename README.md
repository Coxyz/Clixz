# clixz

CLI to inventory, check and create the Docker services under `/srv/docker`.

It is a tool **for the operator**: see what is deployed, verify it still matches
the rules, scaffold a new service, keep its metadata. It is not a compose
generator and not a security engine.

## What changed in 2.0

v1 tried to make bad configurations *inexpressible*: `compose.yaml` was rendered
from a closed typed structure (`spec.json`), and anything the structure could
not describe simply could not be deployed. The reasoning was sound and the
outcome was not — a closed model meets a service that needs a published port, a
USB device or host networking, and it reopens. The repository showed it: an
`Exceptions` dataclass with ten fields, then an `/etc/clixz/elevated.yaml`
allowlist, both added to widen a model that had been narrowed deliberately.

An audit of the running infrastructure on 2026-08-29 settled it. Roughly 70 % of
the system's effort went into filesystem permissions, while ~90 % of the real
risk sat in three privileged containers and in what the reverse proxy published
to the internet — including the MCP server itself, which nothing in clixz could
see because the exposure lived in a database and every check looked at files.

So 2.0 moves the effort:

| v1 | v2 |
|---|---|
| `spec.json` → generated `compose.yaml`, "do not hand-edit" | `compose.yaml` is the source of truth; `clixz new` writes a hardened template you edit |
| Reject what the model cannot express | `clixz check` lints and **warns**; it never rewrites |
| Seven path rules + a POSIX ACL engine | Three rules, no ACLs at all |
| `clixz-runnerd` + `clixz-admind` (root, CAP_DAC_OVERRIDE) | one unprivileged `clixz-mcpd` that cannot write |
| Nothing looked at the reverse proxy | `clixz exposed` cross-checks it |
| 6 126 lines | ~2 900 lines at 2.0 (~4 100 at 2.2, with rules, repos and categories) |

`docs/REFONTE.md` records the reasoning and the decisions; `docs/TODO-OPXYZ.md`
lists the host-side actions the audit produced.

## Install

Published on PyPI as [`clixz`](https://pypi.org/project/clixz/). Write commands
need root (`chown`/`chmod`), so install it system-wide:

```bash
sudo sh -c 'umask 022 && pipx install --global clixz'
sudo clixz upgrade          # every later upgrade
```

The `umask` matters on a hardened host: with `UMASK 027` in `/etc/login.defs`,
pipx and uv create an environment only root can read, and `clixz` then fails
with "permission denied" for everyone else — including `clixz-mcpd`.
`clixz upgrade` sets it for you and calls the installer that put clixz there
(pipx or uv), so there is nothing to remember after the first install.

Write commands re-exec themselves through `sudo` automatically — set
`CLIXZ_NO_SUDO=1` to opt out (containers, CI, and `clixz-mcpd`, which must never
gain privilege).

Optional shell completion for your user: `clixz --install-completion`.

## Commands

```bash
# read
clixz ls [-C apps]              # services with image and published ports
clixz ls --archived
clixz show apps/atuin           # permissions, compose lint, paths, one screen
clixz check [service]           # audit + lint. exit 1 on a permission error
clixz exposed [--snapshot]      # what NPM publishes vs what service.yaml declares
clixz rules                     # the compose rules in effect, and what is ignored

# write  (each accepts --plan: prints what it would do, writes nothing)
clixz new apps/myapp            # tree + hardened compose template + .env + service.yaml
clixz fix [service]             # repair ownership and modes
clixz rm apps/myapp             # archive under .archive/  (--force deletes, TTY only)
clixz category add media        # system account + directory + config entry

# housekeeping
clixz meta [service] [--scaffold]
clixz manifest [--dry-run]
clixz image add|rm|ls <name>    # build contexts under /opt/images
clixz repo add|rm|ls <name>     # git checkouts under /opt/repos (add --url clones)
clixz category ls
clixz rules --edit | --edit-ignore
clixz config [--migrate] [--edit]
clixz mcp                       # what the MCP gateway can run and read
clixz upgrade [--plan]          # upgrade clixz itself, world-readable
```

Every command takes `--json` for machine-readable output. That is what
`clixz-mcpd` consumes.

## Layout

```
/srv/docker/<category>/<service>/
├── compose.yaml     640   source of truth — edit it
├── .env             600   root:root, secrets
├── service.yaml     640   dashboard/MCP metadata
├── config/          750   inputs, mounted :ro
└── data/            750   state, written by the container
```

Contents of `config/` and `data/` are never audited and never touched. A
recursive chown across a running container's state directory is a good way to
break it, and clixz has no opinion about what a service stores.

## Configuration

Read from `--config FILE`, then `/etc/clixz/config.yaml`, then
`~/.config/clixz/config.yaml`, then the bundled defaults.

```yaml
root_dir: /srv/docker
categories:
  apps: { user: svc_apps, group: svc_apps }
rules:
  dir:  { mode: "750" }                        # category/, service/, config/, data/
  file: { mode: "640" }                        # compose.yaml, service.yaml
  env:  { mode: "600", owner: "root:root" }    # .env
images: { dir: /opt/images }
repos:  { dir: /opt/repos }
npm:
  database: /srv/docker/network/npm/data/app/database.sqlite
```

Two files are generated next to the config rather than inside a service, because
they describe the whole tree: `manifest.json` (`clixz manifest`; the container
that serves it mounts it read-only from there) and `npm-hosts.json`
(`clixz exposed --snapshot`, see the MCP gateway below).

### Compose rules and accepted exceptions

What `clixz check` says about a compose file is not hard-coded. Two optional
files sit next to `config.yaml`, and `clixz rules` prints what is in effect:

```yaml
# /etc/clixz/lint.yaml — the level of each rule, for every service
rules:
  image-latest: error        # error | warn | info | off
  no-healthcheck: off
mounts:
  critical: [/var/run/docker.sock, /root]    # replaces the built-in list
```

```yaml
# /etc/clixz/ignore.yaml — findings looked at and accepted, per service
ignore:
  - service: automation/esphome          # globs work: "apps/*", "*"
    rules: [privileged, network-host]
    reason: "flashes boards over USB and discovers them by mDNS"
```

`clixz rules --edit` and `clixz rules --edit-ignore` create them from a commented
template. An ignored finding disappears from `clixz check` (still counted, and
listed with its reason by `--verbose`) and `clixz fix` leaves it alone. Permission
findings (`missing-dir`, `missing-file`, `owner`, `mode`, `acl`) can be ignored
the same way; their severity is not configurable. An entry without a `reason` is
reported and not applied.

`clixz config --migrate` prints a v2 translation of a v1 file. It carries the
identity forward (root_dir, categories, exclude, manifest, images) and **drops**
the ACL sections rather than translating them — they have no v2 equivalent, and
that is the point.

### Why the per-category accounts stay, and the ACLs do not

The `svc_*` accounts are real isolation: the audit verified that a compromised
non-root container in one category cannot read another's data. That holds for
9 of 17 containers — the rest run as root and bypass it by construction, but the
9 are worth the two lines of config.

The ACLs were not. The `dev` principal served code-server, which is not
deployed. The `docker:r` entry on `.env` had no reader — the Docker daemon reads
env files as root. All of them are gone, and with them `setfacl`, the ACL mask,
and the whole class of "the mode you see is not the mode that applies" confusion.

The `komodo` principal is the one the audit got wrong. It reasoned that Komodo
Periphery runs as uid 0 with the Docker socket and therefore reads everything.
It does run as uid 0 — with `cap_drop: ALL`, and root without `CAP_DAC_OVERRIDE`
is subject to file modes like anyone else: the ACL was the only thing letting it
read a compose file, and removing it locked Komodo out of every stack. The fix
is not to bring the ACL back but to say what is true in the one place it
belongs, Periphery's own compose:

```yaml
    cap_add: [DAC_OVERRIDE]
    cap_drop: [ALL]
```

That grants nothing the Docker socket had not already granted. Komodo Core is in
the same position for its own `/config`. **If you deploy with Komodo, add the
capability to both before running `clixz fix` on a tree that still carries v1
ACLs** — a container keeps working until its next restart, so the breakage shows
up later and looks unrelated.

`clixz check` still *detects* leftover ACL entries from v1 and `clixz fix`
clears them with `setfacl -b`.

## The MCP gateway

`clixz-mcpd` is a single unprivileged daemon on a Unix socket, consumed by the
MCP container. Read verbs run as-is; mutating verbs are forwarded to the CLI
with `--plan`, which prints the commands it would run and exits without writing.
The unit carries `ReadOnlyPaths=/srv/docker`, so this is not a policy the daemon
enforces on itself — it is a thing it cannot do.

The approval loop still exists. It goes through the keyboard: the model proposes
a plan, you run `sudo clixz fix …`.

```bash
sudo cp deploy/clixz-mcpd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now clixz-mcpd
```

The daemon also lists repos and categories, prints the rules, and plans
`category add`, `repo add` and `repo rm` — planned, like every other mutation.

`clixz exposed` reads a database only root can open, so the daemon cannot run it
for real. Instead root copies the proxy hosts to `npm-hosts.json` on a timer, and
an unprivileged `clixz exposed` falls back on that copy and says how old it is:

```bash
sudo cp deploy/clixz-snapshot.service deploy/clixz-snapshot.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now clixz-snapshot.timer
```

The same timer refreshes `manifest.json`.

## Development

```bash
make test       # run the test suite
make lint       # ruff on src/ and tests/ (pip install -e '.[dev]')
make build      # sdist + wheel into dist/
make release    # bump, tag, push and publish a GitHub release (CI publishes to PyPI)
```

Releasing: `make release [PART=patch|minor|major]` bumps `__version__`, tags,
pushes and publishes a GitHub release. The release — not the tag — triggers
`.github/workflows/publish.yml`, so GitHub and PyPI always show the same version.
