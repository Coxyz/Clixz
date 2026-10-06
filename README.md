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

## What changed in 2.3

2.0 made the MCP side read-only: the model proposed a plan, the operator typed
the command. 2.3 lets a plan prepared through the MCP server be **applied**
there, once the operator approves the `plan_apply` call in the Claude client —
without bringing back a long-running root daemon:

| 2.2 | 2.3 |
|---|---|
| Mutations planned, then typed by hand | Service plans (`new`, `edit`, `fix`, `rm`) stored by root and applied on approval |
| `clixz new` writes a template | `clixz new`/`edit` also take your compose and service.yaml, and refuse an unaccepted lint error |
| A timer copied the proxy database every 15 min | `exposed` reads it at the moment of the question |
| Units copied by hand from `deploy/` | `clixz daemon install` writes the units the package ships |
| — | `clixz todo`: what is left to do, shared with the AI |
| — | A new service's stack is created in Komodo (not deployed) |

The design is in `docs/specs/2026-10-06-clixz-2.3.md`.

## Install

Published on PyPI as [`clixz`](https://pypi.org/project/clixz/). Write commands
need root (`chown`/`chmod`), so install it system-wide:

```bash
sudo sh -c 'umask 022 && pipx install --global clixz'
sudo clixz daemon install   # the MCP gateway and the root applier (optional)
sudo clixz upgrade          # every later upgrade
```

The `umask` matters on a hardened host: with `UMASK 027` in `/etc/login.defs`,
pipx and uv create an environment only root can read, and `clixz` then fails
with "permission denied" for everyone else — including `clixz-mcpd`.
`clixz upgrade` sets it for you and calls the installer that put clixz there
(pipx or uv), so there is nothing to remember after the first install. It asks
PyPI for the latest release and installs it with caching off — a release minutes
old is otherwise not seen — then runs `clixz daemon install` from the new
version. `clixz-mcpd` also restarts by itself within 30 s of any upgrade, by
whatever route.

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
clixz exposed                   # what NPM publishes vs what service.yaml declares (sudo)
clixz rules                     # the compose rules in effect, and what is ignored

# write  (each accepts --plan: prints what it would do, writes nothing)
clixz new apps/myapp [--compose F] [--service-file F]   # tree + compose + .env + service.yaml
clixz edit apps/myapp --compose F                       # the old file goes to .archive/
clixz fix [service]             # repair ownership and modes
clixz rm apps/myapp             # archive under .archive/  (--force deletes, TTY only)
clixz category add media        # system account + directory + config entry
clixz plan ls|show|apply|drop   # plans prepared through the MCP server

# to do — the same list the AI reads and writes
clixz todo ls [--all]           # todo and doing, by default
clixz todo add "title" -d "description"
clixz todo start|done|archive|rm <id>
clixz todo edit <id>            # $EDITOR, or --title / -d / --state

# housekeeping
clixz meta [service] [--scaffold]
clixz manifest [--dry-run]
clixz image add|rm|ls <name>    # build contexts under /opt/images
clixz repo add|rm|ls <name>     # git checkouts under /opt/repos (add --url clones)
clixz category ls
clixz rules --edit | --edit-ignore
clixz config [--migrate] [--edit]
clixz mcp                       # what the MCP gateway runs, relays, and never does
clixz daemon install|status|restart
clixz upgrade [--plan]          # latest release, no cache, then its units
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

`manifest.json` is generated next to the config rather than inside a service,
because it describes the whole tree; the container that serves it mounts it
read-only from there. `clixz manifest` writes it, and so does every applied plan
that touches a `service.yaml`.

clixz's own state — the stored plans and the todo — lives in `/var/lib/clixz`
(`state: {dir, group}`): `plans/` is root's alone, `todo.yaml` is readable by
everyone and writable by the `group` (default `docker`, the operators).

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

Two halves, one boundary:

- **`clixz-mcpd`** — unprivileged, on a Unix socket mounted into the MCP
  container. Reads run the CLI, here. The unit keeps `ProtectSystem=strict` and
  `ReadOnlyPaths=/srv/docker`: it writes nothing itself.
- **`clixz-apply`** — root, started by systemd **for one request**
  (`clixz-apply.socket`, `Accept=yes`) and gone with it. Only `clixz-mcpd` can
  reach its socket. It computes and stores service plans, applies them, reads
  the proxy database live for `exposed`, and writes the todo. It validates every
  field again, and its sandbox can write the tree, its state directory and the
  manifest — not the config, not `lint.yaml`, not `ignore.yaml`.

A service plan is the unit of trust:

1. the model asks for it (`service_create`, `service_update`, `service_fix`,
   `service_delete`); clixz computes it — commands, diff, lint — and refuses it
   when the result carries an error-level lint finding that `ignore.yaml` does
   not accept;
2. root stores it under a random id in `/var/lib/clixz/plans/` (0700): nothing
   else can write a plan, so an id is proof clixz computed it;
3. the operator approves `plan_apply` in the Claude client;
4. clixz recomputes it against the disk, refuses if the service changed in
   between, applies it once, refreshes the manifest, and — for a new service —
   creates its stack in Komodo (configured, not deployed).

`.env` is never written by a plan, `rm --force` and `repo rm` stay at the
keyboard, and category and repo plans are only ever printed. `clixz mcp` lists
exactly what each half accepts.

```bash
sudo clixz daemon install    # renders the units from the config, starts what is new
clixz daemon status          # are the installed units this version's? are they running?
```

The gateway's groups are the categories' groups, computed at install time: after
`clixz category add`, run `sudo clixz daemon install` again.

To create stacks in Komodo, give clixz an API key of a Komodo service user
(non-admin) in `/etc/clixz/komodo.yaml` (`key:`, `secret:`, root 0600) and add a
`komodo:` section to the config (see `default_config.yaml`).

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
