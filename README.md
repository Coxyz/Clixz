# coxyz

CLI to manage Docker services under `/srv/docker` following coxyz rules
(ownership, permissions, POSIX ACLs).

Replaces `check_fix_permission.zsh` + `services.zsh` with a single typed Python
tool driven by a YAML configuration.

## Install

coxyz is published on PyPI as the [`coxyz-cli`](https://pypi.org/project/coxyz-cli/)
package — the installed command stays `coxyz`. It needs root for most operations
(`chown` / `setfacl`), so install it **system-wide** and run it with `sudo`.

```bash
sudo apt install -y pipx

# Install into an isolated venv under /opt, with the binary on the system PATH.
sudo env PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install coxyz-cli
```

> With pipx ≥ 1.5 you can use the shorter `sudo pipx install --global coxyz-cli`
> instead. Debian 12 ships pipx 1.4.3, which needs the `env` form above.

Then run:

```bash
sudo coxyz check
```

Optionally enable shell completion for your user (no sudo):

```bash
coxyz --install-completion
```

### Update

```bash
sudo env PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx upgrade coxyz-cli
```

### Migrating from a manual install

Earlier setups used hand-written `coxyz` / `coxyz-update` wrapper scripts and a
venv in `/usr/local/libexec/coxyz`. Remove them before installing from PyPI:

```bash
sudo rm -f  /usr/local/bin/coxyz /usr/local/bin/coxyz-update
sudo rm -rf /usr/local/libexec/coxyz
rm -f ~/.zsh/completions/_coxyz ~/.zcompdump*   # stale completion artefacts
```

(`/etc/coxyz/config.yaml` is kept — it is your configuration, not part of the
install.)

## Configuration

`coxyz` reads, in order: `--config FILE`, `/etc/coxyz/config.yaml`,
`~/.config/coxyz/config.yaml`, then the bundled defaults.

```bash
coxyz show-config       # inspect the resolved config
sudo coxyz edit         # create/edit /etc/coxyz/config.yaml (seeded from defaults)
```

Example excludes in `config.yaml`:

```yaml
exclude:
  - "*.bak"
  - "*/do_not_touch/"
```

## Commands

```bash
coxyz list                      # list services with image, ports, status
coxyz list -C apps              # filter by category

coxyz check                     # validate config + audit all services (exit 1 on drift)
coxyz check bitwarden           # audit one service
coxyz check apps/bitwarden -v   # verbose (show OK findings too)

coxyz apply                     # preview planned fixes, confirm, then apply
coxyz apply bitwarden -y

coxyz create                    # interactive prompts, confirm, then create
coxyz create -C apps -n myapp -y

coxyz manifest                  # aggregate every service.yaml → API manifest
coxyz manifest --dry-run        # validate + preview without writing
coxyz meta scaffold apps/nginx  # add a service.yaml template to an existing service
coxyz meta validate             # validate all service.yaml descriptors

coxyz dev add apps/nginx        # make a service editable via code-server
coxyz dev remove apps/nginx     # revoke it
coxyz dev list                  # show dev-enabled services

coxyz show-config               # print resolved config
coxyz edit                      # edit /etc/coxyz/config.yaml
```

Most operations require root (`chown` / `setfacl`), so prefix with `sudo`.

## How it works

- **Config** (`/etc/coxyz/config.yaml` or bundled default) defines:
  - root dir, ACL principals, authorized categories
  - `exclude` glob patterns to ignore paths during audit/apply
  - per-path rules: mode, ACL perms, optional owner override, audit-only flag
- **`check`**: read-only. First validates the config's *structure* (missing keys,
  bad values, sections nested in the wrong place), then audits permissions/ACL —
  reporting drift and warn-only (`data/`, `.env`).
- **`apply`**: shows planned changes, asks for confirmation, then applies fixes.
  - Touches: category/service dirs, `compose.yaml`, the `config/` directory.
  - Never touches: `data/` contents, `.env` files (audit-only).
  - Creates required missing directories before applying path fixes.
- **Dev-mode awareness**: both `check` and `apply` first read the code-server
  compose to learn which services are dev-enabled. For those services the dev
  principal's recursive ACL **and** the default ACL on `config/` and `data/` are
  treated as *expected* — not drift — and any fix is non-destructive (it never
  uses `setfacl --set`/`-b`, which would wipe the dev grant). A leftover dev ACL
  on a service that is *not* dev-enabled is still correctly flagged for removal.
- **`create`**: scaffolds `<category>/<service>/{config/,data/}` plus **empty**
  `compose.yaml` and `.env`, a `service.yaml` template, with correct owners +
  perms + ACL. It does not template `compose.yaml` — you fill it in. Then it
  refreshes the dashboard manifest.
- **`service.yaml`** (dashboard descriptor): a per-service file describing how
  the service appears on the coxyz dashboard — `name`, `icon`, `description`,
  `public` (true ⇒ exposed by the API, false ⇒ hidden entirely), optional
  `url`/`kind`/`container`/`tags`, and a `details:` block (summary, features,
  internal `ports`, `depends_on`, `tech`). Put only **non-sensitive** info here.
  Its permissions are governed by the `service_file` rule (default `640`).
- **`manifest`**: reads every `service.yaml`, validates it, and aggregates the
  **public** ones into the JSON file at `api.manifest`
  (default `/srv/docker/apps/api/data/manifest.json`, mode `644`), which the
  coxyz-api container mounts read-only and serves at `/api/services`. Private
  descriptors never reach the manifest.
- **`meta scaffold <service>`**: drops a `service.yaml` template into an existing
  service (won't overwrite). **`meta validate`**: validates descriptors only.
- **`check`** also validates every `service.yaml` (a missing one is a warning; a
  malformed one is an error that fails the check).
- **`list`**: parses each `compose.yaml` for image/ports and runs an audit
  to show a compliance status.
- **`dev add/remove/list`**: makes a service editable through code-server.
  `add` grants the `dev.principal` group (default `boxyz_dev`) a recursive
  read/write ACL on the service's `config/` and `data/` (existing files **and**
  a default ACL so new files inherit it), and mounts both dirs into the
  code-server compose under `/workspace/services/<category>/<service>/`. `remove`
  revokes *only* that group's ACL entry and unmounts. The managed mounts live in
  a marker-delimited block (`# >>> coxyz dev ... >>>`) that is the single source
  of truth — `list` reads it; everything else in the compose is left untouched.
  Configured under the `dev:` key in `config.yaml`.

### ACL handling

A path governed by an ACL rule is brought to compliance with a **single
`setfacl --set` call** that writes the base entries (`u::`/`g::`/`o::`, i.e. the
octal mode) and the named entries together. `setfacl` then recomputes the ACL
*mask* as the union of the owning group and every named entry, so each entry
stays fully effective — `getfacl` never shows an `#effective:` restriction.

`coxyz` deliberately never runs `chmod` on an ACL-managed path: a `chmod` after
a `setfacl` would rewrite the mask instead of the group bits and silently shrink
the effective rights of every named entry.

One consequence: when a named entry grants more than the owning group (e.g. a
principal with `rw` on a `750` directory), the mask widens and `ls -l` shows the
wider group digit (`770`). That is correct POSIX behaviour — the audit compares
ACL entries, not the displayed mode.

## File layout (enforced)

```
/srv/docker/<category>/<service>/
├── compose.yaml      660  svc_<cat>:svc_<cat>  + ACL principals
├── config/           750  svc_<cat>:svc_<cat>  + ACL principals
│   └── ...           (contents not audited)
└── data/             750  svc_<cat>:svc_<cat>  no ACL (audit only)
```

## Development

```bash
make test       # run the test suite
make build      # build sdist + wheel into dist/
make release    # tag the current version and push (CI publishes to PyPI)
```

Releasing: bump `__version__` in `src/coxyz/__init__.py`, commit, then
`make release`. The tag `vX.Y.Z` triggers `.github/workflows/publish.yml`,
which publishes to PyPI via Trusted Publishing.
