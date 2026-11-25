"""``clixz repo``: the git checkouts under ``/opt/repos``.

Same idea as ``clixz image``: one directory per name under a base directory,
scaffolded and listed by clixz, and not audited — these are development
directories, not a service tree. v1 enforced an owner, a mode and an ACL on
them; since 2.4 an optional owner and mode are back (``repos.owner``,
``repos.mode``), the ACL is not. ``repo ls`` reports a checkout that drifted
and ``repo fix`` repairs it; ``clixz check`` still leaves /opt/repos alone.

The listing is read straight from ``.git/HEAD`` and ``.git/config`` rather than
by running git. ``clixz-mcpd`` runs this as an account that owns none of these
checkouts, and git refuses to operate on a repository owned by someone else.
"""

from __future__ import annotations

import configparser
import os
import re
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

# Same shape as an image name: it becomes a directory name.
REPO_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$")

# https://host/path, ssh://user@host/path, or the scp form git@host:path. The
# leading character is constrained so a URL can never be read as an option.
REPO_URL_RE = re.compile(
    r"^(https://|ssh://|[A-Za-z0-9_][A-Za-z0-9._-]*@)[A-Za-z0-9][A-Za-z0-9._~:/@%+-]*$"
)

DEFAULT_BRANCH = "main"


def validate_repo_name(name: str) -> None:
    if not REPO_NAME_RE.match(name):
        raise ValueError(
            f"Invalid repo name '{name}' "
            "(alphanumeric, '.', '-', '_', no leading/trailing punctuation)"
        )


def validate_repo_url(url: str) -> None:
    if not REPO_URL_RE.match(url):
        raise ValueError(
            f"Invalid repo URL '{url}' (expected https://…, ssh://… or user@host:path)"
        )


def public_url(url: str) -> str:
    """The remote URL without the credentials an https remote may embed.

    ``https://token@github.com/me/repo`` is a common way to store a token, and
    this listing is served to the MCP container.
    """
    if "://" not in url:
        return url  # scp form: the user part is a login name, not a secret
    parts = urlsplit(url)
    if parts.scheme in ("http", "https") and "@" in parts.netloc:
        return urlunsplit(parts._replace(netloc=parts.netloc.rpartition("@")[2]))
    return url


def _branch(git_dir: Path) -> str | None:
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if head.startswith("ref: refs/heads/"):
        return head[len("ref: refs/heads/"):]
    return head[:12] or None  # detached: the commit it sits on


def _origin(git_dir: Path) -> str | None:
    parser = configparser.ConfigParser(strict=False, interpolation=None)
    try:
        parser.read(git_dir / "config", encoding="utf-8")
    except (OSError, configparser.Error):
        return None
    section = 'remote "origin"'
    if parser.has_option(section, "url"):
        return public_url(parser.get(section, "url").strip())
    return None


def repo_info(path: Path) -> dict:
    git_dir = path / ".git"
    info: dict = {"name": path.name, "path": str(path), "git": git_dir.exists()}
    # A worktree or a submodule has a .git *file*; its branch lives elsewhere
    # and is not worth chasing for a listing.
    if git_dir.is_dir():
        info["branch"] = _branch(git_dir)
        info["remote"] = _origin(git_dir)
    return info


def list_repos(base: Path) -> list[dict]:
    if not base.is_dir():
        return []
    return [
        repo_info(entry)
        for entry in sorted(base.iterdir(), key=lambda p: p.name.lower())
        if entry.is_dir() and not entry.name.startswith(".")
    ]


def plan_add(base: Path, name: str, url: str | None = None,
             owner: str | None = None, mode: str | None = None) -> list[list[str]]:
    """The commands that create ``base/name``: a clone, or an empty repository.

    With an ``owner`` (or a ``mode``) configured, the new checkout is handed to
    it straight away, as ``plan_fix`` would.
    """
    validate_repo_name(name)
    target = base / name
    if target.exists():
        raise ValueError(f"{target} already exists.")
    if url:
        validate_repo_url(url)
        # `--` so that nothing after it can be taken for an option.
        commands = [["git", "clone", "--", url, str(target)]]
    else:
        commands = [["mkdir", "-p", str(target)],
                    ["git", "init", "--initial-branch", DEFAULT_BRANCH, str(target)]]
    return commands + fix_commands(target, owner, mode)


# ─── ownership ───────────────────────────────────────────────────────────────
#
# 2.4 brings back an owner and a mode on the checkouts — not the v1 ACL. The
# reason is Komodo: Periphery runs as root, so every file a pull or a rebase
# rewrites comes back root-owned, and the development account loses the
# checkout. `repo fix` repairs it; `repo hook` prints the command Komodo runs
# after its own pulls so that it does not happen in the first place.

# Octal, or a chmod symbolic spec such as "u+rwX,g+rwX,o-w". A whole tree holds
# executables and plain files, so a symbolic spec with X is the useful one.
MODE_RE = re.compile(r"^([0-7]{3,4}|[ugoa]*[-+=][rwxXst]*(,[ugoa]*[-+=][rwxXst]*)*)$")


def validate_mode(mode: str) -> None:
    if not MODE_RE.match(mode):
        raise ValueError(f"Invalid repos.mode '{mode}' (octal, or symbolic like u+rwX,g+rwX)")


def fix_commands(path: Path, owner: str | None, mode: str | None) -> list[list[str]]:
    """chown/chmod a checkout recursively, never following a symlink.

    ``chown -h`` changes a link rather than its target; ``chmod -R`` skips the
    links it meets on the way. The checkout itself must not be a link — the
    top argument is always followed — which ``plan_fix`` refuses.
    """
    commands: list[list[str]] = []
    if owner:
        commands.append(["chown", "-R", "-h", owner, str(path)])
    if mode:
        commands.append(["chmod", "-R", mode, str(path)])
    return commands


def foreign_entry(path: Path, uid: int, gid: int) -> Path | None:
    """The first entry under ``path`` not owned by ``uid:gid``, or None.

    Stops at the first one: ``repo ls`` asks this of every checkout, and a
    ``node_modules`` is not worth walking to the end.
    """
    def wrong(p: Path) -> bool:
        st = os.lstat(p)
        return st.st_uid != uid or st.st_gid != gid

    try:
        if wrong(path):
            return path
    except OSError:
        return None
    for root, dirs, names in os.walk(path):
        for entry in (*dirs, *names):
            candidate = Path(root) / entry
            try:
                if wrong(candidate):
                    return candidate
            except OSError:
                continue
    return None


def plan_fix(base: Path, name: str, owner: str | None,
             mode: str | None) -> list[list[str]]:
    validate_repo_name(name)
    target = base / name
    if target.is_symlink():
        raise ValueError(f"{target} is a symlink — clixz never follows one as root.")
    if not target.is_dir():
        raise ValueError(f"No such repo: {target}")
    return fix_commands(target, owner, mode)


def komodo_hook(uid: int, gid: int, mode: str | None) -> str:
    """The shell command a Komodo Repo runs after a clone or a pull.

    Numeric ids: the account names do not exist inside the Periphery container.
    Komodo runs it with the checkout as working directory. chmod goes first:
    once the files are handed over, root without CAP_FOWNER may not chmod them.
    """
    command = f"chown -R -h {uid}:{gid} ."
    if mode:
        command = f"chmod -R {mode} . && {command}"
    return command
