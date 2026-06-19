"""``coxyz build``: let a service build its own image from a Dockerfile.

A service is **build-enabled** when it carries a ``config/Dockerfile``. That file
is the single source of truth — its mere presence is the signal. coxyz then
grants the *komodo* principal (the group Komodo Periphery runs with) a recursive
**read** ACL on the service's ``config/`` and ``data/`` (existing tree + a default
ACL so edited sources stay readable), so Komodo can read the build context.

This keeps the per-category ``svc_*`` isolation intact: only the build-enabled
service's ``config/``/``data/`` become readable by komodo — nothing else — and
the grant is expressed as an ACL that ``coxyz check``/``apply`` audit, not as a
broad group membership on the Periphery container.

The build context should be the service's ``data/`` directory, with the
Dockerfile referenced out-of-context::

    docker build -f <svc>/config/Dockerfile <svc>/data

so ``.env`` and the rest of the service tree never enter the build context.
"""

from __future__ import annotations

from pathlib import Path

DOCKERFILE_NAME = "Dockerfile"

# Komodo only needs to READ the build context: read + traverse (x→X on dirs).
BUILD_PERMS = "rx"

# settings.principals key whose group Komodo Periphery runs as.
BUILD_PRINCIPAL = "komodo"


def dockerfile_path(svc_path: Path) -> Path:
    return svc_path / "config" / DOCKERFILE_NAME


def is_build_enabled(svc_path: Path) -> bool:
    """A service builds its own image iff it carries a ``config/Dockerfile``."""
    return dockerfile_path(svc_path).is_file()


def build_dirs(svc_path: Path) -> list[Path]:
    """The directories Komodo must read to build: ``config/`` and ``data/``."""
    return [p for p in (svc_path / "config", svc_path / "data") if p.is_dir()]


def dockerfile_template(service: str) -> str:
    """A commented Dockerfile skeleton (Node.js example) for a new build service."""
    return f"""\
# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile — image du service '{service}', construite par Komodo.
#
# coxyz a accordé au groupe komodo une ACL de lecture récursive sur config/ et
# data/ de ce service. Construis avec data/ comme CONTEXTE et ce fichier via -f :
#
#   docker build -f .../{service}/config/Dockerfile .../{service}/data
#
# Côté Komodo (ressource Build / Stack) :
#   context    = /srv/docker/<cat>/{service}/data
#   dockerfile = /srv/docker/<cat>/{service}/config/Dockerfile
#
# Les COPY ci-dessous sont donc relatifs à data/. Exemple Node.js — à adapter.
# ─────────────────────────────────────────────────────────────────────────────
FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

RUN addgroup -S app && adduser -S app -G app

COPY package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY src ./src

RUN chown -R app:app /app
USER app

EXPOSE 3000
CMD ["node", "src/index.js"]
"""
