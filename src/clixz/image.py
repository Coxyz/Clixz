"""``clixz image``: manage self-built image build contexts under ``/opt/images``.

A self-built image lives in its own directory ``<images.dir>/<name>/`` holding
the Dockerfile and sources — **separate** from the service tree under
``root_dir``. The matching service in ``/srv/docker`` stays empty (it just
*consumes* the built image, like any third-party image).

clixz scaffolds the directory and a Dockerfile, and stops there. v1 also
enforced an owner and a mode on every context; the audit found that rule was
the source of the only permanent drift in ``clixz check``, protecting nothing —
these are development directories, not a service tree.
"""

from __future__ import annotations

import re

# Docker image/repo names: alphanumeric plus . _ - (no leading/trailing punct).
IMAGE_NAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$")

DOCKERFILE_NAME = "Dockerfile"


def validate_image_name(name: str) -> None:
    if not IMAGE_NAME_RE.match(name):
        raise ValueError(
            f"Invalid image name '{name}' "
            "(alphanumeric, '.', '-', '_', no leading/trailing punctuation)"
        )


def dockerfile_template(name: str) -> str:
    """A commented Dockerfile skeleton (Node.js example) for a new image."""
    return f"""\
# ─────────────────────────────────────────────────────────────────────────────
# Dockerfile — image '{name}', construite par Komodo depuis /opt/images/{name}.
#
# Le CONTEXTE de build est ce dossier (/opt/images/{name}). Le service
# /srv/docker correspondant ne contient PAS de source : il consomme l'image.
#
# Côté Komodo (ressource Build / Stack) :
#   context    = /opt/images/{name}
#   dockerfile = /opt/images/{name}/Dockerfile
#
# Exemple Node.js — à adapter.
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
