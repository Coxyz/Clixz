# Developer convenience targets. End users install with pipx (see README).

VERSION := $(shell python3 -c "import sys; sys.path.insert(0, 'src'); import clixz; print(clixz.__version__)")

# Which part of the version `make release` bumps: patch (default), minor, major.
PART ?= patch

.PHONY: help test lint build clean release

help:
	@echo "make test                  - run the test suite"
	@echo "make lint                  - run ruff on src/ and tests/"
	@echo "make build                 - build sdist + wheel into dist/"
	@echo "make clean                 - remove build artefacts"
	@echo "make release [PART=patch]  - bump v$(VERSION), commit, tag, push & publish a GitHub release (CI publishes to PyPI)"
	@echo "                             PART = patch | minor | major"

test:
	PYTHONPATH=src python3 -m pytest tests -q

lint:
	python3 -m ruff check src tests

build: clean
	python3 -m pip install --upgrade build
	python3 -m build

clean:
	rm -rf build dist src/*.egg-info

# Bump the version, commit it, create the vX.Y.Z tag, push branch + tag, and
# publish a GitHub release on that tag. The release triggers
# .github/workflows/publish.yml, which builds and publishes to PyPI; the tag
# alone publishes nothing. Requires bump-my-version (pip install -e '.[release]'
# or pipx install bump-my-version) and an authenticated gh.
release:
	@command -v gh >/dev/null 2>&1 || { \
		echo "gh not found — install the GitHub CLI and run: gh auth login"; exit 1; }
	@command -v bump-my-version >/dev/null 2>&1 || { \
		echo "bump-my-version not found — run: pipx install bump-my-version"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { \
		echo "Working tree is dirty — commit your changes first."; exit 1; }
	bump-my-version bump $(PART)
	git push --follow-tags origin $$(git rev-parse --abbrev-ref HEAD)
	gh release create $$(git describe --tags --abbrev=0) --verify-tag --generate-notes
	@echo ">>> Released $$(git describe --tags --abbrev=0) — publish.yml will publish it to PyPI."
