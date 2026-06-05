# Developer convenience targets. End users install with pipx (see README).

VERSION := $(shell python3 -c "import sys; sys.path.insert(0, 'src'); import coxyz; print(coxyz.__version__)")

# Which part of the version `make release` bumps: patch (default), minor, major.
PART ?= patch

.PHONY: help test build clean release

help:
	@echo "make test                  - run the test suite"
	@echo "make build                 - build sdist + wheel into dist/"
	@echo "make clean                 - remove build artefacts"
	@echo "make release [PART=patch]  - bump v$(VERSION), commit, tag & push (CI publishes to PyPI)"
	@echo "                             PART = patch | minor | major"

test:
	python3 -m unittest discover -s tests -v

build: clean
	python3 -m pip install --upgrade build
	python3 -m build

clean:
	rm -rf build dist src/*.egg-info

# Bump the version, commit it, create the vX.Y.Z tag, and push branch + tag.
# Pushing the tag triggers .github/workflows/publish.yml, which builds and
# publishes to PyPI. Requires bump-my-version (pip install -e '.[release]'
# or pipx install bump-my-version).
release:
	@command -v bump-my-version >/dev/null 2>&1 || { \
		echo "bump-my-version not found — run: pipx install bump-my-version"; exit 1; }
	@git diff --quiet && git diff --cached --quiet || { \
		echo "Working tree is dirty — commit your changes first."; exit 1; }
	bump-my-version bump $(PART)
	git push --follow-tags origin $$(git rev-parse --abbrev-ref HEAD)
	@echo ">>> Pushed $$(git describe --tags --abbrev=0) — publish.yml will release it to PyPI."
