---
name: release
description: Cut a release of fastapi-rbac — bump version, update CHANGELOG, tag, and publish to PyPI. User-invoked only.
disable-model-invocation: true
---

# Release fastapi-rbac

Wraps the `make release` flow (test → build → publish) with version + changelog hygiene.
This publishes to PyPI — an irreversible, outward-facing action. Confirm each step; never skip tests.

## Preconditions
- Working tree is clean and on the default branch, fully pushed.
- `TWINE_USERNAME`/`TWINE_PASSWORD` (or `__token__` + PyPI token) available in the environment.

## Steps

1. **Pick the version.** Ask the user for the new version if not given (semver). Current version lives in `pyproject.toml` (`[project] version`).

2. **Bump** `version` in `pyproject.toml`.

3. **Update `CHANGELOG.md`.** Add a section for the new version dated today, summarizing changes since the last tag:
   ```
   git log --pretty=format:'- %s' <last-tag>..HEAD
   ```

4. **Verify — evidence before publishing:**
   ```
   make test      # or: pytest tests/ -v
   make lint      # ruff + black --check + isort --check + mypy
   ```
   Do not proceed if either fails. Report the actual output.

5. **Build:** `make build` (runs `clean` + `uv build`). Confirm `dist/` holds the sdist and wheel for the new version.

6. **Commit & tag:**
   ```
   git commit -am "Release vX.Y.Z"
   git tag vX.Y.Z
   ```

7. **Confirm with the user**, then **publish:** `make publish` (`twine upload dist/*`).

8. **Push:** `git push && git push --tags`. The `publish.yml` workflow may also trigger on the tag — check it doesn't double-publish.

## After
State the published version and the PyPI URL. If any step failed, stop and report exactly where.
