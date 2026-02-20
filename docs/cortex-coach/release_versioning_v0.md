# Release & Versioning v0

## Version Source of Truth

- Package version is defined in `pyproject.toml` (`project.version`).
- Release tag must match package version exactly: `v<project.version>`.

Examples:
- `project.version = "0.1.0"` -> tag `v0.1.0`
- `project.version = "0.2.0rc1"` -> tag `v0.2.0rc1`

## Release Workflow

GitHub Actions workflow: `.github/workflows/release.yml`

Trigger:
- push tag matching `v*`

Behavior:
1. verifies tag matches `pyproject.toml` version
2. runs CI quality gate
3. builds `sdist` + `wheel`
4. publishes GitHub Release with generated notes and `dist/*` artifacts

## Maintainer Steps

1. Update `project.version` in `pyproject.toml`.
2. Commit and push to `main`.
3. Create and push release tag:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

4. Confirm release workflow succeeds in GitHub Actions.
