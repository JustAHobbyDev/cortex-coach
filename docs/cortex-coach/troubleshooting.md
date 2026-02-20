# Troubleshooting

## `missing manifest: .../.cortex/manifest_v0.json`

Run `init` first:

```bash
just coach-init /path/to/project my_project "My Project"
```

## `lock_timeout: unable to acquire .cortex lock`

Another process holds the lock, or a stale lock exists.

Options:

1. Wait and retry.
2. Increase timeout:

```bash
cortex-coach audit \
  --project-dir /path/to/project \
  --lock-timeout-seconds 30
```

3. Force unlock (use carefully):

```bash
cortex-coach audit \
  --project-dir /path/to/project \
  --force-unlock
```

## Invalid apply scope

Error example:

`invalid apply scope(s): invalid; valid: design, direction, governance`

Use only supported values in `--apply-scope`.

## `audit-needed` always says `required`

This usually means high-risk files are dirty (for example `specs/`, `policies/`, `.cortex/manifest_v0.json`, or coach scripts).

Inspect details:

```bash
cortex-coach audit-needed --project-dir /path/to/project --format json
```

If expected, run audit and continue:

```bash
cortex-coach audit --project-dir /path/to/project
```

## `uv` permission/cache issues

If `uv` fails in restricted environments, run directly with Python:

```bash
python3 scripts/cortex_project_coach_v0.py --help
```

Then return to `uv` in normal environments.
