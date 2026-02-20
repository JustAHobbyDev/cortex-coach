# Quickstart

Assumption: `cortex-coach` is installed and on your `PATH`.

## External Project Example (Copy/Paste)

```bash
mkdir -p ~/projects/acme-admin
cd ~/projects/acme-admin
cortex-coach init \
  --project-dir . \
  --project-id acme_admin \
  --project-name "Acme Admin Dashboard"
cortex-coach coach --project-dir .
cortex-coach audit --project-dir .
```

## 1) Initialize a Project

```bash
cortex-coach init \
  --project-dir /path/to/project \
  --project-id my_project \
  --project-name "My Project"
```

Equivalent `just` recipe:

```bash
just coach-init /path/to/project my_project "My Project"
```

## 2) Run a Coach Cycle

```bash
cortex-coach coach \
  --project-dir /path/to/project
```

Equivalent:

```bash
just coach-cycle /path/to/project
```

## 3) Run an Audit

```bash
cortex-coach audit \
  --project-dir /path/to/project
```

Equivalent:

```bash
just coach-audit /path/to/project
```

## 4) Optional: Apply Drafts

```bash
cortex-coach coach \
  --project-dir /path/to/project \
  --apply \
  --apply-scope direction,governance
```

## If `cortex-coach` Is Not Installed

Use:

```bash
uv run python3 scripts/cortex_project_coach_v0.py <command> ...
```

## Expected Output Location

Inside the target project:

- `.cortex/manifest_v0.json`
- `.cortex/artifacts/*`
- `.cortex/prompts/*`
- `.cortex/reports/*`
