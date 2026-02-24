# Agent Context Loader

`agent_context_loader_v0` builds a bounded context bundle for unfamiliar agents.
Recommended entrypoint is now `cortex-coach context-load`.

It loads:
1. control-plane artifacts first (`manifest`, latest audit reports)
2. latest promoted decision artifacts (`.cortex/artifacts/decisions/decision_*_v*.md`)
3. task-relevant files next (`direction`, `governance`, `design`, `spec`)
4. optional adapter slice last (read-only bounded `beads_file` payloads)

## Preferred CLI Usage

```bash
cortex-coach context-load \
  --project-dir /path/to/project \
  --task "design drift" \
  --adapter-mode off \
  --max-files 10 \
  --max-chars-per-file 2000 \
  --fallback-mode priority \
  --assets-dir /path/to/cortex-assets
```

Adapter enrichment example:

```bash
cortex-coach context-load \
  --project-dir /path/to/project \
  --task "governance blocker" \
  --adapter-mode beads_file \
  --adapter-file .cortex/reports/beads_adapter.json \
  --adapter-max-items 4
```

## Script Usage

```bash
uv run python3 scripts/agent_context_loader_v0.py \
  --project-dir /path/to/project \
  --task "design drift" \
  --max-files 10 \
  --max-chars-per-file 2000
```

Save to file:

```bash
uv run python3 scripts/agent_context_loader_v0.py \
  --project-dir /path/to/project \
  --task "governance updates" \
  --out-file .cortex/reports/agent_context_bundle_v0.json
```

## `just` Wrapper

```bash
just coach-context-load /path/to/project design 10 2000
```

Policy recommendation:

```bash
just coach-context-policy /path/to/project
```

## Output

JSON with:
- selected files (ordered)
- selection rationale (`selected_by`)
- per-file truncation flags
- warnings for missing control-plane files
- adapter status metadata (`adapter.mode`, `adapter.status`, selected/candidate counts)
- fallback metadata (`fallback_level`, `fallback_attempts`)

Use this bundle as the direct input context for agents.
