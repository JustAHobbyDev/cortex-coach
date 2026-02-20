# Migration Matrix (Cortex -> cortex-coach)

Purpose: track what moved to standalone `cortex-coach` runtime ownership versus what remains Cortex-owned and imported as fixtures/contracts.

## Ownership Split

- Cortex-owned (source of truth): contract/assets definitions, governance policies, fixture exports.
- cortex-coach-owned: CLI/runtime behavior, checks, loader behavior, packaging, release/CI, coach docs/tests.

## Mapping

- `cortex/scripts/cortex_project_coach_v0.py` -> `cortex-coach/cortex_coach/coach.py` (runtime-owned)
- `cortex/scripts/agent_context_loader_v0.py` -> `cortex-coach/cortex_coach/agent_context_loader.py` (runtime-owned)
- `cortex/scripts/design_prompt_dsl_compile_v0.py` -> `cortex-coach/cortex_coach/design_prompt_dsl_compile.py` (runtime-owned)
- `cortex/tests/test_coach_*.py` -> `cortex-coach/tests/test_coach_*.py` (runtime test ownership)
- `cortex/docs/cortex-coach/*` -> `cortex-coach/docs/cortex-coach/*` (runtime docs ownership)
- `cortex/contracts/coach_asset_contract_v0.json` ->
  - bundled runtime default: `cortex-coach/cortex_coach/data/assets/contracts/coach_asset_contract_v0.json`
  - Cortex export fixture copy: `cortex-coach/fixtures/cortex_asset_bundle_v0/contracts/coach_asset_contract_v0.json`
- `cortex/templates/design_ontology_v0.schema.json` ->
  - bundled runtime default: `cortex-coach/cortex_coach/data/assets/templates/design_ontology_v0.schema.json`
  - Cortex export fixture copy: `cortex-coach/fixtures/cortex_asset_bundle_v0/templates/design_ontology_v0.schema.json`
- `cortex/templates/modern_web_design_vocabulary_v0.json` ->
  - bundled runtime default: `cortex-coach/cortex_coach/data/assets/templates/modern_web_design_vocabulary_v0.json`
  - Cortex export fixture copy: `cortex-coach/fixtures/cortex_asset_bundle_v0/templates/modern_web_design_vocabulary_v0.json`

## Compatibility Note

The runtime defaults to bundled package assets; maintainers can override via `--assets-dir` to test against newer Cortex-exported bundles.
