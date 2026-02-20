# Install

## Prerequisites

- Python 3.10+
- `uv` (recommended)
- `just` (recommended for task shortcuts)

## From Source (Current Recommended)

Clone the repository:

```bash
git clone https://github.com/JustAHobbyDev/cortex.git
cd cortex
```

Install the CLI:

```bash
uv pip install -e .
```

Run:

```bash
cortex-coach --help
```

## No-Install Run Mode (Fallback)

If you do not want to install, run directly from repo root:

```bash
uv run python3 scripts/cortex_project_coach_v0.py --help
```

Or use `just` recipes:

```bash
just --list
```
