# Install

## Prerequisites

- Python 3.10+
- `uv` (recommended)

## Install Standalone CLI (Recommended)

Install latest release:

```bash
uv tool install git+https://github.com/JustAHobbyDev/cortex-coach.git
```

Run:

```bash
cortex-coach --help
```

## Install Specific Version

```bash
uv tool install git+https://github.com/JustAHobbyDev/cortex-coach.git@v0.1.0
```

## Pip Fallback

```bash
pip install git+https://github.com/JustAHobbyDev/cortex-coach.git@v0.1.0
```

## From Source (Development)

```bash
git clone https://github.com/JustAHobbyDev/cortex-coach.git
cd cortex-coach
uv sync --group dev
uv run cortex-coach --help
```

## Script Mode (Fallback)

If needed, run directly from the local repo:

```bash
uv run python3 cortex_coach/coach.py --help
```
