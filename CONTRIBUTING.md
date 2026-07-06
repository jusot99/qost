# Contributing

## Setup

```bash
git clone https://github.com/jusot99/qost.git
cd qost
pip install -e ".[dev]"
```

## Code Quality

All checks must pass before submitting a PR:

```bash
ruff check src/qost/
python3 -m mypy src/qost/
python3 -m pytest tests/
```

| Check | Purpose |
|-------|---------|
| **ruff** | Enforces style and catches common mistakes |
| **mypy** | Ensures type correctness |
| **pytest** | Runs the 170+ test suite |

> [!TIP]
> **Run all three checks locally** before opening a PR. CI runs them automatically, but fixing issues early saves time.

## Pull Request Process

1. Create a feature branch from `main`.
2. Make your changes ➜ keep them focused on one issue.
3. Run all three checks above. Fix any failures.
4. Open a PR with a clear description of what and why.
5. CI will run the checks automatically. The PR won't be merged until all pass.

## Guidelines

- Follow the existing code style. When in doubt, match surrounding code.
- Use `logging` instead of bare `print()` or `pass` in except blocks.
- Add tests for new features. Use `pytest-asyncio` for async functions.
- Don't introduce new dependencies without discussing it first.
- Keep `pyproject.toml` as the single source of truth for version and deps.

> [!NOTE]
> This is a **security tool**. Be extra careful when handling credentials, network data, or system-level operations in your contributions.
