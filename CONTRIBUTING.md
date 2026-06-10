# Contributing

jusotscope is an open-source project. Contributions are welcome.

## Getting Started

1. Fork the repo
2. Install in editable mode: `pip install -e .`
3. Run tests: `python -m pytest tests/`

## Guidelines

- Keep it simple — no unnecessary dependencies
- CLI tools go under `src/jusotscope/<tool>/`
- Shared utilities go in `_shared/`
- Every module has a `register(subparsers)` function
- Format with `ruff` if possible
