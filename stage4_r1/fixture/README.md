# Synthetic OpenCode Stage 4 fixture — public and credential-free

This is **not PCC source code**. Only synthetic data; no secrets, tokens, IDs, remote calls, or dependencies.

## Task for a real OpenCode model

Implement `src/selection.py::parse_selection` so all deterministic tests pass. Allowed code edit: `src/selection.py` only. Do not rewrite, remove, or edit tests. Do not create network calls, subprocesses, access environment variables, or modify unrelated files.

Success contract: parse ASCII decimal integers separated by commas and inclusive ascending ranges `a-b`; permit spaces; return a sorted unique list. Raise `ValueError` on malformed/empty/negative/reversed input. No external dependencies.

## Independent validator

From this directory, run `python3 -m unittest discover -s tests -v` with standard library only. A genuine AI execution must include recorded model identity, session ID, actual OpenCode tool/diff evidence, and the untouched test hashes. Reference implementation in a **separate private evaluator packet** is NEVER included in model-visible workspace.

## Safety

No GitHub Actions by default, no hosted CI, no private repositories, no model API keys, no checkout, no remote writes. Any future execution requires a separate Owner approval after pinning Ollama binaries, model digests and validating the offline topology.
