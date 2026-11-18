# Contributing to depscope

Thanks for considering a contribution.

## Before opening a pull request

1. Search existing issues and pull requests to avoid duplicated work.
2. For larger features or changes to risk classifications, open an issue describing the expected behavior and compatibility implications.
3. Keep changes focused; add or update tests for changed parsing, detection, output, or exit-code behavior.

## Local checks

Install a Rust toolchain compatible with the `rust-version` in [Cargo.toml](Cargo.toml), then run:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

These are suggested local checks; a successful PR still depends on the checks required by the repository at review time. Avoid unrelated dependency updates.

## Reporting problems

Use a normal GitHub issue for reproducible, non-sensitive bugs and feature proposals. For a potential security vulnerability, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

Please do not submit real secrets, private lockfiles, tokens, or confidential build logs. Security heuristic findings should be described as potential risks, not confirmed vulnerabilities without supporting evidence.
