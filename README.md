# depscope

Scope your Rust dependency supply chain from a single `Cargo.lock`.

`depscope` parses a lockfile into a source-agnostic view and applies a small,
deterministic set of supply-chain risk heuristics. It is dependency-light,
`#![forbid(unsafe_code)]`, and drives both a human-readable CLI and a CI gate
from the same pure logic.

## Why

A `Cargo.lock` is the ground truth of what actually ships. Before trusting a
build — or auditing one — it helps to know:

- which packages come from **Git** instead of crates.io,
- which registry packages are **missing a checksum** (integrity can't be verified),
- which crates are pinned to **multiple major versions** (wider attack surface),
- which dependencies are still **pre-1.0** (unstable API).

`depscope` answers those questions in one command and exits non-zero when a
CI gate finds something it shouldn't.

## Install

```bash
cargo install depscope
```

## Usage

```bash
# Count packages grouped by source
depscope scan path/to/Cargo.lock

# List detected risks (human-readable)
depscope risks path/to/Cargo.lock

# Same, as JSON
depscope risks path/to/Cargo.lock --json

# Emit a minimal CycloneDX 1.5 SBOM
depscope sbom path/to/Cargo.lock

# CI gate: non-zero exit if any High/Medium risk is found
depscope check path/to/Cargo.lock
```

### Example

```
$ depscope scan Cargo.lock
Scanned 333 packages from Cargo.lock
  registry   332
  root       1

$ depscope risks Cargo.lock
[MEDIUM] syn@2.0.119, 3.0.0 — Multiple versions locked (2.0.119, 3.0.0); consider unifying to reduce attack surface and bloat.
[LOW] aes@0.9.2 — Pre-1.0 version — API is not stabilized; upgrades may break.
```

## Risk levels

| Level   | Triggers                                                        |
|---------|-----------------------------------------------------------------|
| `HIGH`  | Git-sourced dependency; registry package missing a checksum     |
| `MEDIUM`| Local path dependency; non-standard source; duplicate versions  |
| `LOW`   | Pre-1.0 version                                                 |

## Library

The analysis is exposed as a small, `#![forbid(unsafe_code)]` library so it can
be embedded or tested directly:

```rust
use depscope::{from_lockfile, detect_risks};

let pkgs = from_lockfile("Cargo.lock")?;
let risks = detect_risks(&pkgs);
```

## License

Licensed under either of MIT or Apache-2.0 at your option.
