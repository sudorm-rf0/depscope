# Security Policy

## Reporting a vulnerability

Please **do not** file a public GitHub issue for a suspected security vulnerability.

Use [GitHub's private vulnerability reporting](https://github.com/sudorm-rf0/depscope/security/advisories/new) if enabled. If the private reporting form is unavailable, contact the repository maintainer privately through an established channel before disclosing sensitive details.

Include the affected version or commit, a minimal reproduction, impact, and any relevant evidence. Do not include credentials, proprietary lockfiles, or other secrets.

We will investigate reports as resources permit. No response-time or disclosure deadline is guaranteed.

## Scope and limitations

depscope analyzes Rust dependency metadata using deterministic heuristics. Risk classifications are **signals for review**, not proof of an exploitable vulnerability, and they do not replace a vulnerability advisory database, source audit, or independent security review.

Review findings in context before using them to block releases. Avoid uploading private `Cargo.lock` files or sensitive build data to public issues.
