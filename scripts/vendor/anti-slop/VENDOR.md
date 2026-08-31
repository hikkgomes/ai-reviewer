# Vendored anti-slop

This directory vendors the source rules from [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop).

- Upstream commit: `6d538555cb151d4121ed51a27db81890eacf8ae9`
- Oxlint: `1.78.0`
- `@oxlint/plugins`: `1.78.0`
- ast-grep: `@ast-grep/cli` `0.45.2`
- ast-grep licence: MIT. Upstream project: [ast-grep/ast-grep](https://github.com/ast-grep/ast-grep).
- ast-grep provides the skill-local structural backends for Go, Rust, C, C++,
  Java, and C#. It is used for bounded syntax evidence only, not semantic
  type or control-flow proof.
- Licence: the upstream MIT licence is retained in `LICENSE`.
- Gate A: Oxlint 1.78 resolved `./index.ts` relative to this directory, emitted
  `message`, `code`, `filename`, and `labels[].span.{line,column}`, and emitted
  no planted default diagnostic with `categories.correctness: off`.

To re-vendor or upgrade, inspect the upstream source and the exact package
version, run `npm install --save-dev --save-exact` followed by `npm ci`, verify
`node_modules/.bin/oxlint --version` and `node_modules/.bin/ast-grep --version`,
run the Gate A check and the native ast-grep rule tests, then record the
version, lock-file change, and every intentional local source change here.
Reviews use only these skill-local binaries and never search `PATH`.

## Local patches

The `ast-grep/` project contains Dissect-owned structural rule packs and
fixtures for Go, Rust, C, C++, Java, and C#. They are not upstream Oxlint
patches and are reviewed under `reference/anti-slop-rule-contract.md`.
