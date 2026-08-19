# Vendored anti-slop

This directory vendors the source rules from [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop).

- Upstream commit: `6d538555cb151d4121ed51a27db81890eacf8ae9`
- Oxlint: `1.78.0`
- `@oxlint/plugins`: `1.78.0`
- Licence: the upstream MIT licence is retained in `LICENSE`.
- Gate A: Oxlint 1.78 resolved `./index.ts` relative to this directory, emitted
  `message`, `code`, `filename`, and `labels[].span.{line,column}`, and emitted
  no planted default diagnostic with `categories.correctness: off`.

To re-vendor, inspect the upstream source at the desired commit, copy `src/` while excluding `*.test.ts`, update this SHA, run the Gate A end-to-end check, and regenerate `package-lock.json` with `npm install` in this directory. Record every intentional local source change in this file before editing a vendored rule. Do not edit vendored sources without a recorded local-patch entry.

## Local patches

None.
