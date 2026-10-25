# Transparency log restart, 25 October 2026

deRoute's transparency log was restarted from empty on 25 October 2026, before public launch. This note records why, and what the old log contained, so the restart itself is on the record.

## Why

Two problems were found while checking the first production deployment:

1. The code seeded an empty log with three entries dated 1 January, 1 February and 1 March 2025. They were not real checks: their evidence fields were hashes of fixed strings. That code has been removed (commit `931f404`); an empty log is now valid and the first entry is always the first real check.
2. A test run had written into the production database. It recorded one monitoring run with a placeholder Arc transaction (`0xdddd...dddd`) and a failed audit of `llama3-3-70b` that came from a test fixture, not from the real model. Tests now use a separate database the production credentials cannot write to.

## The old log

- Size: 10 entries (3 seeded, 6 from the test-triggered monitoring run, 1 real independent verification submitted with `scripts/drouter-cli.mjs verify --submit`).
- Root hash: `24e5ab4fa834cb3ed01001ddb16d4ec01f35fab9138bf6822149934be5dd0a99`
- Signing key: `657cf497484247e6ce5e4b28107c7a2c34d8adb9872b4d3ff9b194f7e95309ae`
- Anchored on Arc testnet (chain 5042002) in transaction `0xbdba12c6022b92bedc5e56e1a7f0c3f9009cc7ee211d2217dc7ae54cca38464a`.

That anchor stays on chain. Anyone comparing it with the current log will see the current log does not extend it; this note is the explanation.

## What was removed from the database

- All 10 entries and the tree head of the old log.
- The single test-triggered monitoring run.
- The fixture audit result for `llama3-3-70b` (dated 25 October 2025). The real audit result for `kimi-k3` was kept.
- The one independent verification submission, which was submitted again against the new log.

Payment and credit records were not touched.
