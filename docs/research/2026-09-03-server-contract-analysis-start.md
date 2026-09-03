# 2026-09-03 — server-contract analysis branch start

Branch:

```text
analysis/server-contracts-11.6.3
```

Base:

```text
d1d22361df4da74da4ef4bdf41eb420b846bc072
```

## Decision

For the independent preservation-server goal, switch from purely blocker-driven
reverse engineering to a broad **server-facing contract recovery** pass.

Do not attempt to understand every IL2CPP function. Recover all network-facing task,
request, response, server-derived state and consumer semantics first.

## Implemented in the first branch commit

- `scripts/analyze-server-contracts.py`
  - parses `dump.cs` type inheritance;
  - enumerates `NetworkTask` descendants;
  - maps Il2CppDumper `ScriptMethod` entries to task types;
  - classifies request/response-role methods;
  - scans exact arm64 method bodies for managed string references;
  - emits only bounded contract-like paths/field/header identifiers;
  - optionally consumes a local complete `final_map.json` for candidate endpoint
    correlation;
  - labels candidate bindings by evidence source rather than presenting heuristics
    as proof.

- `.github/workflows/analyze-server-contracts.yml`
  - downloads the same frozen 11.6.3 XAPK used by existing exact-specimen analysis;
  - verifies frozen XAPK / arm64 IL2CPP / metadata hashes;
  - runs Il2CppDumper ephemerally;
  - runs the broad contract analyzer;
  - deletes all raw specimen/decompiler material;
  - uploads only sanitized JSON/Markdown reports.

- `CLIENT_CONTRACT_HANDOFF.md`
  - branch-specific continuation instructions and phase plan.

- `docs/server-facing-contract-analysis.md`
  - rationale, evidence rules and C0-C5 roadmap.

## Pending evidence

The first CI run must establish the real aggregate C0 counts. Do not insert guessed
counts here.

After the workflow is green, append:

```text
workflow run:
NetworkTask descendants:
task methods:
request-role methods:
response-role methods:
tasks with contract literals:
known false-negative classes:
known false-positive classes:
```

Then proceed to C1 endpoint binding before adding more one-off parser scripts.
