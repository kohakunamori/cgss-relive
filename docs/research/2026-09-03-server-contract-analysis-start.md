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

Commit:

```text
ae5bea4bd071fc3f42f570f7d33648a942da4e4a
```

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

## First exact-specimen result

Workflow:

```text
Analyze final 11.6.3 server contracts
run 33778354480
artifact final-client-server-contract-inventory
artifact id 9902546755
artifact sha256 1d6b8c768e1e64395393097eaf57fa8d40b63a54cf8c84b432c034b509712c5e
```

All substantive steps passed: frozen specimen verification, Il2CppDumper, broad
contract scan, clean-room deletion gate and sanitized artifact upload.

C0 aggregate result:

```text
NetworkTask descendants          502
mapped task methods             1596
request-role methods             402
response-role methods            513
tasks with contract literals     359
tasks with zero mapped methods     0
api map loaded                 false
endpoint candidates                0  (expected while no complete map is supplied)
```

The pass is not merely finding bootstrap classes. High-signal recovered examples
include:

```text
Stage.LoadTask
Stage.LiveStartTask
Stage.LiveEndTask
Stage.StoryStartTask
Stage.GachaExeTask
Stage.HomeCustomizeUpdateTask
Cute.VersionCheckTask
```

Representative parser breadth from the sanitized output:

```text
Stage.LoadTask       113 contract-like literals
Stage.LiveEndTask    127 contract-like literals
Stage.LiveStartTask    5 contract-like literals
Stage.StoryStartTask   5 contract-like literals
Stage.GachaExeTask    33 contract-like literals
```

These counts are inventory evidence, not proof that every emitted identifier is a
required response field. C2/C3 still need to distinguish hard reads, conditional
reads, request writes and shared helper literals.

## C0 conclusion

**C0 broad NetworkTask inventory is complete enough to proceed.**

There are no known zero-method false negatives in the selected NetworkTask set. The
502 task types should not be compared one-to-one with the 516 A-group API entries:
path aliases, shared task bases, nonstandard task construction and the separate
VR/login group make those different domains.

## Next bottleneck: C1 endpoint binding

The first run intentionally had no `final_map.json`, so `endpoint_candidates=0` is
expected. C1 must now bind the already-established final ApiType identities to these
tasks without guessing.

Priority order:

1. derive/ingest sanitized final `(group,key,name,path)` metadata;
2. bind exact literal/path or ApiType key flows first;
3. use normalized task/enum names only as `candidate` evidence;
4. preserve legitimate path aliases by canonical `(group,key)` identity;
5. report unresolved bindings explicitly.

Do not return to one-off Home parser work unless C1/C2 discovers a concrete blocker
that the broad pass cannot represent.
