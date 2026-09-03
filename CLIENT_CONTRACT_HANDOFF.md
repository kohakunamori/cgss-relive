# CLIENT CONTRACT HANDOFF — CGSS 11.6.3

Authoritative continuation point for branch:

```text
analysis/server-contracts-11.6.3
```

Base when this branch was created:

```text
main d1d22361df4da74da4ef4bdf41eb420b846bc072
```

## Goal

Build the fastest path to a complete independent preservation server by recovering
the **entire server-facing contract surface** of the untouched final Android 11.6.3
client in broad static passes before implementing endpoints one blocker at a time.

This is deliberately narrower than "understand every IL2CPP method". Rendering,
animation, shaders, CRI internals and other purely local client logic are outside
this work unless they consume server-derived state.

## Existing facts — do not rediscover

Read `AGENT_HANDOFF.md` first. In particular:

- exact final specimen is frozen and hash-verified;
- Unity 2022.3.56f1 / IL2CPP metadata v31;
- transport codec and header semantics are already closed;
- final resource revision 10133800 and resource resolver are already closed;
- `/load/check` 214 semantics are closed;
- `/load/index` minimal parser/Home control flow is already reduced;
- a delivered final `ApiType.ApiList` map has 516 normal A-group entries plus
  22 VR/login entries; see `docs/api-map-11.6.3.md`;
- do not treat static/CI success as visible Home runtime success.

## New analysis strategy

The branch shifts from purely blocker-driven reverse engineering to:

```text
global-metadata.dat + libil2cpp.so
        -> all NetworkTask descendants
        -> request-side methods
        -> response Parse/CheckResult methods
        -> contract-like string/key references
        -> endpoint binding
        -> state writes / consumers
        -> generated local-server contracts
```

The first broad pass is implemented by:

```text
scripts/analyze-server-contracts.py
.github/workflows/analyze-server-contracts.yml
```

It emits only sanitized derived metadata. It must not commit or upload APK/XAPK,
`libil2cpp.so`, metadata, `dump.cs`, `script.json`, `stringliteral.json`, game
databases/assets or bulk decompiler output.

## Current phase

### C0 — broad NetworkTask inventory

Status: **implemented, CI validation pending/ongoing**

Expected artifact:

```text
final-client-server-contract-inventory/
  server-contract-inventory.json
  server-contract-inventory.md
```

Schema 1 records:

- all recoverable `NetworkTask` descendants;
- inheritance;
- method counts;
- request-role methods such as `SetParameter` / `PreparePostData` / `CreateBody`;
- response-role methods such as `Parse` / `SetResponseData` / `CheckResult`;
- method RVAs/signatures;
- only contract-like referenced literals:
  - endpoint-shaped paths;
  - snake_case field keys;
  - header-shaped identifiers;
  - bounded identifier-like strings.

If a local complete `final_map.json` is available, pass `--api-map` to correlate
task names/paths with `(group,key,path)` identities. Do not invent missing map rows.

## Next phases

### C1 — endpoint binding

Bind every A/B `ApiType` entry to the responsible task(s). Preserve aliases by
`(group,key)`; path is not a unique ID.

Target output:

```text
contracts/endpoints.json
```

Each row should contain evidence/confidence, never a guess presented as proof.

### C2 — request schema extraction

For each bound task, recover fields emitted by request construction / post params
and classify required/conditional/default behavior where statically provable.

### C3 — response schema extraction

For each `Parse` path, recover hard reads, optional reads, arrays/nested maps,
primitive type expectations and common parser helpers.

### C4 — state mutation / consumer graph

Trace parsed values into `Work*`, `Savedata*`, singleton state and immediate
consumers. This is the step that lets the local server omit response fields that
the final client never uses.

### C5 — server generation

Generate route/model/test skeletons from proven contracts, then implement only
the stateful preservation semantics required for Home, cards/idols, commu,
music/MV, LIVE, Room and other archival surfaces.

## Evidence policy

Use labels such as:

```text
proven-static
proven-runtime
candidate
unresolved
```

Never turn a naming heuristic into a proven endpoint binding.

## Runtime role

Rooted-device work remains necessary, but runtime should be used mainly to close
ambiguities after the broad static contract map exists, not as the primary way to
discover endpoints one at a time.

## Handoff checklist for the next agent

1. Fetch this branch and read this file plus `AGENT_HANDOFF.md`.
2. Inspect the latest `Analyze final 11.6.3 server contracts` workflow run.
3. Download/read only the sanitized contract artifact.
4. Record aggregate C0 results in `docs/research/2026-09-03-server-contract-analysis-start.md`.
5. Fix broad-pass false negatives before hand-analyzing individual tasks.
6. Start C1 endpoint binding using the already-established final ApiType map.
