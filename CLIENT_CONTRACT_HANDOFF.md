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

Primary implementation:

```text
scripts/analyze-server-contracts.py
.github/workflows/analyze-server-contracts.yml
```

Raw specimen/decompiler material must remain ephemeral.

## C0 — broad NetworkTask inventory

Status: **COMPLETE ENOUGH TO PROCEED**

First validated exact-specimen run:

```text
workflow run                     33778354480
branch commit                    ae5bea4bd071fc3f42f570f7d33648a942da4e4a
artifact                         final-client-server-contract-inventory
artifact id                      9902546755
artifact sha256                  1d6b8c768e1e64395393097eaf57fa8d40b63a54cf8c84b432c034b509712c5e
NetworkTask descendants          502
mapped task methods             1596
request-role methods             402
response-role methods            513
tasks with contract literals     359
tasks with zero mapped methods     0
```

High-signal examples proven to be included in the broad pass:

```text
Cute.VersionCheckTask
Stage.LoadTask
Stage.HomeCustomizeUpdateTask
Stage.LiveStartTask
Stage.LiveEndTask
Stage.StoryStartTask
Stage.GachaExeTask
```

The first run did **not** load a complete API map, so endpoint candidate count was
zero by design. Do not treat that as a static-analysis failure.

Detailed first-run evidence is recorded in:

```text
docs/research/2026-09-03-server-contract-analysis-start.md
```

## C1 — endpoint binding

Status: **NEXT ACTIVE PHASE**

Bind every final A/B `ApiType` identity to responsible task(s). Canonical endpoint
identity is:

```text
(group, key)
```

not path, because legitimate aliases exist.

Evidence priority:

1. exact ApiType key flow / exact endpoint literal;
2. task construction/call-site proof;
3. exact path reference;
4. normalized task/enum name only as `candidate`;
5. runtime only where static evidence stays ambiguous.

Target output:

```text
contracts/endpoints.json
```

Each row needs an evidence label such as:

```text
proven-static
proven-runtime
candidate
unresolved
```

Never promote a naming heuristic to proof.

## C2 — request schema extraction

For each bound task, recover fields emitted by request construction/post params and
classify required/conditional/default behavior where statically provable.

## C3 — response schema extraction

For each `Parse` path, distinguish hard reads, optional reads, arrays/nested maps,
primitive type expectations and shared helper literals.

The C0 literal inventory is only a candidate field superset; do not directly turn
all emitted literals into required response fields.

## C4 — state mutation / consumer graph

Trace parsed values into `Work*`, `Savedata*`, singleton state and immediate
consumers. This lets the preservation server omit production fields that the final
client never uses.

## C5 — server generation

Generate route/model/test skeletons from proven contracts, then implement only the
stateful preservation semantics required for Home, cards/idols, commu, music/MV,
LIVE, Room and other archival surfaces.

## Runtime role

Rooted-device work remains necessary, but runtime should close residual ambiguity and
acceptance gaps after the broad static contract map exists. Do not regress to using
runtime as the primary endpoint-discovery loop.

## Handoff checklist for the next agent

1. Fetch `analysis/server-contracts-11.6.3`.
2. Read this file, `AGENT_HANDOFF.md`, and the dated C0 research log.
3. Inspect/download run `33778354480` sanitized artifact if still retained.
4. Continue C1 endpoint binding; do not restart C0 or bootstrap research.
5. If the complete delivered `final_map.json` is available locally, validate it with
   the existing strict map validator and feed it to `--api-map`.
6. Otherwise derive a sanitized `(group,key,name,path)` representation from the exact
   final specimen before using naming heuristics broadly.
