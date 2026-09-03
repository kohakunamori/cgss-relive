# Final 11.6.3 `LoadTaskParam` request-side closure

This note closes the remaining bounded static question around
`LoadTaskParam.load_state` and `LoadTaskParam.next_api` for the exact final Android
11.6.3 specimen.

It is **not** runtime acceptance evidence and it does not add fields to the
`/load/index` response.

## Exact specimen result

The hash-verified exact workflow run `33744105632` (run #41) completed
successfully, including the clean-room artifact boundary. Its schema-4 bounded
construction report establishes:

```text
Stage.LoadTask.SetParameter @ 0x04877A14

LoadTaskParam : BaseParam
BaseParam     : PostParams
NetworkTask.Params : PostParams @ +0x30

LoadTaskParam.load_state @ +0x40
LoadTaskParam.next_api   @ +0x50
```

The `BaseParam` name is not globally unique in `dump.cs`; the analyzer therefore
pins the relevant type by the exact constructor reached from `SetParameter`:

```text
Stage.BaseParam::.ctor
```

This avoids confusing it with unrelated same-name metadata types. The report also
labels only fields on `LoadTaskParam` as `load_state` / `next_api`; same numeric
offsets on unrelated types are not promoted to target-field evidence.

## `SetParameter` construction flow

The same constructed object is held in `x20`. Within the bounded
`SetParameter()` body the client:

```text
constructs/initializes x20 through Stage.BaseParam::.ctor
writes x20+0x50 (next_api) from local/task state
writes x20+0x40 (load_state) as local/task state
stores x20 into LoadTask(this)+0x30
```

The final store is:

```text
x20 -> NetworkTask.Params
```

because `LoadTask` inherits through `BaseTask` from `NetworkTask`, whose
`Params` field is a `PostParams` at offset `0x30`.

The important directionality correction is that `SetParameter()` **writes**
`this+0x30`; it does not load a response/parser child from `this+0x30` and then
read `+0x40/+0x50` from it.

## Consequence for `/load/index`

`load_state` and `next_api` are outbound task/request parameter state. Current
exact evidence does not support treating either name as a `/load/index` response
key or parser dependency.

Therefore:

- do not add `load_state` to the starter response;
- do not add `next_api` to the starter response;
- remove both from the `/load/index` response-blocker list;
- keep the reduced starter profile unchanged;
- only revisit this conclusion if original-client runtime produces contradictory
  evidence.

The decisive remaining milestone is rooted original-client runtime through the
local TLS/resource stack and visible Home.
