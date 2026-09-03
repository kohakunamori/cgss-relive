# Server-facing contract analysis plan — final Android 11.6.3

## Why this branch exists

The bootstrap-focused workflow is efficient for reaching Home, but a complete
preservation server would become slow if every later feature were discovered only
by "run -> hit blocker -> reverse one parser -> retry".

The new objective is therefore to recover the client's server-facing semantics in
broad static passes, while retaining runtime testing as an acceptance and ambiguity
resolution tool.

This does **not** require full semantic recovery of all 222,595 method definitions.
The server only needs the subset that participates in network request construction,
response parsing, persistent server-derived state and the consumers of that state.

## Starting evidence

The exact final specimen already supports direct file-state IL2CPP analysis:

```text
package               jp.co.bandainamcoent.BNEI0242
app                    11.6.3 (438)
Unity                  2022.3.56f1
IL2CPP metadata        v31
type definitions       31,804
method definitions     222,595
Assembly-CSharp types  21,083
```

No prerequisite "unpacking" phase is justified while the frozen file-state
`libil2cpp.so` and `global-metadata.dat` continue to resolve type/method names,
signatures and exact native RVAs. Runtime image dumping should be introduced only
if concrete protected/stubbed/runtime-generated code is observed.

The final API inventory already establishes 516 normal A-group keys and a separate
22-entry VR/login group. Relative paths are known at high confidence, while
per-endpoint host assignment remains a separate proof obligation.

## Contract-recovery pipeline

```text
C0 NetworkTask inventory
   ↓
C1 ApiType endpoint -> task binding
   ↓
C2 outbound request schema
   ↓
C3 inbound response parser schema
   ↓
C4 parsed state -> Work*/Savedata -> consumer graph
   ↓
C5 generated server route/model/test skeleton
   ↓
targeted runtime validation
```

### C0: broad task inventory

`scripts/analyze-server-contracts.py` starts by identifying every recoverable type
whose inheritance chain reaches `NetworkTask`.

For those types it records request/response-role methods and scans the native method
body for references to **contract-like** managed literals only. Arbitrary dialogue,
localized text and other game content are deliberately excluded.

This gives a broad index suitable for prioritizing later static analysis without
committing bulk reverse-engineering output.

### C1: endpoint binding

Canonical identity is `(ApiType group, key)`, not path. The final map has legitimate
path aliases. Bindings should combine:

- exact endpoint literal reference;
- ApiType enum/key flow;
- task construction/call sites;
- normalized task/enum naming only as a candidate heuristic;
- runtime traces where static binding is ambiguous.

### C2/C3: schema recovery

The desired product is not a copied production response. It is the minimum typed
contract the final client expects.

Useful evidence includes:

- string-key hard reads/writes;
- parser helper called for each key;
- array loops and nested node access;
- presence checks / conditional branches;
- default values;
- field writes following parse;
- request parameter construction.

### C4: state and consumers

For preservation, a server field is valuable only when it changes client-observable
behavior. Trace parsed fields into client state and then into consumers so unused
production fields can be omitted.

### C5: local-server generation

Once contracts are evidence-backed, generate deterministic server skeletons and
tests. Stateful semantics should be implemented only where preservation features
need them; payments, rankings and live-service social/economy behavior do not need
production parity.

## Artifact boundary

Allowed derived output:

- type/method names and signatures;
- RVAs/call relationships;
- endpoint names/paths;
- field/header identifiers;
- inferred schemas with evidence/confidence;
- aggregate counts.

Keep raw/proprietary material ephemeral:

- APK/XAPK;
- `libil2cpp.so`;
- `global-metadata.dat`;
- bulk `dump.cs` / `script.json` / `stringliteral.json`;
- master/manifest databases and resource bodies;
- raw credentials/session captures.

## Immediate success criterion

C0 is useful when one exact-specimen run can enumerate the `NetworkTask` surface and
produce a bounded sanitized report without manual selection of individual bootstrap
classes. C1 then becomes the next bottleneck, not another Home-specific parser pass.
