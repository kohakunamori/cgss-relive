# CGSS preservation client layer

This directory defines the thin client-side compatibility layer for the frozen
CGSS Android 11.6.3 client.

The preservation client is **not** an offline reimplementation of game logic.
Its job is limited to helping the original runtime reach a preservation
environment while leaving original serializers, parsers, state machines, UI,
Live, card, Home, and resource semantics intact.

## Artifact model

The project maintains three distinct client artifacts:

1. **Original** — byte-exact frozen 11.6.3 specimen. Never rebuilt or patched.
2. **Preservation** — minimal environment compatibility delta only.
3. **Research** — Preservation behavior plus diagnostics/instrumentation.

A visible Home milestone has three different meanings:

- Research Home: diagnostics path validated.
- Preservation Home: thin client layer validated.
- Original Home: compatibility server/preservation milestone validated.

Only the last one proves untouched-client compatibility.

## Allowed preservation responsibilities

The preservation layer may implement only these boundary concerns:

- bootstrap/config loading;
- endpoint resolution/redirection;
- TLS trust/hostname/pinning compatibility;
- asset base-URL redirection;
- modern Android compatibility fixes.

Research-only builds may additionally enable bounded instrumentation and
verbose diagnostics.

## Forbidden preservation responsibilities

Do not move server or game semantics into the client. In particular, do not:

- force API `result_code` values;
- skip `/load/check` or resource initialization;
- synthesize `/load/index` fields in the client;
- swallow parser exceptions or missing-key failures;
- patch owned cards, user state, rewards, songs, Live progression, or gacha;
- force `SceneManager.ChangeView(Home)`;
- replace original serializers/parsers with compatibility serializers/parsers.

When one of those areas fails, Research instrumentation should identify the
first failing consumer and the compatibility server/resource layer should be
fixed instead.

## Configuration model

`config.example.json` documents the portable endpoint/asset/TLS settings that
a future bootstrap shim will consume. The configuration deliberately describes
*where* the original client connects, not *what* the server should return.

The intended service abstraction is:

```text
API
ASSET
WEB
```

A deployment can map those services to local, LAN, archive, hybrid, or capture
endpoints without hard-coding many individual URLs into native patches.

## Native patch policy

Native changes must be declarative and auditable. `native-patches.json` is the
manifest for the frozen 11.6.3 `libunity.so` baseline. Apply patches only with
`scripts/apply-client-patches.py`.

Every patch entry must record:

- a stable patch id;
- compatibility class (`endpoint`, `tls`, `asset`, `android_compat`, or
  `instrumentation`);
- exact source binary SHA-256;
- file offset;
- expected original bytes;
- same-length replacement bytes;
- semantic explanation.

The patch tool refuses to write when the binary hash or expected original bytes
do not match. Blind offset patching is not allowed.

The current manifest intentionally contains no active patch. Runtime research
must first establish the exact endpoint/TLS mechanism that can be changed
without weakening original protocol or game semantics.
