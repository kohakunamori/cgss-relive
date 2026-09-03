# Local final-resource server

`server.resource_server` is the read-only serving layer over the frozen
`10133800` content-addressed archive:

```text
resource-cache/10133800/objects/<hh>/<md5>
```

The HTTP layer accepts URL families reconstructed from the exact final 11.6.3
client and maps them back to the same archive.

## Statically reconstructed URL families

Examples include:

```text
/dl/<ver>/manifests/<file>
/dl/<ver>/[Low|High/]AssetBundles/<Platform>/<file-or-hash>
/dl/resources/[Low|High/]AssetBundles/<Platform>/<file-or-hash>[.lz4]
/dl/<ver>/[Low|High/]Sound/<Platform-or-Common>/<file-or-hash>
/dl/resources/[Low|High/]Movie/<file-or-hash>
/dl/<ver>/Generic/Blob/<file-or-hash>
/dl/<ver>/Generic/Master/<file-or-hash>
/dl/resources/Generic/<hh>/<hash>
```

Important builder facts:

- `isS3=false` selects `storages.game.starlight-stage.jp`;
- `isS3=true` selects the Akamai CDN family;
- hash-prefix sharding is branch-specific, not universal;
- Movie/resource forms can omit the version segment;
- regular paths use Savedata `RES_VER`;
- `.lz4` belongs to compressed builder forms rather than defining a different
  archive identity.

## Filename index

Filename-addressed storages requests require the locally preserved final manifest
SQLite database:

```powershell
python -m server.resource_server `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db
```

The DB is opened read-only; only `name, hash` from `manifests` is loaded. Without
it, hash-addressed forms still work and unresolved filename forms return 404
rather than being guessed.

## Bootstrap manifest wire objects

Verified local copies, when needed, live outside Git under:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

They are exposed only as version-scoped manifest requests. Nothing is synthesized
and no proprietary body is committed.

## Run with TLS and sanitized runtime evidence

For the native final-client path:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8444 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --cert .\work\tls\resource.chain.pem `
  --key .\work\tls\resource.key.pem `
  --event-log .\work\runtime-starter-resource.jsonl
```

The certificate SAN must match the original resource hostname being redirected.
Do not assume the API certificate covers `storages.game.starlight-stage.jp`.

## Sanitized event log

`--event-log` is specifically for integration evidence. The requested filename,
MD5/hash, path tail and query string are discarded before logging. Only synthetic
route category + HTTP status are retained:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

`/healthz` is not logged at all, so monitoring cannot create a false
`resource_plane_observed` phase.

Control/resource logs can later be merged safely by event timestamp:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run starter=.\work\runtime-starter-control.jsonl `
  --merge-run starter=.\work\runtime-starter-resource.jsonl
```

This avoids concurrent writes from two server processes to one evidence file.

## HTTP behavior

The server is read-only and supports:

- `GET`;
- `HEAD`;
- one `Range: bytes=...` range;
- immutable ETag/cache headers for content-addressed objects;
- version-scoped bootstrap manifests;
- optional TLS;
- optional sanitized resource-plane event logging.

Invalid URL families, wrong frozen versions, unknown filenames and missing
objects return 404. Unsatisfiable ranges return 416.

## Native bootstrap role

The static final-client parent continuation is now closed:

```text
/load/check 10133000
-> 214 + required_res_ver=10133800
-> client persists RES_VER=10133800
-> SetupNetwork becomes ready
-> ResourcesManager.GameInitialize resumes
-> AssetManager.InitializeManifest
-> DownloadOrLoadForInitialize
-> resource requests handled here
-> GameInitialize completes
-> BootMain.StartConnect
-> /load/index
```

Therefore start and route the resource server **before** launching the native 214
run. Do not wait for an automatic second `/load/check`; it is not a required link.

A successful `@resource/*` event after the 214 is direct runtime evidence that the
client entered the statically expected resource initialization stage.

## Integrity boundary

`archive-resources.py` verifies compressed MD5 before atomically admitting an
object into the archive. The hot serving path does not rehash every request. If
the archive may have changed, rerun the offline verifier before serving it.
