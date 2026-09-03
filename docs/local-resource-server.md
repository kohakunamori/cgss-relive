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
resource/hush Generic forms
```

Important builder facts:

- `isS3=false` selects `storages.game.starlight-stage.jp`;
- `isS3=true` selects the Akamai CDN family;
- hash-prefix sharding is branch-specific, not universal;
- Movie/resource forms can omit the version segment;
- regular paths use Savedata `RES_VER`;
- `.lz4` belongs to compressed builder forms rather than defining a different
  archive identity.

## Exact filename index — path-shaped names matter

Filename-addressed storages requests require the preserved final manifest SQLite
DB. Final `manifests.name` cannot be reduced to basename safely. Aggregate final
10133800 facts are:

```text
rows                          220837
names containing '/'           12317
unique basenames              220652
basename collision groups        137
basename hash-conflict groups    130
```

The server therefore loads **exact normalized manifest names only**. For a URL
tail it tries relative suffixes longest-first; `.lz4` stripping is performed at
the same suffix depth. It never creates fuzzy basename aliases.

The real final DB is exercised by `scripts/verify-final-manifest-resolution.py`.
Current closed aggregate result:

```text
resolved          220837 / 220837
unresolved             0
hash mismatches         0
unknown category        0
```

This includes all 12317 path-shaped names.

Expected uncommitted DB path:

```text
work/resources/manifest_10133800.db
```

## Bootstrap manifest wire objects

Verified local copies live outside Git under:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

Both are exposed only through version-scoped `/dl/10133800/manifests/...` routes.
They are served as exact bytes with `Cache-Control: no-cache`; they are not
content-addressed objects and do not receive an ETag. GET and HEAD are covered by
HTTP regression tests.

## Fast rooted-device preflight — schema 3

Before launching the original client:

```powershell
python .\scripts\preflight-local-resources.py `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  -o .\work\resource-preflight.json
```

Frozen invariants:

```text
manifest rows   220837
unique hashes   220803
wire manifests  2
```

Schema 3 checks:

- exact resource version;
- manifest SQLite `PRAGMA quick_check`;
- frozen row and unique-hash counts;
- all 220803 expected object files present and non-zero;
- `all_dbmanifest` parses the expected Android-manifest MD5;
- local `Android_AHigh_SHigh` compressed bytes match that MD5;
- its CGSS 16-byte wrapper/raw LZ4 payload decodes;
- decoded bytes are SQLite;
- decoded SQLite bytes are identical to the supplied manifest DB;
- `master.mdb` has a valid manifest entry;
- the content-addressed master object exists;
- the master's actual MD5 matches its manifest digest.

Output contains only counts, booleans and failure codes. Exit code `0` means
ready; exit code `2` means the local cache is not ready.

The fast preflight intentionally does **not** hash every 220803 object on every
server start. Admission/download tooling already validates MD5, and rehashing the
entire archive would make normal iteration unnecessarily expensive.

## Optional full archive MD5 audit

When archive bytes may have been changed after admission, after copying the cache
to new storage, or before a preservation milestone, run the full audit explicitly:

```powershell
python .\scripts\audit-local-resource-objects.py `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  -o .\work\resource-object-audit.json
```

It computes MD5 once for every **unique** manifest hash and reports only aggregate
counts:

```text
manifest_unique
checked
missing
unreadable
mismatched
invalid_manifest_hashes
```

No resource filename, digest or path is written to its report. This is a
heavyweight integrity audit, not a prerequisite for every rooted-device launch.

## Preferred rooted-device backend mode

The recommended topology terminates HTTPS in `server.tls_mux`, so the resource
backend itself remains loopback HTTP:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8081 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --event-log .\work\runtime-starter-resource.jsonl
```

The mux routes `storages.game.starlight-stage.jp` to this backend. The normal
first run should use `scripts/run-rooted-local-stack.py`, which runs the fast
preflight and verifies the TLS mux before declaring readiness.

Standalone TLS remains supported for isolated backend tests, but one device port
443 should not be mapped to two independent host listeners.

## Sanitized event log

`--event-log` never records requested filename, MD5/hash, path tail or query. It
retains only category + HTTP status:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

`/healthz` is excluded so monitoring cannot create a false
`resource_plane_observed` phase.

Control/resource logs can be merged by timestamp with
`scripts/analyze-runtime-events.py`.

## HTTP behavior

The server is read-only and supports:

- `GET`;
- `HEAD`;
- one `Range: bytes=...` range;
- immutable ETag/cache headers for content-addressed objects;
- exact version-scoped bootstrap manifests;
- optional standalone TLS;
- optional sanitized resource-plane event logging.

Invalid URL families, wrong frozen versions, unknown exact filenames and missing
objects return 404. Unsatisfiable ranges return 416.

## Native bootstrap role

```text
/load/check 10133000
-> 214 + required_res_ver=10133800
-> Savedata RES_VER=10133800
-> SetupNetwork ready
-> ResourcesManager.GameInitialize resumes
-> AssetManager.InitializeManifest
-> DownloadOrLoadForInitialize
-> resource requests handled here
-> GameInitialize completes
-> BootMain.StartConnect
-> /load/index
```

Start and route the resource backend before launching the native 214 run. Do not
wait for an automatic second `/load/check`; it is not a required link.

A successful sanitized `@resource/*` event after 214 is direct runtime evidence
that the original client entered the statically expected resource stage.
