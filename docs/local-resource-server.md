# Local final-resource server

`server.resource_server` is the read-only serving layer over the frozen
`10133800` content-addressed archive. The archive remains stored as:

```text
resource-cache/10133800/objects/<hh>/<md5>
```

The HTTP layer no longer assumes that the final 11.6.3 client always asks for a
single `/dl/resources/<Category>/<hh>/<hash>` shape. Static analysis of
`CustomPreference` and `AssetHandle.BuildURL` proves several URL families, so the
server accepts those families and resolves them back to the same object store.

## Statically reconstructed URL families

The final client can construct paths such as:

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

The exact builder facts are important:

- `isS3=false` selects `storages.game.starlight-stage.jp` and does **not** imply
  a `<hash-prefix>/<hash>` path for every resource;
- `isS3=true` selects the Akamai CDN family and introduces hash-prefix sharding
  only in specific branches;
- `Movie` and hush/resource paths can omit the resource-version segment;
- regular paths use the Savedata `RES_VER` value;
- `.lz4` is appended by the compressed/hush branch rather than being a separate
  archive identity.

The compatibility server therefore resolves hash-addressed forms directly and
supports filename-addressed storages forms when a local final manifest database
is supplied.

## Optional filename index

A filename-addressed request cannot be mapped to the content-addressed archive
from the URL alone. Pass the locally preserved final manifest SQLite database:

```powershell
python -m server.resource_server `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db
```

The database is opened read-only and only `name, hash` from `manifests` is loaded
into memory. The database itself remains proprietary/uncommitted.

Without `--manifest-db`, hash-addressed paths continue to work; filename paths
return 404 instead of guessing.

## Bootstrap manifest wire objects

The resource archive intentionally stores ordinary downloadable objects by MD5.
`all_dbmanifest` and `Android_AHigh_SHigh` are separate bootstrap wire objects.
If the verified copies are needed for a real-client resource update, place them
locally under:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

They are then exposed only at the configured frozen version:

```text
/dl/10133800/manifests/all_dbmanifest
/dl/10133800/manifests/Android_AHigh_SHigh
```

Nothing is synthesized and these files must never be committed.

## Run

Plain HTTP for local socket tests:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8081 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db
```

TLS for a redirected original resource hostname:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8444 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --cert .\work\tls\resource.chain.pem `
  --key .\work\tls\resource.key.pem
```

The certificate SAN must match whichever original resource hostname is actually
redirected. The control-API certificate for `apis.game.starlight-stage.jp` must
not be assumed valid for `storages.game.starlight-stage.jp` or the Akamai host.

## HTTP behavior

The server is read-only and supports:

- `GET`;
- `HEAD`;
- one `Range: bytes=...` range;
- immutable `ETag`/cache headers for content-addressed objects;
- version-scoped bootstrap manifests;
- optional TLS.

Invalid URL families, mismatched frozen versions, unknown filenames and missing
objects return 404. Unsatisfiable ranges return 416.

## Integration policy

The control server now explicitly returns `data.isS3=false`, selecting the
storages URL family when `/load/check` reaches its successful parse. Redirect the
resource hostname only when running the real resource-update path; a direct
success `/load/check` differential can be used first to separate resource-stage
failures from later BootMain or `/load/index` failures.

## Integrity boundary

`archive-resources.py` verifies compressed MD5 before atomically admitting an
object into the archive. The serving hot path therefore does not rehash every
request. If the archive may have changed, rerun the offline verifier before
serving it.
