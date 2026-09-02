# Local final-resource object server

This is the first serving layer over the frozen `10133800` content-addressed
archive. It is deliberately narrower than a complete replacement for
`asset-starlight-stage.akamaized.net`.

## Scope

`server.resource_server` serves only canonical final resource object requests:

```text
/dl/resources/AssetBundles/<hh>/<md5>
/dl/resources/Sound/<hh>/<md5>
/dl/resources/Movie/<hh>/<md5>
/dl/resources/Generic/<hh>/<md5>
```

Each request maps to the existing archive layout:

```text
resource-cache/10133800/objects/<hh>/<md5>
```

The server is read-only and supports:

- `GET`;
- `HEAD`;
- single HTTP `Range: bytes=...` requests;
- `ETag` using the content MD5 from the URL;
- optional TLS using the same `--cert` / `--key` convention as the control API.

It does **not** currently synthesize or serve:

```text
/dl/10133800/manifests/all_dbmanifest
/dl/10133800/manifests/Android_AHigh_SHigh
```

Those wire bootstrap objects are not part of `archive-resources.py`'s current
content-addressed object store. Do not redirect the asset hostname merely because
this server exists. The original 11.6.3 runtime should first prove that resource
networking is the active blocker; then freeze/serve the exact manifest wire
objects rather than inventing them.

## Run

Assuming the archive was prepared as documented in `resource-bootstrap.md`:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8081 `
  --root .\resource-cache\10133800
```

TLS is optional for local socket tests:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8444 `
  --root .\resource-cache\10133800 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem
```

The current generated test certificate is scoped to the control API hostname, so
it must not be assumed valid for the asset CDN hostname. Asset-host certificate
SAN/routing changes belong to the runtime integration step after a real client
shows that local asset redirection is required.

## Integrity boundary

`archive-resources.py` is responsible for verifying object MD5 before an object
is atomically admitted to the archive. The serving hot path therefore does not
rehash every object on every request. If an archive may have been modified,
rerun the offline verifier before serving it.
