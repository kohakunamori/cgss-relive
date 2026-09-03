# Rooted Android integration for the final CGSS 11.6.3 client

This is the real-client acceptance procedure for the untouched final Android
11.6.3 build. It preserves original hostnames/HTTPS and uses a rooted test device
only for reversible DNS/hosts and system-CA integration.

## Static facts that drive the test

For the exact hash-verified final 11.6.3 arm64 IL2CPP specimen:

- API traffic uses `UnityWebRequest`;
- no managed `CertificateHandler` / `ValidateCertificate` override is proven on
  the API path;
- no managed/Java pinning implementation is wired into the proven API path;
- `Stage.LoadTask.Parse` is RVA `0x04850a94`;
- result code 214 persists `required_res_ver=10133800` into Savedata `RES_VER` and
  does **not** automatically resend `/load/check` in the same network coroutine;
- the parent continuation resumes into
  `AssetManager.InitializeManifest -> DownloadOrLoadForInitialize` before
  BootMain reaches `/load/index`;
- final `StageSceneDefine.eViewId` maps `Home=6`, `Login_Bonus=7`,
  `Asset_Download=8`;
- successful `/load/index` parsing reaches `BootMain.ChangeView`, selecting
  `Home(6)` when no login bonus exists and `Login_Bonus(7)` otherwise;
- `/load/title` is not a hard Home prerequisite;
- `data.isS3=false` selects `storages.game.starlight-stage.jp`.

The remaining decisive uncertainty is original-client runtime acceptance of the
local TLS/resource stack and synthetic starter-visible `/load/index` state.

## 1. Install dependencies

```powershell
python -m pip install -r .\server\requirements.txt
```

## 2. Generate one disposable multi-SAN certificate

The built-in TLS mux serves both original HTTPS hostnames on one device-facing
port. Generate one leaf containing both SANs:

```powershell
python .\scripts\make-test-tls-cert.py `
  --hostname apis.game.starlight-stage.jp `
  --hostname storages.game.starlight-stage.jp
```

Default output is under gitignored `work/tls/`:

```text
work/tls/ca.cert.pem
work/tls/ca.key.pem
work/tls/server.chain.pem
work/tls/server.key.pem
```

Never commit private keys.

## 3. Trust the CA as an Android system CA

Use the rooted device/root manager's supported system-CA mechanism. Android
14+/Conscrypt/APEX layouts differ across Magisk, KernelSU and ROMs, so this repo
does not automate that persistent system mutation.

Acceptance condition: the CGSS process trusts `ca.cert.pem` through the system
trust domain. Installing it only as a user CA is not sufficient evidence.

## 4. Redirect both original hostnames on device

Make both original names resolve to device loopback:

```text
127.0.0.1 apis.game.starlight-stage.jp
127.0.0.1 storages.game.starlight-stage.jp
```

Keep the original names intact so HTTP Host, TLS SNI and certificate SAN checks
remain realistic.

## 5. Start plain local backends

TLS terminates only at `server.tls_mux`; the API and resource backends stay on
loopback plain HTTP. This avoids two competing TLS listeners while preserving the
original external HTTPS semantics.

### Control API backend — port 8080

Use starter-visible first:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8080 `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter-control.jsonl `
  --api-map .\work\final_map.json
```

`--api-map` only annotates sanitized unknown-route evidence. It does not invent a
response.

### Frozen resource backend — port 8081

Start this **before launching native 214 mode**:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8081 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --event-log .\work\runtime-starter-resource.jsonl
```

The resource log contains only category/status evidence:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

Resource filename/hash/query is never logged and `/healthz` is excluded.

Verified local bootstrap wire manifests, when required, live outside Git under:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

## 6. Start the built-in single-port TLS Host mux — port 8445

```powershell
python -m server.tls_mux `
  --host 127.0.0.1 `
  --port 8445 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --api-backend 127.0.0.1:8080 `
  --resource-backend 127.0.0.1:8081
```

The mux dispatches only by the original Host header:

```text
apis.game.starlight-stage.jp
  -> http://127.0.0.1:8080

storages.game.starlight-stage.jp
  -> http://127.0.0.1:8081
```

It does not log request paths, headers, bodies or query strings. Sanitized runtime
evidence remains in the two backend JSONL files.

Unknown Host is rejected with 421. Request bodies are forwarded opaquely. The
current mux accepts GET/HEAD/POST and Content-Length request bodies; unexpected
chunked request upload is rejected explicitly rather than guessed.

## 7. Use exactly one `adb reverse` for device HTTPS 443

Point the device's only loopback 443 listener at mux port 8445:

```powershell
.\scripts\prepare-device-tunnel.ps1 -HostPort 8445 -RequireRoot
```

Conceptually:

```text
CGSS https://apis.game.starlight-stage.jp:443
CGSS https://storages.game.starlight-stage.jp:443
                |
                v
      device 127.0.0.1:443
                |
          adb reverse
                |
                v
     host TLS mux 127.0.0.1:8445
          /                   \
 API backend :8080      resource backend :8081
```

Do not create two competing `adb reverse tcp:443` mappings.

Remove the mapping with:

```powershell
.\scripts\prepare-device-tunnel.ps1 -Remove
```

## 8. Native `/load/check` behavior — primary experiment

Incoming final-binary default:

```text
RES-VER: 10133000
```

Default local response:

```text
result_code = 214
required_res_ver = 10133800
data.isS3 = false
```

Expected statically closed continuation:

```text
/load/check 214
-> Savedata RES_VER=10133800
-> SetupNetwork finishes
-> GameInitialize resumes
-> InitializeManifest
-> DownloadOrLoadForInitialize
-> resource request(s)
-> GameInitialize completes
-> BootMain.StartConnect
-> /load/index
-> Stage.LoadTask.Parse
-> Home(6) or Login_Bonus(7)
```

A later second `/load/check` is possible for an independent path, but is not a
required link and must not be used as the 214 acceptance criterion.

## 9. Analyze one merged control/resource timeline

The analyzer can merge independent sanitized files by their numeric event time:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run starter=.\work\runtime-starter-control.jsonl `
  --merge-run starter=.\work\runtime-starter-resource.jsonl `
  -o .\work\runtime-starter-report.json
```

Repeated `--merge-run` with the same label forms one deterministic run. Missing
timestamps are rejected rather than ordered heuristically.

Important hard-mainline phases include:

```text
resource_version_214_responded
resource_plane_observed
resource_plane_served
load_index_reached
post_load_index_observed
```

A healthy native timeline may be as simple as:

```text
/load/check             214
@resource/manifest      200
@resource/AssetBundles  200/206
/load/index             200
```

No second `/load/check` is needed for that timeline to be valid.

## 10. Diagnostic direct-success differential

Only if native mode fails before useful resource evidence, restart the API backend
with:

```text
--accept-old-resource-version
```

while keeping the same starter-visible profile. This returns success to old
10133000 while still supplying `required_res_ver=10133800`. It is a diagnostic
branch, not the protocol-default model.

Compare equivalent runs, for example:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run native=.\work\runtime-native-control.jsonl `
  --merge-run native=.\work\runtime-native-resource.jsonl `
  --merge-run direct=.\work\runtime-direct-control.jsonl `
  --merge-run direct=.\work\runtime-direct-resource.jsonl
```

## Acceptance questions, in order

1. Does TLS complete and does `/load/check` reach the control backend?
2. After native 214, does any `@resource/*` request appear?
3. Are resource requests served successfully, or which sanitized category first
   returns 404/416?
4. Does the client subsequently reach `/load/index`?
5. Does starter-visible `/load/index` lead to a later client action?
6. Does the device visibly render Home or Login Bonus followed by Home?
7. What is the first unsupported post-Home endpoint or local-state dependency?

Static `Home=6` / `Login_Bonus=7` is already confirmed. Runtime is validating that
the local stack reaches/renders those views, not rediscovering their numeric IDs.

## Failure classification

### No control request

Check hosts/DNS, IPv6, `adb reverse`, mux process and app process network
reachability.

### TLS error before HTTP

Check system-root visibility and that `server.cert.pem` contains both original
DNS SANs. Keep original Host/SNI. Do not patch the APK before collecting the exact
failure.

### Mux 421

The client used a hostname not in the two-host allow-list. Capture only the
minimum local/private evidence necessary to identify that hostname; do not add a
wildcard route blindly.

### 214 returned, no resource event

Static continuation says setup should finish and `GameInitialize` should enter
`InitializeManifest`. Check the storages hosts mapping, mux routing, resource
backend health, Savedata transition and logcat. Use direct-success only after
these checks.

### `@resource/unresolved` or resource 404

The client reached the resource plane. Investigate URL-builder coverage,
manifest-name resolution, local object/wire-manifest presence and frozen version.
The sanitized JSONL deliberately hides the raw path; use a local private debug
capture only when necessary and never commit it.

### `/load/index` arrives, then stalls

Do not add hundreds of optional fields. `LoadTask.Parse` is guard-heavy and a
provided parent can make child reads hard. Use the starter/empty/strict
differential only after identifying the first real blocker.

### Known final endpoint returns 404 after Home

Use `api_candidates` to identify its final Task/Parse implementation and restore
only the parser-safe minimum. Never return arbitrary empty success merely because
an endpoint name is known.
