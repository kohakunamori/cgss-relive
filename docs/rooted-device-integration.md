# Rooted Android integration for the final CGSS 11.6.3 client

This is the real-client acceptance procedure for the untouched final Android
11.6.3 build. It preserves original hostnames/HTTPS and uses a rooted test device
only for reversible DNS/hosts and system-CA integration.

## Static facts that drive the test

For the exact hash-verified final 11.6.3 arm64 IL2CPP specimen:

- API traffic uses `UnityWebRequest`;
- no managed `CertificateHandler` subclass / `ValidateCertificate` override is
  proven on the API path;
- no managed/Java pinning implementation is wired into the proven API path;
- targetSdk is modern, so a user CA alone is not a reliable trust path;
- `Stage.LoadTask.Parse` is RVA `0x04850a94`;
- result code 214 persists `required_res_ver=10133800` into Savedata `RES_VER` and
  does **not** automatically resend `/load/check` in the same network coroutine;
- the parent coroutine continuation is now closed: after setup becomes ready,
  `ResourcesManager.GameInitialize` resumes into
  `AssetManager.InitializeManifest -> DownloadOrLoadForInitialize` before
  BootMain reaches `/load/index`;
- final `StageSceneDefine.eViewId` maps `Home=6`, `Login_Bonus=7`,
  `Asset_Download=8`;
- successful `/load/index` parsing reaches `BootMain.ChangeView`, which selects
  `Home(6)` when no login bonus exists and `Login_Bonus(7)` otherwise;
- `/load/title` is a Title/user-driven branch, not a hard Home prerequisite;
- `data.isS3=false` selects `storages.game.starlight-stage.jp`.

The remaining decisive uncertainty is original-client runtime acceptance of the
local TLS/resource stack and synthetic starter-visible `/load/index` state.

## 1. Install dependencies

```powershell
python -m pip install -r .\server\requirements.txt
```

## 2. Generate disposable TLS material

```powershell
python .\scripts\make-test-tls-cert.py
```

Default output is under gitignored `work/tls/`.

The control certificate needs SAN:

```text
apis.game.starlight-stage.jp
```

The resource certificate needs SAN:

```text
storages.game.starlight-stage.jp
```

A single certificate may cover both only if both SANs are actually present.
Never commit private keys.

## 3. Trust the CA as a system CA

Use the rooted device/root manager's supported system-CA mechanism. Android
14+/Conscrypt/APEX layouts differ across Magisk, KernelSU and ROMs, so this repo
does not automate the system mutation.

Acceptance condition: the CGSS process trusts the disposable CA through the
system trust domain. Merely installing it as a user certificate is insufficient.

## 4. Redirect both original hostnames for the native run

For the primary native-214 test, make these mappings effective on device:

```text
127.0.0.1 apis.game.starlight-stage.jp
127.0.0.1 storages.game.starlight-stage.jp
```

Keep the original names so Host, TLS SNI and SAN semantics remain intact.

For the diagnostic `--accept-old-resource-version` run, the resource redirect may
be omitted if the purpose is strictly to test whether bypassing the native 214
branch reaches BootMain sooner.

## 5. Bridge device ports to host servers

The existing helper prepares the API 443 reverse to host 8443:

```powershell
.\scripts\prepare-device-tunnel.ps1 -HostPort 8443 -RequireRoot
```

Conceptually:

```text
CGSS https://apis.game.starlight-stage.jp:443
  -> device 127.0.0.1:443
  -> adb reverse
  -> host API TLS server :8443
```

The resource hostname also uses HTTPS 443. If both hostnames resolve to the same
device loopback address, a single device port cannot distinguish SNI targets by
TCP port. Use one of these integration layouts:

1. preferred: a local TLS/SNI reverse proxy on host/device-facing 443 that routes
   `apis.game...` to API :8443 and `storages.game...` to resource :8444;
2. use distinct loopback aliases/IPs plus root iptables/nft redirects per target;
3. run a unified front proxy that terminates a certificate covering both SANs and
   dispatches by SNI/Host.

Do not attempt to bind two independent `adb reverse tcp:443` mappings at once.

Remove the API helper mapping with:

```powershell
.\scripts\prepare-device-tunnel.ps1 -Remove
```

## 6. Start the control server with starter-visible state

Use starter-visible first:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter-control.jsonl `
  --api-map .\work\final_map.json
```

`--api-map` only annotates sanitized unknown-route events; it never invents a
response.

The event log excludes UDID, SID, USER-ID, PARAM, viewer-id values and decoded
request/response values.

## 7. Start the frozen resource server before launching native mode

Do **not** wait for a second `/load/check`. The static parent continuation says
resource initialization is the expected next stage after the native 214.

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

The resource event log contains only category/status evidence:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

It never contains resource filenames, hashes or query strings. `/healthz` is
explicitly excluded from runtime evidence.

Place verified local bootstrap wire manifests, when required, under:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

No proprietary manifest/database/resource body belongs in Git.

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

Expected static continuation:

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

A second `/load/check` may occur for some independent reason, but it is not a
required link and must not be used as the acceptance criterion for 214.

## 9. Diagnostic direct-success differential

Only if native mode stalls before useful resource evidence, compare:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --accept-old-resource-version `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-direct-control.jsonl
```

This returns success to old 10133000 while still supplying
`required_res_ver=10133800`. It is a diagnostic branch, not the native protocol
model.

## 10. Analyze the run

The runtime analyzer schema is 3 and understands sanitized resource routes.
When control/resource logs are combined into one time-ordered timeline, the key
phases are:

```text
resource_version_214_responded
resource_plane_observed
resource_plane_served
load_index_reached
post_load_index_observed
```

Until the analyzer's merge mode is available, either write both sanitized
servers to one dedicated runtime JSONL on a filesystem where append semantics are
reliable, or analyze the two logs separately and use their timestamps to order
evidence. Do not concatenate unsanitized web-server logs.

Typical single-log command:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl
```

If starter-visible reaches `/load/index` but then fails, use empty/strict profiles
only as controlled differentials.

## Acceptance questions, in order

1. Does TLS complete and does `/load/check` reach the control server?
2. After native 214, does any `@resource/*` request appear?
3. Are resource requests served successfully, or what sanitized category first
   returns 404/416?
4. Does the client subsequently reach `/load/index`?
5. Does the starter-visible `/load/index` response lead to a later client action?
6. Does the device visibly render Home or Login Bonus followed by Home?
7. What is the first unsupported post-Home endpoint or local-state dependency?

Static mapping `Home=6` / `Login_Bonus=7` is already confirmed. The runtime test
is validating that the local stack reaches/renders those views, not rediscovering
what the numeric IDs mean.

## Failure classification

### No control request

Check hostname resolution, IPv6, reverse/proxy routing and app process network
reachability.

### TLS error before HTTP

Check system-root visibility, certificate dates/SAN, SNI and original Host. Do not
patch the APK before collecting the exact failure.

### 214 returned, no resource event

This is now a narrow blocker. The static continuation says setup should finish and
`GameInitialize` should enter `InitializeManifest`. Check resource-host routing,
TLS/SNI for `storages.game...`, local Savedata transition and logcat. Compare the
direct-success differential only after those are checked.

### `@resource/unresolved` or resource 404

The client reached the resource plane. Investigate URL-builder coverage,
manifest-name resolution, local object/wire-manifest presence and frozen version.
The sanitized JSONL intentionally does not reveal the raw path; use a local
private/debug capture only when necessary and never commit it.

### `/load/index` arrives, then stall/error

Do not add hundreds of optional fields. `LoadTask.Parse` is guard-heavy; a
provided parent can make child reads hard. Compare starter/empty/strict only after
identifying the first real blocker.

### Known final endpoint returns 404 after Home

Use `api_candidates` to identify its final Task/Parse implementation and restore
only the parser-safe minimum shape. Never return arbitrary empty success merely
because an endpoint name is known.
