# Rooted Android integration for the final CGSS 11.6.3 client

This is the real-client acceptance procedure for the untouched final Android
11.6.3 build. It preserves original hostnames/HTTPS and uses a rooted test device
only for reversible routing plus manually managed system-CA trust.

## Static facts that drive the test

For the exact hash-verified final 11.6.3 arm64 IL2CPP specimen:

- package: `jp.co.bandainamcoent.BNEI0242`;
- unique MAIN/LAUNCHER activity:
  `jp.co.cygames.stage.StageUnityPlayerActivity`;
- API/resource traffic uses `UnityWebRequest` on the proven paths;
- no managed `CertificateHandler` / `ValidateCertificate` override or application
  pinning implementation is proven on the bootstrap path;
- `Stage.LoadTask.Parse` is RVA `0x04850a94`;
- result code 214 persists `required_res_ver=10133800` into Savedata `RES_VER` and
  does **not** automatically resend `/load/check` in the same network coroutine;
- the parent continuation resumes through
  `AssetManager.InitializeManifest -> DownloadOrLoadForInitialize` before
  BootMain reaches `/load/index`;
- `Home=6`, `Login_Bonus=7`, `Asset_Download=8`;
- `/load/title` is not a hard Home prerequisite;
- `data.isS3=false` selects `storages.game.starlight-stage.jp`.

The launcher is derived with `aapt dump badging` from the exact hash-verified
XAPK. The extractor accepts only package `jp.co.bandainamcoent.BNEI0242`,
versionName `11.6.3`, versionCode `438`, and requires exactly one distinct
launchable activity across matching APK splits. It is not a guessed Unity class.

The reduced starter creates its owned card through
`cs_gacha_data_cenere -> WorkCardData.AddCardData`, keeps `user_card_list=[]` and
`user_chara_list=[]`, and backs unit serial `1` with an actual WorkCardData entry.
Original-client acceptance of that synthetic state remains runtime-pending.

## 1. Install dependencies

```powershell
python -m pip install -r .\server\requirements.txt
```

## 2. Generate one disposable multi-SAN certificate

```powershell
python .\scripts\make-test-tls-cert.py `
  --hostname apis.game.starlight-stage.jp `
  --hostname storages.game.starlight-stage.jp
```

Default private material is under gitignored `work/tls/`:

```text
work/tls/ca.cert.pem
work/tls/ca.key.pem
work/tls/server.chain.pem
work/tls/server.key.pem
```

Never commit private keys.

## 3. Manually prepare rooted Android trust/routing

Install `work/tls/ca.cert.pem` into the **system** trust domain using the root
manager/ROM-specific mechanism. Android 14+/Conscrypt/APEX layouts vary; the repo
deliberately does not automate this persistent mutation.

Make both original names resolve to device loopback:

```text
127.0.0.1 apis.game.starlight-stage.jp
127.0.0.1 storages.game.starlight-stage.jp
```

Keep the original names intact so Host, TLS SNI and SAN verification remain
realistic.

## 4. Host resource preflight — schema 3

The preferred supervisor runs this automatically. For the first device session it
is still useful to run explicitly:

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

Schema 3 verifies:

```text
manifest SQLite quick_check/count/hash-shape
all 220803 content-addressed objects present and non-zero
all_dbmanifest parses Android_AHigh_SHigh MD5
Android_AHigh_SHigh compressed MD5 matches that index
Android_AHigh_SHigh CGSS-wrapper/LZ4 decodes
wire decode is SQLite
wire-decoded SQLite bytes == supplied manifest DB
master.mdb entry exists
master.mdb content-addressed object exists
master.mdb actual MD5 == manifest hash
```

The report exposes only counts, booleans and failure codes. It does not output
resource names/hashes or database contents. Do not continue unless it returns
exit code 0 and `ready: true`.

The resolver itself is separately verified against every final manifest row:

```text
220837 resolved
0 unresolved
0 hash mismatch
0 unknown category
```

This includes 12317 path-shaped manifest names; basename aliases are intentionally
not used because the final manifest contains colliding basenames.

For a slower preservation-grade byte audit after copying/restoring the archive:

```powershell
python .\scripts\audit-local-resource-objects.py `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db
```

That optional audit hashes every unique object; it is not part of each launch.

## 5. Start the whole host stack under the supervisor

Preferred first-run command:

```powershell
python .\scripts\run-rooted-local-stack.py `
  --resource-root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --ca-cert .\work\tls\ca.cert.pem `
  --api-map .\work\final_map.json `
  --viewer-id 1 `
  --producer-name "Relive Producer"
```

The supervisor gates readiness in this order:

```text
resource preflight schema 3
  -> API backend 127.0.0.1:8080 /healthz
  -> resource backend 127.0.0.1:8081 /healthz
  -> TLS mux 127.0.0.1:8445
  -> API original hostname: CA chain + SAN/SNI + Host /healthz
  -> storages original hostname: CA chain + SAN/SNI + Host /healthz
  -> foreground fail-fast monitoring
```

The TLS readiness probe connects to loopback at the TCP layer but uses each
original hostname as `server_hostname`, and trusts only the generated local CA.
Therefore a wrong CA, broken chain or missing original-host SAN is rejected before
`stack ready` is printed. Android system-CA visibility is still a separate device
acceptance gate.

Default behavior is native resource-version negotiation. Do not pass
`--accept-old-resource-version` on the primary run.

Sanitized runtime evidence is written to:

```text
work/runtime-starter-control.jsonl
work/runtime-starter-resource.jsonl
```

Any unexpected child exit tears down the full local stack.

## 6. Create exactly one device 443 reverse

The tunnel helper defaults to the TLS mux port `8445`:

```powershell
.\scripts\prepare-device-tunnel.ps1 -RequireRoot
```

Equivalent explicit form:

```powershell
.\scripts\prepare-device-tunnel.ps1 `
  -DevicePort 443 `
  -HostPort 8445 `
  -RequireRoot
```

Topology:

```text
CGSS https://apis.game.starlight-stage.jp:443
CGSS https://storages.game.starlight-stage.jp:443
                |
         device 127.0.0.1:443
                |
           adb reverse
                |
      host 127.0.0.1:8445 TLS mux
          /                    \
 API :8080                 resource :8081
```

Do not create two competing `adb reverse tcp:443` mappings.

Cleanup:

```powershell
.\scripts\prepare-device-tunnel.ps1 -Remove
```

## 7. Run the read-only device preflight — schema 2

Before launching the game:

```powershell
.\scripts\check-rooted-device.ps1
```

For a selected ADB device:

```powershell
.\scripts\check-rooted-device.ps1 -Serial <adb-serial>
```

It does **not** mutate package data, hosts, CA stores or system files. Core
`ready:true` requires:

```text
ADB state = device
su -c id returns uid=0
package jp.co.bandainamcoent.BNEI0242 is installed
versionName = 11.6.3
versionCode = 438
PackageManager MAIN/LAUNCHER resolves to:
  jp.co.bandainamcoent.BNEI0242/jp.co.cygames.stage.StageUnityPlayerActivity
adb reverse contains tcp:443 -> tcp:8445
API hostname is present on a 127.0.0.1 hosts entry
storages hostname is present on a 127.0.0.1 hosts entry
```

The launcher check is a runtime cross-check against the activity independently
extracted from the exact frozen XAPK.

If `work/tls/ca.cert.pem` is available, the script additionally looks for an
exact-byte SHA-256 match in common system-CA directories. That check is
**advisory**: root managers may install/re-encode certificates in ways that do not
preserve exact file bytes. A negative result is not proof that Android does not
trust the CA; actual CGSS TLS acceptance remains decisive.

Do not launch the client until the core device report is `ready:true`.

## 8. Exact launch + private package-scoped logcat capture

The preferred real-client entry is now:

```powershell
.\scripts\capture-device-logcat.ps1 `
  -Launch `
  -ClearBuffer `
  -RawPath .\work\private\runtime-starter-logcat.txt `
  -SanitizedPath .\work\runtime-starter-device.jsonl
```

For a selected device, add `-Serial <adb-serial>`.

With `-Launch`, this helper normally performs the read-only device preflight
first. It then:

```text
verify exact 11.6.3 / versionCode 438 package
force-stop prior target process
clear logcat if -ClearBuffer was requested
am start -W -n jp.co.bandainamcoent.BNEI0242/jp.co.cygames.stage.StageUnityPlayerActivity
wait for the exact package PID
capture only that PID's logcat to work/private/
on completion sanitize it to category-only JSONL
```

`-SkipDevicePreflight` exists only for a deliberate diagnostic session. Do not use
it on the primary acceptance run.

The raw file under `work/private/` can contain URLs, identifiers, certificate
messages or other sensitive values. It is gitignored. **Do not commit, upload or
share the raw logcat.** The sanitizer emits only:

```text
time
category
severity
```

Device categories are diagnostic evidence such as TLS/network/crash/ANR. They do
not advance HTTP/resource/Home phases by themselves.

Press Ctrl+C after the desired startup outcome/failure has been reproduced; the
finally path runs the sanitizer over the private capture.

## 9. Native `/load/check` — primary experiment

The untouched binary starts with:

```text
RES-VER: 10133000
```

Default local response:

```text
result_code = 214
required_res_ver = 10133800
data.isS3 = false
```

Expected statically closed progression:

```text
/load/check 214
-> Savedata RES_VER=10133800
-> SetupNetwork finishes
-> InitializeManifest
-> all_dbmanifest / Android_AHigh_SHigh / resource work
-> GameInitialize completes
-> BootMain.StartConnect
-> /load/index
-> Stage.LoadTask.Parse
-> Home(6) or Login_Bonus(7)
```

Do not require an immediate second `/load/check`; it is not part of the same-task
214 continuation.

## 10. Analyze server + device evidence — report schema 4

Merge the two server streams by timestamp and attach sanitized device diagnostics
to the same logical run:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run starter=.\work\runtime-starter-control.jsonl `
  --merge-run starter=.\work\runtime-starter-resource.jsonl `
  --device-log starter=.\work\runtime-starter-device.jsonl `
  -o .\work\runtime-starter-report.json
```

The HTTP/resource phase machine is driven **only** by server events. Device
logcat evidence is attached under `device_diagnostics`; it cannot fabricate
`/load/check`, resource-plane or Home progress.

A healthy native server timeline can be as small as:

```text
/load/check             214
@resource/manifest      200
@resource/Generic       200/206
/load/index             200
```

or include other resource categories. A second `/load/check` is not required.

If there is no HTTP event at all but `device_diagnostics` contains TLS/network
failures, diagnose the device trust/routing layer instead of changing response
payloads.

## 11. Diagnostic direct-success differential

Only if native 214 fails before useful resource evidence, restart the supervisor
with:

```text
--accept-old-resource-version
```

This returns success for old 10133000 while still advertising/advancing the final
required resource version. It is diagnostic only, not the native protocol model.

## Manual three-process mode

Use only to isolate one backend problem. The normal first run should use the
supervisor.

### API

```powershell
python -m server.http_server `
  --host 127.0.0.1 --port 8080 `
  --experimental-starter-load-index `
  --viewer-id 1 --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter-control.jsonl `
  --api-map .\work\final_map.json
```

### Resource backend

```powershell
python -m server.resource_server `
  --host 127.0.0.1 --port 8081 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --event-log .\work\runtime-starter-resource.jsonl
```

### TLS mux

```powershell
python -m server.tls_mux `
  --host 127.0.0.1 --port 8445 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --api-backend 127.0.0.1:8080 `
  --resource-backend 127.0.0.1:8081
```

## Acceptance questions, in order

1. Host resource preflight `ready:true`?
2. Supervisor verifies both TLS original-host routes and remains healthy?
3. Device read-only preflight schema 2 `ready:true`?
4. Does exact `StageUnityPlayerActivity` start and the CGSS process remain alive?
5. Does the actual CGSS process trust TLS and reach `/load/check`?
6. After native 214, does `@resource/*` traffic appear?
7. Are those requests served, or which sanitized category first returns 404/416?
8. Does `/load/index` arrive?
9. Does the reduced starter response produce a later client action?
10. Does Home visibly render (possibly after Login Bonus)?
11. What is the first unsupported post-Home endpoint/local-state dependency?

Server `200`/`result_code=1`, a green host preflight, or static `Home=6` are not by
themselves original-client acceptance evidence.

## Failure classification

### Host preflight fails

Fix the exact reported invariant before running the game. In particular, a wire
manifest DB mismatch means the two bootstrap wire files and manifest SQLite do not
belong to the same frozen state; a master MD5 mismatch means the content-addressed
path contains incorrect bytes.

### Device preflight core fails

Fix the ADB target/package/version/launcher/reverse/hosts condition. Do not
interpret a failure here as a CGSS protocol problem.

### TLS fails before HTTP

The host supervisor already verified the generated CA/chain/SAN locally. The main
remaining device-side question is whether that CA is actually in the CGSS
process's system trust domain. Keep original Host/SNI; do not patch the APK before
collecting the exact failure. Use the sanitized device diagnostic categories,
while keeping raw logcat private.

### 214 returned, no resource event

Static continuation says GameInitialize should proceed into manifest/resource
initialization. Check storages host routing, Android trust, Savedata state and
sanitized device diagnostics before using the direct-success differential.

### `@resource/unresolved` / 404

The final filename resolver has been checked against all 220837 manifest rows,
including 12317 path-shaped names. A new unresolved request is therefore strong
evidence of a URL family outside the current reconstructed builders, not a reason
to add fuzzy basename lookup.

### `/load/index` arrives, then stalls

Do not inflate the response with optional sections. The parser is guard-heavy and
partially populated guarded parents can be more dangerous than omission. Keep the
current reduced starter and identify the first actual blocker.

### Known endpoint 404 after Home

Use final Task/Parse evidence and implement only the parser-safe minimum. Never
return arbitrary empty success solely because the endpoint name is known.
