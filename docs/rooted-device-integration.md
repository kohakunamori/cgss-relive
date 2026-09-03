# Rooted Android integration for the final CGSS 11.6.3 client

This is the real-client acceptance procedure for the untouched final Android
11.6.3 build. It preserves the original hostname/HTTPS behavior and uses a rooted
test device only for reversible DNS/hosts and system-CA integration.

## Static facts that now drive the test

For the final 11.6.3 IL2CPP specimen:

- API traffic uses `UnityWebRequest`;
- no managed `CertificateHandler` subclass or `ValidateCertificate` override was
  found;
- no managed/Java certificate-pinning implementation is wired into the API path;
- the manifest has no `networkSecurityConfig` and targets modern Android, so a
  user CA alone is not a reliable trust path;
- `Stage.LoadTask.Parse` is RVA `0x04850a94`;
- successful `/load/index` parsing flows through
  `BootMain.CallbackOnSuccessLoad -> LastInitialized -> ChangeView(6|7)` toward
  the Home view;
- `/load/title` is a user-driven TitleTask and is **not** a proven prerequisite
  for entering Home;
- result code 214 persists `required_res_ver` but does **not** automatically
  resend `/load/check` inside the same network task;
- successful `VersionCheckTask.Parse` consumes `data.isS3`; the preservation
  server fixes it to `false`, selecting the `storages.game.starlight-stage.jp`
  URL family.

The remaining uncertainty is runtime state-machine behavior between version
checking/resource initialization and BootMain, not response cryptography.

## 1. Install server dependencies

From the repository root:

```powershell
python -m pip install -r .\server\requirements.txt
```

## 2. Generate disposable API TLS material

```powershell
python .\scripts\make-test-tls-cert.py
```

Default output is under gitignored `work/tls/`:

```text
work/tls/ca.cert.pem
work/tls/ca.key.pem
work/tls/server.cert.pem
work/tls/server.key.pem
work/tls/server.chain.pem
```

The API certificate must contain a SAN for:

```text
apis.game.starlight-stage.jp
```

Never commit private keys.

## 3. Trust the CA as a system CA

Use the rooted device/root manager's supported system-CA mechanism. Android
14+/Conscrypt/APEX layouts differ across Magisk, KernelSU and ROMs, so the
repository intentionally does not automate this mutation.

The acceptance condition is that the CGSS app process trusts the CA through the
system trust domain. Merely seeing the certificate in the user-certificate UI is
not sufficient.

## 4. Redirect the control hostname

For the first control-path test, make this hosts mapping effective on the device:

```text
127.0.0.1 apis.game.starlight-stage.jp
```

Use a reversible/systemless hosts mechanism. Keep the original hostname so Host,
TLS SNI and certificate SAN still match production semantics.

Do **not** redirect a resource hostname for the direct-success differential. Add
resource redirection only when exercising the real 214/resource-update path.

## 5. Bridge device TCP 443 to the host

```powershell
.\scripts\prepare-device-tunnel.ps1 -HostPort 8443 -RequireRoot
```

For a specific ADB target:

```powershell
.\scripts\prepare-device-tunnel.ps1 -Serial <serial> -HostPort 8443 -RequireRoot
```

Conceptually:

```text
CGSS -> https://apis.game.starlight-stage.jp:443
          device hosts -> 127.0.0.1
          adb reverse tcp:443 -> tcp:8443
          host cgss-relive TLS server
```

Remove the mapping with:

```powershell
.\scripts\prepare-device-tunnel.ps1 -Remove
```

## 6. Start with the starter-visible `/load/index` profile

The first real-client run should use the one-card starter-visible profile, not the
old strict-minimal profile. The final parser proves that a non-empty unit element
needs `unit_slot` + `name` in its first pass and `unit_id` + `name` in a later
pass; the builder/validator now reflects that contract.

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter.jsonl `
  --api-map .\work\final_map.json
```

`--api-map` is optional. When present it is used only to annotate sanitized
unknown-route events with the validated final endpoint identity; it does not
invent responses.

Implemented bootstrap/control routes currently include:

```text
POST /load/check
POST /load/title
POST /load/index
POST /load/set_cache_clear_flg
POST /load/update_agreement_status
GET  /healthz
```

The event log deliberately excludes UDID, SID, USER-ID, PARAM, viewer-id values
and decoded request/response values. It records only safe headers, route/status,
key shapes, result-code/resource-version summaries and endpoint candidates.

## 7. Two `/load/check` experiments

The two modes answer different questions and must not be conflated.

### A. Native resource-version negotiation (default)

With incoming `RES-VER: 10133000`, the server returns:

```text
result_code = 214
required_res_ver = 10133800
```

Final-client static analysis proves that 214 is a skip/allowed business code at
the network layer, `required_res_ver` is persisted into Savedata `RES_VER`, and
there is **no automatic resend inside the same d48 request coroutine**. A later
request or resource update belongs to a higher-level state machine.

Use this mode when testing the complete frozen-resource path.

### B. Diagnostic direct success

To distinguish the 214/resource-update path from a later BootMain blocker:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --accept-old-resource-version `
  --experimental-starter-load-index `
  --event-log .\work\runtime-direct.jsonl
```

For incoming `10133000`, this returns `result_code=1` while still supplying
`required_res_ver=10133800`. This is a controlled differential only: it bypasses
the native 214 gate but does not prove that every local resource prerequisite is
satisfied.

Both modes return `data.isS3=false` when the load-check data object is parsed.

## 8. Resource-host integration for the native 214 path

Static analysis reconstructs the default resource host as:

```text
storages.game.starlight-stage.jp
```

when `isS3=false`. The Akamai host is the `isS3=true` branch and has different
hash-prefix behavior.

Prepare the local resource server as documented in
`docs/local-resource-server.md`. A full filename-addressed storages run should
supply the local final manifest database:

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

The resource certificate needs a SAN for the resource hostname. The API
certificate cannot simply be reused unless it was generated with both SANs.

If the client needs the initial resource wire manifests, place verified local
copies under:

```text
resource-cache/10133800/manifests/all_dbmanifest
resource-cache/10133800/manifests/Android_AHigh_SHigh
```

No proprietary manifest/database/resource file is committed.

## 9. Analyze the sanitized run

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl
```

If the starter-visible run fails after `/load/index`, use empty/strict profiles
only as controlled differentials rather than as the default first attempt.

For example:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl `
  empty=.\work\runtime-empty.jsonl `
  strict=.\work\runtime-strict.jsonl
```

## Acceptance questions, in order

The first real run should answer these questions without overclaiming:

1. Does TLS complete and does `/load/check` reach the server?
2. In native mode, after the server returns 214, what is the **next observed
   client action**: resource URL, process/view transition, later `/load/check`, or
   error?
3. Does any later control request carry `RES-VER: 10133800`?
4. In direct-success mode, does the client proceed farther than native mode?
5. Does BootMain reach `/load/index`?
6. Does `/load/index` return success and is a later client action observed?
7. Does `ChangeView(6|7)` produce the visible Home/login-bonus flow on device?
8. What is the first unsupported route or local-state/content blocker after that?

A server-side `result_code=1` event alone proves only that the server returned a
success response. It does **not** prove client acceptance. Client acceptance needs
a later observable client action.

## Current static mainline

The currently closed portion is:

```text
ResourcesManager.GameInitialize
  -> BootNetwork.SetupNetwork
  -> SetupNetworkCoroutine
  -> Certification.Login
  -> /load/check (existing viewer)
  -> [higher-level resource/view state transition still not closed]
  -> BootMain.FinishLoad
  -> BootMain.Initialize
  -> asset predownload/verify
  -> BootMain.StartConnect
  -> /load/index
  -> Stage.LoadTask.Parse
  -> Parse == 1
  -> BootMain.CallbackOnSuccessLoad
  -> LastInitialized
  -> BootMain.ChangeView
  -> SceneManager.ChangeView(6|7)
  -> Home semantics (view enum mapping still needs runtime/static closure)
```

`/load/title` belongs to the Title user-interaction branch and should not be
inserted into this mainline merely because the endpoint exists.

## Failure classification

### No server request

Check hostname resolution, ADB reverse, IPv6 and whether the client selected a
different hostname.

### TLS error before HTTP

Check that the CA is visible as a system root, certificate dates/SAN are correct,
and SNI/Host remain the original hostname. Do not patch the APK before collecting
the exact failure.

### 214 returned and nothing else is observed

Do not call this a failed `/load/check` parse. Static analysis says 214 can update
Savedata without an in-coroutine retry. Compare with direct-success mode and, if
needed, redirect/serve the storages resource hostname to observe the higher-level
resource state machine.

### Resource request returns 404

Record the exact path. The local resource server now supports the statically
reconstructed URL families; a 404 should mean a missing manifest index entry,
missing local object/wire manifest, unsupported builder shape, or wrong frozen
version rather than the old single-template assumption.

### `/load/index` arrives and then the client stalls/errors

Do not add hundreds of optional fields. `LoadTask.Parse` is highly guard-driven
and can silently truncate if a provided structure omits a hard child. First
compare the sanitized sequence and starter/empty/strict differential, then adjust
only a statically or runtime-proven dependency.

### Known final endpoint returns 404

Use the `api_candidates` annotation to select that endpoint's exact final-client
Task/Parse path. Do not return an arbitrary empty success unless its parser proves
that shape safe.
