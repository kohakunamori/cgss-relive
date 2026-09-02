# Rooted Android integration for the final CGSS 11.6.3 client

This document is the first real-client integration path for the supplied final
Android 11.6.3 build.  It keeps the client hostname and HTTPS semantics intact
while redirecting only the CGSS control API to a local `cgss-relive` server.

## Why HTTPS is the default

The final 11.6.3 client targets modern Android and its manifest does not declare a
custom `networkSecurityConfig` or a cleartext opt-in.  Static IL2CPP metadata
contains Unity/Mono's normal certificate-validation surface but, so far, no game
class overriding a `ValidateCertificate` method has been found.

That is evidence against a managed custom certificate pin, not a guarantee that
no native/plugin validation exists.  The least invasive integration experiment
therefore preserves:

- hostname: `apis.game.starlight-stage.jp`
- scheme: HTTPS
- port from the client's point of view: 443
- original Host header and TLS SNI

A local test CA is trusted as a **system** CA on a dedicated rooted device.  A
user-installed CA alone is not a reliable choice for a modern target-SDK app.

Do not redirect the asset CDN yet.  The first test redirects only the control API
hostname so resource downloads can remain independently observable.

## 1. Install Python dependencies

From the repository root:

```powershell
python -m pip install -r .\server\requirements.txt
```

## 2. Generate disposable TLS material

```powershell
python .\scripts\make-test-tls-cert.py
```

Default output is under the gitignored `work/tls/` directory:

```text
work/tls/ca.cert.pem
work/tls/ca.key.pem
work/tls/server.cert.pem
work/tls/server.key.pem
work/tls/server.chain.pem
```

The server certificate contains a SAN for:

```text
apis.game.starlight-stage.jp
```

Never commit or share the generated private keys.

## 3. Make the test CA a system-trusted CA

This step is intentionally not automated in the repository because Android 14+
Conscrypt/APEX layouts and root-manager overlay mechanisms differ across Magisk,
KernelSU and ROMs.

On the dedicated rooted device, use the root solution's supported system-CA
mechanism to make `work/tls/ca.cert.pem` trusted by apps as a **system** CA.  If
the root solution offers a "trust user certificates as system" or systemless CA
module, use a version compatible with that Android release.

After changing the system CA set, reboot if the root/overlay mechanism requires
it.

The important acceptance condition is not merely that the certificate appears in
Android Settings; the application process must see it through the platform trust
store.

## 4. Redirect only the control hostname to loopback

The rooted device needs this effective hosts entry:

```text
127.0.0.1 apis.game.starlight-stage.jp
```

Use the root manager's systemless-hosts mechanism or another reversible rooted
hosts override.  Do not edit a read-only system partition in place just for this
experiment.

Confirm from a root shell that name resolution reaches loopback before launching
the client.

## 5. Bridge device port 443 to the host

The helper keeps the client on port 443 while allowing the development server to
run unprivileged on host port 8443:

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

Remove the reverse mapping with:

```powershell
.\scripts\prepare-device-tunnel.ps1 -Remove
```

## 6. Start the current bootstrap server

The static-parser-derived `/load/index` profile is still experimental, so it is
behind an explicit switch:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-minimal-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-events.jsonl
```

The event log is intentionally sanitized. It contains route/status, APP/RES/Unity
version headers, decoded request key names and response key/result-code shape. It
does **not** write UDID, SID, USER-ID, PARAM or decoded request/response values.
That file is the preferred artifact to share back during the first integration
run.

Implemented routes at this stage:

```text
POST /load/check
POST /load/title
POST /load/index
GET  /healthz
```

`/load/check` negotiates resource revision `10133800`.  `/load/title` uses the
statically proven minimal success response.  `/load/index` uses the candidate
synthetic profile documented in `docs/load-index-11.6.3.md`.

## 7. First runtime acceptance test

Start with a dedicated test install/state, then launch CGSS while observing its
process logcat plus `work/runtime-events.jsonl`.

The first useful outcomes are deliberately narrow:

1. Does TLS complete?
2. Does the server receive `POST /load/check`?
3. Does the client accept the encrypted response and continue/restart according
   to the resource-version result?
4. Which endpoint is requested next?
5. If `/load/index` is reached, does the candidate minimal profile parse, or what
   is the first missing/state-dependent field?

Do not collect or commit raw production credentials.  For a golden fixture,
retain only a dedicated test installation and sanitize identifiers/session
values before committing anything under `tests/fixtures/`.

## Failure classification

### No server request at all

Check hostname resolution, the ADB reverse mapping and whether the process is
using IPv6 or another API hostname.

### TLS/certificate error before HTTP

The most likely causes are that the CA is only user-trusted, the certificate SAN
or date is wrong, or the final client has a validation path not visible in the
managed metadata.  Capture the exact logcat error before modifying the APK.

### HTTP request arrives but client reports a connection/protocol error

Record the route and HTTP status.  The wire codec is already round-trip tested;
this class of failure is more likely a response-schema/state issue than TLS.

### `/load/index` arrives and then the client errors

This is the expected place for the next schema iteration.  The profile is
explicitly a static candidate, not yet a runtime-proven complete account model.
The first failing field/state transition becomes the next native-parser target.
