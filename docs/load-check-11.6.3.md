# CGSS Android 11.6.3 `/load/check` reconstruction

This note records the current clean-room understanding of the final Android
11.6.3 version-check path and the behavior implemented by `cgss-relive`.

## Final-client native targets

For the exact final arm64 IL2CPP specimen:

| Managed method | arm64 RVA |
| --- | ---: |
| `Cute.NetworkTask.SetResponseData` | `0x050cae58` |
| `Cute.NetworkTask.CheckResult` | `0x050cae60` |
| `Cute.NetworkTask.Parse` | `0x050c437c` |
| `Cute.VersionCheckTask.Parse` | `0x050c5400` |
| `Cute.CryptAES.decrypt` | `0x050c2434` |
| `Cute.Cryptographer.decode` | `0x050c3688` |
| `Cute.Certification.VersionCheckTaskExec` | `0x050bde1c` |
| `<VersionCheckTaskExec>d__43.MoveNext` | `0x050bf3c8` |
| `NetworkManager.<Connect>d__48.MoveNext` | `0x050b61c8` |

## Response wire path

The common HTTP completion path performs:

```text
HTTP response body
  -> CGSS AES/base64 decode
  -> MessagePack -> JSON/LitJson
  -> NetworkTask.SetResponseData
  -> CheckResult / task Parse
```

The repository's response codec is the tested inverse of the final-client
request envelope. Response cryptography is no longer the main uncertainty.

## Result-code constants

Final 11.6.3 constants:

| meaning | code |
| --- | ---: |
| success | `1` |
| session error | `201` |
| app-version error | `204` |
| resource-version error | `214` |

`data_headers.result_code` is the common business-code field.

## Correct 214 semantics

The previous bootstrap working model treated 214 as if it directly caused an
immediate `/load/check` retry. Final static control-flow analysis disproves that.

For a response with result code 214:

1. the d48 HTTP coroutine accepts 214 through the final-client skip/allowed-code
   table instead of treating it as a generic transport error;
2. common result handling persists `required_res_ver` into local Savedata
   `RES_VER`;
3. no popup is required for 214 in this path;
4. the same d48 coroutine does **not** automatically resend `/load/check`;
5. any later resource download, view transition or later version-check request is
   initiated by a higher-level boot/resource state machine.

Therefore this sequence is valid only as two observations separated by an
unknown higher-level transition:

```text
observed /load/check with RES-VER 10133000
server -> 214 + required_res_ver 10133800
client persists RES_VER = 10133800
... higher-level boot/resource behavior ...
possible later request(s) with RES-VER 10133800
```

Do not describe the second request as an automatic retry unless runtime evidence
actually shows it.

## Resource-host selector: `data.isS3`

`Cute.VersionCheckTask.Parse` is the confirmed writer of `NetworkUtil.isS3`:

```text
response data["isS3"] -> ToBoolean -> NetworkUtil.isS3
```

The selector chooses between the final resource hosts/URL families:

```text
isS3 = false -> storages.game.starlight-stage.jp
isS3 = true  -> asset-starlight-stage.akamaized.net
```

The offline server fixes `isS3=false` so the resource plane is deterministic and
matches the storages URL family supported by `server.resource_server`.

## Default preservation policy

The default server behavior remains native resource-version negotiation:

```text
incoming RES-VER != 10133800
  -> result_code = 214
  -> required_res_ver = 10133800
  -> data.isS3 = false

incoming RES-VER == 10133800
  -> result_code = 1
  -> data.isS3 = false
```

This models the final-client business-code path without inventing an immediate
retry.

## Diagnostic direct-success policy

For a controlled runtime differential, the server exposes:

```text
--accept-old-resource-version
```

When the client sends old `RES-VER: 10133000`, this mode returns:

```text
result_code = 1
required_res_ver = 10133800
data.isS3 = false
```

The purpose is to answer a narrow question: does bypassing the 214 gate allow the
client to reach a later BootMain or `/load/index` stage?

It is **not** the default protocol model and it does not prove that all local
resource prerequisites are satisfied. `required_res_ver` is still supplied so
common result handling can advance subsequent request headers to the frozen
version.

## Why both modes matter

A native-mode stall after server-side 214 is ambiguous because static analysis
says no in-coroutine retry should be expected. Compare:

- native 214 mode;
- direct-success mode;
- and, when needed, native mode with the local storages resource host redirected.

That three-way differential separates:

1. version-result handling;
2. higher-level resource initialization/update;
3. later BootMain `/load/index` parsing.

## Resource version facts

Keep these two values distinct:

```text
binary/default RES_VER: 10133000
frozen final server/resource revision: 10133800
```

`10133800` is independently validated by the repository's public-CDN bootstrap
and manifest/master verification workflow.

## Implemented modules

- `server/cgss_codec.py` — final request/response envelope;
- `server/header_codec.py` — reversible final UDID-header decode;
- `server/load_check.py` — native 214 and explicit direct-success policies;
- `server/bootstrap_core.py` — transport-independent request/response exchange;
- `server/http_server.py` — HTTPS/control front end, defaults `isS3=false`;
- `server/resource_server.py` — final-client resource URL-family resolver over
  the frozen content-addressed archive.

## Runtime evidence boundary

A server event showing `result_code=1` or 214 proves what the server returned.
It does not, by itself, prove the original client accepted the response.

Client acceptance requires a later observable client action such as:

- a resource request;
- a subsequent control request;
- `/load/index`;
- a view transition/logcat event;
- or visible Home behavior.

The sanitized runtime analyzer deliberately keeps this distinction.
