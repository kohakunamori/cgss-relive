# CGSS Android 11.6.3 `/load/check` reconstruction

This note records the clean-room understanding of the final Android 11.6.3
version-check path and the behavior implemented by `cgss-relive`.

## Exact final-client targets

For the hash-verified final arm64 IL2CPP specimen:

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
| `Cute.Certification.Login` | `0x050bdd9c` |
| `Cute.BootNetwork.SetupNetwork` | `0x050c6c84` |
| `<SetupNetworkCoroutine>d__11.MoveNext` | `0x050c74dc` |
| `Stage.ResourcesManager.GameInitialize` | `0x037340ac` |
| `<GameInitialize>d__85.MoveNext` | `0x0374ed34` |
| `Cute.AssetManager.InitializeManifest` | `0x050a9000` |

Important correction: `0x0374eed8` is **not** the `GameInitialize` coroutine
entry. It is the direct `bl Cute.BootNetwork.SetupNetwork` instruction inside
`<GameInitialize>d__85.MoveNext`.

## Response wire path

The common HTTP completion path performs:

```text
HTTP response body
  -> CGSS AES/base64 decode
  -> MessagePack -> JSON/LitJson
  -> NetworkTask.SetResponseData
  -> CheckResult / task Parse
```

The repository response codec is the tested inverse of the final-client request
envelope. Response cryptography is no longer the main uncertainty.

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

For result code `214`:

1. the HTTP/network coroutine accepts 214 through the final-client allowed-code
   path instead of treating it as a generic transport failure;
2. common result handling persists `required_res_ver` into Savedata `RES_VER`;
3. no popup is required for 214 in this path;
4. the same network coroutine does **not** automatically resend `/load/check`.

Therefore do not model 214 as:

```text
/load/check 10133000 -> 214 -> immediate /load/check 10133800
```

unless a real runtime independently happens to show a later check.

## The parent continuation is now statically closed

The earlier documentation stopped at “some unknown higher-level resource
transition after 214”. Bounded final-client coroutine evidence closes that gap.

`BootMain.Initialize` starts `ResourcesManager.GameInitialize`:

```text
0x39ce8b4  bl  Stage.ResourcesManager.GameInitialize
0x39ce8c4  bl  UnityEngine.MonoBehaviour.StartCoroutine
```

`GameInitialize` starts the network setup:

```text
0x374eed8  bl  Cute.BootNetwork.SetupNetwork
```

`SetupNetworkCoroutine` directly calls and yields `Certification.Login`:

```text
0x50c758c  bl  Cute.Certification.Login
0x50c759c  bl  UnityEngine.MonoBehaviour.StartCoroutine
state <- 1
return true
```

The existing-viewer login path owns `VersionCheckTaskExec`, hence `/load/check`.
After setup becomes ready, `GameInitialize` resumes and directly starts manifest
initialization:

```text
0x374ef00  read BootNetwork ready flag
0x374ef04  if not ready -> yield/poll
...
0x374ef38  bl  Cute.AssetManager.InitializeManifest
0x374ef4c  bl  UnityEngine.MonoBehaviour.StartCoroutine
state <- 2
return true
```

`AssetManager.<InitializeManifest>d__65.MoveNext` in turn invokes
`DownloadOrLoadForInitialize` from multiple states, including call sites
`0x50b103c`, `0x50b1094`, and `0x50b1324`.

The final native mainline is therefore:

```text
BootMain.Initialize
  -> ResourcesManager.GameInitialize
  -> BootNetwork.SetupNetwork
  -> SetupNetworkCoroutine
  -> Certification.Login
  -> VersionCheckTaskExec
  -> /load/check RES-VER=10133000
  -> server: 214 + required_res_ver=10133800
  -> client persists Savedata RES_VER=10133800
  -> SetupNetwork completes / ready
  -> GameInitialize resumes
  -> AssetManager.InitializeManifest
  -> manifest/resource DownloadOrLoadForInitialize
  -> GameInitialize completes
  -> BootMain.Initialize resumes
  -> BootMain.StartConnect
  -> /load/index
```

A second `/load/check` is not a required link in this static chain.

## Resource-host selector: `data.isS3`

`Cute.VersionCheckTask.Parse` is the confirmed writer of `NetworkUtil.isS3`:

```text
response data["isS3"] -> ToBoolean -> NetworkUtil.isS3
```

The selector chooses between final resource hosts/URL families:

```text
isS3 = false -> storages.game.starlight-stage.jp
isS3 = true  -> asset-starlight-stage.akamaized.net
```

The offline server fixes `isS3=false` so resource routing is deterministic and
matches the storage-family support in `server.resource_server`.

## Default preservation policy

Default server behavior remains native version negotiation:

```text
incoming RES-VER != 10133800
  -> result_code = 214
  -> required_res_ver = 10133800
  -> data.isS3 = false

incoming RES-VER == 10133800
  -> result_code = 1
  -> data.isS3 = false
```

The important runtime observation after the first 214 is now **resource-plane
traffic**, not an expected retry.

## Diagnostic direct-success policy

For a controlled differential the server exposes:

```text
--accept-old-resource-version
```

When the client sends `RES-VER: 10133000`, this mode returns:

```text
result_code = 1
required_res_ver = 10133800
data.isS3 = false
```

This mode separates the native 214/resource branch from later BootMain or
`/load/index` failures. It is not the protocol-default model.

## Sanitized runtime evidence

The control API event log and resource server event log use the same strict
sanitized schema. The resource server may be started with `--event-log`; it logs
only synthetic categories:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

It never logs resource filenames, hashes, query strings, request bodies, UDID,
SID, USER-ID, PARAM, or viewer/account values.

`scripts/analyze-runtime-events.py` treats:

```text
214 response -> later @resource/*
```

as direct evidence that the client advanced into the statically proven
`InitializeManifest`/resource stage even when no second `/load/check` appears.

## Evidence boundary

A server-side 214 or success event proves what the server returned. A resource
request proves the client advanced into resource initialization. `/load/index`
proves the client advanced beyond that resource stage.

Visible Home still requires an original-client runtime observation; static
control flow alone does not claim that a particular local run rendered Home.
