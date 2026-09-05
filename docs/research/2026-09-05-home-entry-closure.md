# Original 11.6.3 Home-entry runtime closure — 2026-09-05

## Result

The original untouched CGSS Android 11.6.3 client now reaches Home through its
own state machine. The previous runtime blocker was the legitimate first-time
Asset Download page with 4927 predownload entries; that download completed through
the original UI and the client naturally transitioned to Home.

This closure does **not** use a forced scene, parser bypass, forced success return,
TLS-verifier override, exception swallowing, or direct callback invocation.

## First-time download completion

A read-only Frida completion observer was attached while the existing download was
already in progress. It changed no arguments or return values. The observed terminal
sequence was:

```text
AssetDownload.FinishLoadCommonData @ 0x398850c
AssetDownload.FinishLoadStandardData @ 0x3988624
SceneManager.ChangeView(view=6, is_force=false)
```

The already-running main trace independently recorded the same natural scene
transition and then the actual Home lifecycle:

```text
Stage.Home.Start             @ 0x3ec16f8
Stage.Home.FinishLoad        @ 0x3ec49ac
Stage.Home.FinishLoad        @ 0x3ec49ac
Stage.Home.StartViewProcess  @ 0x3ecce20
```

No exception/error event was recorded after the first Home start.

## Cold-start persistence proof

After the first download completed, the app was force-stopped only for a deliberate
persistence check. A fresh instrumented launch used the same original client and
local API compatibility stack. After the known Title tap, the only scene IDs were:

```text
4 -> 5 -> 6
```

There was no scene 8 (`Asset_Download`). The cold run then repeated:

```text
/load/index Parse return = 1
BootMain.ChangeView
SceneManager.ChangeView(6, is_force=false)
Stage.Home.Start
Stage.Home.FinishLoad
Stage.Home.StartViewProcess
```

This closes the possibility that the first Home entry was merely a transient
post-download state. The client persisted its first-time resource-download state
and now returns to Home on a cold launch without re-entering Asset Download.

## Runtime/API scope

The successful Home proof used:

```text
control/API host:
  apis.game.starlight-stage.jp -> local compatibility stack

/load/check:
  result_code=1 at persisted RES_VER 10133800
  isS3=true

bulk resource family:
  official asset-starlight-stage.akamaized.net CDN
```

Therefore the milestone proven here is **original-client bootstrap and Home
acceptance**. Full offline preservation still requires closing the resource plane
so later preserved use does not depend on the official CDN.

## Gitignored evidence

```text
work/runtime/home-official-assets-s3-clean.jsonl
work/runtime/asset-download-completion-live.jsonl
work/runtime/cgss-home-after-download.png
work/runtime/home-cold-after-download.jsonl
work/runtime/cgss-home-cold-verified.png
work/runtime-api-home-cold-after-download.jsonl
```

The screenshot artifacts are retained only as local runtime evidence. Research
Frida scripts/logs must remain out of the final preservation artifact.

## Next blocker policy

Do not reopen bootstrap/Home work unless a later cold run contradicts this evidence.
Continue from Home and isolate exactly one unsupported endpoint/local-state
consumer at a time. Implement only runtime-proven clean-room contracts and keep
client-side changes restricted to environmental compatibility boundaries.
