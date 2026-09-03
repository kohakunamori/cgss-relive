# Final Android 11.6.3 bootstrap static closure — 2026-09-03

This note records bounded clean-room static evidence produced from the exact final Android 11.6.3 specimen. The specimen was downloaded ephemerally, verified by frozen SHA-256 values, analyzed, and deleted before artifact upload. No APK/XAPK, ELF, metadata, bulk decompiler output, resource body, or account/session material is retained.

## Specimen identity

```text
package:      jp.co.bandainamcoent.BNEI0242
version:      11.6.3
versionCode:  438
XAPK SHA256:  609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d
arm64 libil2cpp.so SHA256:
              2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5
global-metadata.dat SHA256:
              2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

The CI analysis pipeline verifies all three hashes before static analysis. If a public mirror changes its `latest` file, analysis stops at the hash gate.

## Corrected native RVAs

The previous seed `0x0374EED8` was not the entry of `Stage.ResourcesManager.<GameInitialize>d__85.MoveNext`; it is the direct call site to `Cute.BootNetwork.SetupNetwork` inside that coroutine.

Confirmed final entries:

```text
Stage.ResourcesManager.GameInitialize                         0x037340AC
Stage.ResourcesManager.<GameInitialize>d__85..ctor           0x0374ED08
Stage.ResourcesManager.<GameInitialize>d__85.MoveNext        0x0374ED34
Cute.BootNetwork.SetupNetwork                                0x050C6C84
Cute.BootNetwork.SetupNetworkCoroutine                       0x050C6CB4
Cute.BootNetwork.<SetupNetworkCoroutine>d__11.MoveNext       0x050C74DC
Cute.Certification.Login                                     0x050BDD9C
Cute.Certification.VersionCheckTaskExec                      0x050BDE1C
Cute.Certification.<VersionCheckTaskExec>d__43.MoveNext      0x050BF3C8
Cute.AssetManager.InitializeManifest                         0x050A9000
Stage.BootMain.<Initialize>d__14.MoveNext                    0x039CE78C
Stage.BootMain.StartConnect                                  0x039C9A24
Stage.LoadTask.Parse                                         0x04850A94
Stage.BootMain.ChangeView                                    0x039C9960
Stage.SceneManager.ChangeView                                0x0373BD8C
```

## Resource/version continuation is now statically closed

`Stage.BootMain.<Initialize>d__14.MoveNext` directly calls and starts the `ResourcesManager.GameInitialize` coroutine:

```text
0x39CE8B4  bl  Stage.ResourcesManager.GameInitialize
0x39CE8C4  bl  UnityEngine.MonoBehaviour.StartCoroutine
```

Inside `Stage.ResourcesManager.<GameInitialize>d__85.MoveNext`:

```text
0x374EED8  bl  Cute.BootNetwork.SetupNetwork
...
0x374EF00  read BootNetwork ready flag
0x374EF04  if not ready -> yield/poll state
...
0x374EF38  bl  Cute.AssetManager.InitializeManifest
0x374EF4C  bl  UnityEngine.MonoBehaviour.StartCoroutine
0x374EF50  state <- 2
0x374EFA4  return true (yield)
```

`SetupNetwork` enters `SetupNetworkCoroutine`, whose state 0 directly calls and yields `Certification.Login`:

```text
0x50C758C  bl  Cute.Certification.Login
0x50C759C  bl  UnityEngine.MonoBehaviour.StartCoroutine
0x50C75A0  current <- coroutine
0x50C75A8  state <- 1
0x50C75AC  return true
```

The login/version path contains `VersionCheckTaskExec`, which owns `/load/check`. Existing static analysis already proves that result code `214` persists `required_res_ver` into Savedata `RES_VER` and does not resend `/load/check` inside the same network coroutine.

The newly closed parent continuation therefore makes the native path:

```text
BootMain.Initialize
  -> ResourcesManager.GameInitialize
  -> BootNetwork.SetupNetwork
  -> SetupNetworkCoroutine
  -> Certification.Login
  -> VersionCheckTaskExec
  -> /load/check
  -> 214 + required_res_ver=10133800
  -> persist Savedata RES_VER=10133800
  -> SetupNetwork completes / becomes ready
  -> GameInitialize resumes
  -> AssetManager.InitializeManifest
  -> manifest/resource DownloadOrLoadForInitialize state machine
  -> GameInitialize completes
  -> BootMain.Initialize resumes
  -> BootMain.StartConnect
  -> /load/index
```

This supersedes the old handoff phrase `higher-level resource/view transition NOT yet statically closed`. A second `/load/check` is not a required link in this static mainline.

## Manifest initialization continues into resource loading

`Cute.AssetManager.<InitializeManifest>d__65.MoveNext` contains multiple calls to:

```text
Cute.AssetManager.DownloadOrLoadForInitialize
```

at, among others:

```text
0x50B103C
0x50B1094
0x50B1324
```

The coroutine stores yielded work into its `current` field and advances its state before returning `true`. Thus `InitializeManifest` is not a no-op flag setter; it is the resource bootstrap stage that can issue manifest/object work before BootMain proceeds to `/load/index`.

## `/load/index` success -> exact Home mapping

`Stage.BootMain.ChangeView` has a bounded final-client instruction window:

```text
call LoginBonusData.IsExistLoginBonus
...
mov  w8, #6
test login-bonus result
cinc w1, w8, ne
b    Stage.SceneManager.ChangeView
```

The final `StageSceneDefine.eViewId` enum independently maps:

```text
BootMain       = 5
Home           = 6
Login_Bonus    = 7
Asset_Download = 8
```

Independent call-site corroboration includes:

```text
Stage.Footer.OnClickHomeButton -> SceneManager.ChangeView(6)
Stage.MenuTop.OnPushOsBackKey  -> SceneManager.ChangeView(6)
```

Therefore the post-`/load/index` tail is now statically confirmed as:

```text
/load/index
  -> Stage.LoadTask.Parse
  -> BootMain.CallbackOnSuccessLoad
  -> BootMain.LastInitialized
  -> BootMain.ChangeView
  -> no login bonus: Home (6)
     login bonus:    Login_Bonus (7), then normal flow can return Home
```

Visible Home entry remains runtime-pending only because the original client has not yet been run against the local stack in this environment; the numeric/name mapping itself is no longer a static gap.

## Runtime consequence

The first rooted-device run should treat the expected native progression as:

```text
/load/check 214
-> resource manifest/object traffic
-> /load/index
-> Home(6) or Login_Bonus(7)
```

A lack of a second `/load/check` is normal. The runtime tooling should therefore record sanitized resource-plane requests in addition to control-plane requests so that a run cannot be misclassified as stalled at 214 when it actually entered `InitializeManifest`.
