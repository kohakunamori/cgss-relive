# CGSS 11.6.3 research client

This directory belongs to the `client-research-fixed` research branch. It exists
to shorten original-client reverse-engineering iterations without weakening the
server acceptance target.

## Policy

There are two distinct artifacts:

- **Untouched 11.6.3** remains the preservation acceptance client. A server-side
  milestone such as visible Home is only considered proven when this client
  reaches it without protocol-semantic patches.
- **Research-fixed 11.6.3** is a locally rebuilt and locally signed diagnostic
  client. It may change Android shell/network/debug configuration and add
  instrumentation, but it must not silently make malformed API state valid.

Do not commit original APK/XAPK/splits, native game binaries, metadata, assets,
production credentials, or research signing keys. Existing `.gitignore` rules
keep these under `work/` out of Git.

## Exact runtime baseline

The native instrumentation points in `instrumentation-points.yml` are tied to:

```text
package          jp.co.bandainamcoent.BNEI0242
versionName      11.6.3
versionCode      438
Unity            2022.3.56f1
IL2CPP metadata  31

libil2cpp.so SHA-256
2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5

global-metadata.dat SHA-256
2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

Do not reuse the RVAs on another build.

## Build the first research APK set

Acquire the installed original package first:

```powershell
./scripts/pull-installed-apk.ps1
```

This creates a timestamped specimen directory under `work/apk/` containing
`manifest.json`, `base.apk`, and every installed split.

Build a research copy from that exact specimen:

```powershell
./scripts/build-research-client.ps1 -SpecimenDir work/apk/<timestamp>
```

The first research build deliberately makes only Android-shell changes:

```text
android:debuggable=true
android:usesCleartextTraffic=true
android:networkSecurityConfig=@xml/relive_network_security_config
trust system + user CA stores through Android Network Security Config
re-sign base + every split with one local research key
```

Output is written under:

```text
work/research-client/apks/
work/research-client/research-build.json
work/research-client/cgss-research.jks
```

The signing key is local research material and must never be committed.

Because the Play-installed original and the research set have different signing
certificates, Android cannot update one over the other. On a dedicated research
device, preserve any local data you still need and then run:

```powershell
./scripts/install-research-client.ps1 -UninstallOriginal
```

Without `-UninstallOriginal`, the installer first tries a non-destructive
`install-multiple -r` and explains a likely signature mismatch if Android
rejects it.

## Runtime instrumentation

The initial Frida script is intentionally bounded. It records only entry/exit
of already recovered IL2CPP methods such as:

```text
Cute.NetworkTask.PrepareHeaders
Cute.NetworkTask.PreparePostData
Cute.NetworkTask.CreateBody
Cute.CryptAES.EncryptRJ256
Cute.CryptAES.DecryptRJ256
Cute.Certification.VersionCheckTaskExec
Cute.BootNetwork.SetupNetworkCertification
Stage.LoadTask.Parse
```

It does **not** dump decrypted request/response payloads, credentials, viewer
IDs, UDIDs, or arbitrary process memory.

With a matching Frida server running on the rooted Android research device:

```powershell
python ./scripts/run-research-trace.py
```

Events are written to the gitignored file:

```text
work/runtime/cgss-research-trace.jsonl
```

Attach to an already running game instead of spawning it with:

```powershell
python ./scripts/run-research-trace.py --attach
```

## Next patch stages

Changes should be added in this order and each stage should remain independently
reviewable:

1. prove whether Android user-CA/network-security changes actually affect the
   final Unity transport;
2. add more bounded parser/resource/work-data instrumentation based on the first
   real runtime blocker;
3. only after a native behavior is understood, add byte patches with the exact
   `libil2cpp.so` hash **and expected original bytes** recorded next to each
   patch point;
4. keep protocol-bypass experiments explicitly labeled and never use them as
   untouched-client acceptance evidence.

In particular, do not make the research client automatically swallow missing
`/load/index` keys, force `result_code=1`, skip resource initialization, or
force `SceneManager` to Home as the normal development path. The purpose of the
research client is to make failures observable, not to hide them.
