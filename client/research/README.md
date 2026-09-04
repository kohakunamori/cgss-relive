# CGSS 11.6.3 research client

This directory belongs to the `client-research-fixed` research branch. It exists
to shorten original-client reverse-engineering iterations without weakening the
server acceptance target.

## Policy

There are three distinct client artifacts:

- **Original 11.6.3** is the byte-exact frozen acceptance client. A server-side
  milestone such as visible Home is only considered proven when this client
  reaches it without client compatibility changes.
- **Preservation 11.6.3** is a thin compatibility client. It may change endpoint
  routing, TLS trust, asset routing, and modern Android compatibility, but it
  must keep original protocol parsers, game state, UI, Live, card, Home, and
  resource semantics intact. See `../preservation/README.md`.
- **Research 11.6.3** is Preservation behavior plus locally enabled diagnostic
  instrumentation. Research conveniences must not silently make malformed API
  state valid.

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

XAPK SHA-256
609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d

base APK SHA-256
c73fc868bcaaccb7912eddb4d6651189d52526c5df5c31ec9b12de8c06c19cee

arm64 split SHA-256
da2d09804bdc33a586e684599a42f496db4f43ceedc4359f45b89f8fc571d3c7

libil2cpp.so SHA-256
2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5

global-metadata.dat SHA-256
2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

Do not reuse the RVAs on another build.

## Prepare a research specimen

### From an installed original client

Acquire the installed package:

```powershell
./scripts/pull-installed-apk.ps1
```

This creates a timestamped specimen directory under `work/apk/` containing
`manifest.json`, `base.apk`, and the splits actually installed for that device.

### From the frozen XAPK

The repository also supports the exact frozen XAPK hash above without committing
it to Git:

```powershell
python ./scripts/extract-xapk-specimen.py \
  "C:/path/to/デレステ-11.6.3.xapk" \
  -o work/apk/frozen-11.6.3
```

By default this extracts only the base APK and arm64 split, which is the useful
set for the arm64 research device. The helper verifies the XAPK, base, arm64
split, `libil2cpp.so`, and `global-metadata.dat` hashes before declaring the
specimen exact. Use `--include-armeabi-v7a` only when a 32-bit split is actually
needed.

## Build the first research APK set

Build a research copy from either specimen layout:

```powershell
./scripts/build-research-client.ps1 -SpecimenDir work/apk/<specimen>
```

The first research build deliberately makes only Android-shell changes:

```text
android:debuggable=true
android:usesCleartextTraffic=true
android:networkSecurityConfig=@xml/relive_network_security_config
trust system + user CA stores through Android Network Security Config
re-sign base + every selected split with one local research key
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

## Current boundary findings

Runtime experiments have already established two important environment facts:

1. Android hosts/network-security configuration is not sufficient by itself for
   the final Unity transport on the current rooted test device.
2. UnityTLS loads its default CA store from the Android Conscrypt APEX and a
   preservation CA not present in that store fails with verification mask
   `0x8` before `/load/title` reaches the local compatibility server.

The Frida scripts in this directory are evidence/diagnostic tools for those
findings. They are not the intended long-term endpoint/TLS implementation.

## Next patch stages

Changes should be added in this order and each stage should remain independently
reviewable:

1. move endpoint routing and additional CA trust into the thin Preservation
   boundary without disabling hostname or certificate validation;
2. route all native byte changes through the hash/expected-byte guarded patch
   manifest under `client/preservation/`;
3. use Research instrumentation to locate the first real resource/parser/runtime
   blocker after the environment boundary is working;
4. fix protocol/game-state failures in the compatibility server or resource
   layer, not by making the client parser more permissive;
5. keep any protocol-bypass experiment explicitly labeled and never use it as
   Original-client acceptance evidence.

In particular, do not make the research client automatically swallow missing
`/load/index` keys, force `result_code=1`, skip resource initialization, or
force `SceneManager` to Home as the normal development path. The purpose of the
Research build is to make failures observable, not to hide them.
