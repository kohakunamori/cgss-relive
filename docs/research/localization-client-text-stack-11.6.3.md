# Final 11.6.3 localization text stack — static checkpoint

Date: 2026-09-04

Branch: `localization/zh-cn-complete`

Validated by GitHub Actions run `33859407066` at commit `2545b5bbd4fc92856030b3fd588c85917963ca26` against the exact frozen final Android specimen.

## Input identity

The workflow re-verifies all three frozen inputs before analysis:

```text
XAPK
609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d

arm64 libil2cpp.so
2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5

global-metadata.dat
2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

Il2CppDumper v6.7.46 successfully resolved metadata v31 and emitted its ephemeral `dump.cs`. The CI then extracted only localization-relevant type/method metadata, deleted the XAPK/APKs/IL2CPP/metadata/dump outputs, and uploaded the sanitized JSON report.

## Static result

The final client metadata contains the legacy Unity UI text stack:

```text
UnityEngine.UI.Text   present
UnityEngine.Font      present
```

The targeted TextMeshPro types were not present in the final metadata:

```text
TMPro.TMP_Text            absent
TMPro.TextMeshProUGUI     absent
TMPro.TextMeshPro         absent
TMPro.TMP_FontAsset       absent
TMPro.TMP_Settings        absent
```

This is strong static evidence that the first localization runtime should target `UnityEngine.UI.Text`, not implement a dual Legacy-Text/TMP hook layer up front. It is **not yet runtime proof** that every visible CGSS label flows through `Text.set_text`; the next rooted-device probe must establish actual setter hits and identify any custom rendering paths.

## Exact localization-relevant RVAs

`UnityEngine.UI.Text`:

```text
get_font       0x7dc0128
set_font       0x7dc0250
get_text       0x7dc0364
set_text       0x7dc036c
get_fontSize   0x7dc06e0
set_fontSize   0x7dc06fc
get_fontStyle  0x7dc08a0
set_fontStyle  0x7dc08bc
```

`UnityEngine.Font`:

```text
get_fontSize   0x7c46c84
```

The primary M1 dynamic anchor is therefore:

```text
UnityEngine.UI.Text.set_text @ libil2cpp.so + 0x7dc036c
```

Font replacement/fallback experiments can additionally observe:

```text
UnityEngine.UI.Text.set_font @ libil2cpp.so + 0x7dc0250
```

## M1 implications

The shortest path to a real "Hello Chinese" proof is now:

1. On the rooted final-client device, attach a read-only probe to `Text.set_text` and verify actual CGSS UI traffic.
2. Record representative Title/Home/system labels and identify whether any visible text bypasses this setter.
3. Verify IL2CPP `System.String` layout/readout and call frequency under the final arm64 build.
4. Inject one controlled replacement after runtime observation proves the call signature.
5. Inspect the active `UnityEngine.Font` objects and determine whether the shipped fonts contain the required Simplified-Chinese glyphs.
6. If not, establish a Chinese-capable Font load/assignment path through `Text.set_font` before bulk translation.
7. Move the proven hook into the production APK-loaded localization native runtime; Frida remains a discovery tool only and is not the final delivery mechanism.

`localization/runtime/probes/ui-text-frida.js` implements step 1 as a local-only dynamic probe anchored to this exact frozen specimen.

## Evidence boundary

Do not treat this static checkpoint as proof of visible Chinese rendering. M1 acceptance still requires a rebuilt/re-signed client that loads the production localization runtime and renders a controlled Chinese string without a PC-side transient injection.
