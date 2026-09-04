# Localization runtime

This tree is for the client-side localization runtime and its discovery probes.

## Current state

Static final-client analysis has established a legacy `UnityEngine.UI.Text` path and no targeted TextMeshPro types in the frozen 11.6.3 IL2CPP metadata. See [`docs/research/localization-client-text-stack-11.6.3.md`](../../docs/research/localization-client-text-stack-11.6.3.md).

The first dynamic probe is:

```text
probes/ui-text-frida.js
```

It attaches read-only to the exact frozen arm64 method:

```text
UnityEngine.UI.Text.set_text
libil2cpp.so + 0x7dc036c
```

Typical local research invocation with a rooted/debuggable setup and Frida available:

```bash
frida -U -f jp.co.bandainamcoent.BNEI0242 \
  -l localization/runtime/probes/ui-text-frida.js
```

The probe deduplicates observed strings and emits `cgss-ui-text` messages. Captured game text is local research material and must not be committed as a bulk dump.

## Production rule

Frida is only a discovery/validation tool. M1 is not accepted until a rebuilt/re-signed 11.6.3 install set loads the production localization runtime itself and renders controlled Chinese text without PC-side transient injection.
