# Historical control/API protocol — verification targets

> **Status: historical reference only.**
>
> This document summarizes older public CGSS API clients so we can search the final APK efficiently. Nothing here should be treated as current until verified against the archived client specimen.

## Historical API host

Older clients used:

```text
https://apis.game.starlight-stage.jp/
```

The private-server implementation should not assume this hostname is still the only control-plane host. The final APK/string inventory and cold-launch connection trace are authoritative.

## Historical payload envelope

A public 2021 implementation describes this request pipeline:

```text
request parameters
      |
      v
MessagePack
      |
      +----> Base64 form used in PARAM hash input
      |
      v
Base64(MessagePack bytes)
      |
      v
AES-CBC + PKCS#7
  - random per-request 32-byte ASCII key
  - IV derived from UDID bytes
      |
      v
ciphertext || request_key
      |
      v
Base64 HTTP body
```

The corresponding response path recovered the key from the body tail, AES-CBC-decrypted the payload, Base64-decoded it, then MessagePack-decoded the response object.

For relive, the important question is not whether we can reproduce this old implementation. The important question is whether the **final client still contains this envelope and field contract**.

## Historical request fields / headers

High-value symbols to search in the final managed/IL2CPP metadata:

```text
APP-VER
CARRIER
DEVICE-ID
DEVICE-NAME
DEVICE
GRAPHICS-DEVICE-NAME
IDFA
IP-ADDRESS
KEYCHAIN
PARAM
PLATFORM-OS-VERSION
PROCESSOR-TYPE
RES-VER
SID
UDID
USER-ID
UV
X-Unity-Version
viewer_id
timezone
data_headers
sid
```

## Historical integrity/session behavior

Older public code indicates:

- `viewer_id` was separately encrypted/obfuscated before MessagePack serialization;
- `PARAM` was derived from request-specific data including device/user context, path and Base64-encoded packed parameters;
- `UDID` and `USER-ID` headers were obfuscated rather than sent directly;
- `SID` was transformed before being sent as a header;
- a response `data_headers.sid` value advanced client session state.

Exact salts, embedded keys and transformation constants should be recovered only if the final client actually uses this protocol. Do not carry old constants into the new server by assumption.

## Static verification strategy

### Managed/Mono build

Search `Assembly-CSharp.dll` and relevant supporting assemblies first for the header literals above. Map xrefs to:

1. request builder;
2. serialization function;
3. encryption/wrapping function;
4. HTTP send function;
5. response unwrap/deserialize function;
6. session update function.

### IL2CPP build

Recover metadata/symbol mappings first, then search reconstructed strings/xrefs. Avoid beginning with blind native disassembly of `libil2cpp.so`.

### DEX/Android wrapper

Search DEX separately for Android-side device identifiers, certificate/network configuration, Play services and WebView/deep-link glue. Unity networking may be native even if Java code contains no API URLs.

## Dynamic verification strategy

For a dedicated archival test installation, record a cold launch and answer these questions in order:

1. Which host resolves first?
2. Which TLS SNI/hostname is used for control API versus asset CDN?
3. Which request occurs before an account/session exists?
4. Does the client still send the historical header names?
5. Is the body high-entropy/Base64-like, binary MessagePack, JSON, protobuf, or another format?
6. Does one session value change after every successful response?
7. Which fields are deterministic versus per-request random?

Raw captures remain local under `captures/raw/`. Only redacted/minimal fixtures belong in Git.

## Compatibility-server design consequence

Do **not** model the relive server around a real production account. The server should terminate the final client's protocol envelope and expose an internal clean model such as:

```text
transport/envelope
    -> decoded request DTO
    -> compatibility service
    -> synthetic archival profile/database
    -> response DTO
    -> transport/envelope
```

This separation lets us replace transport details if the final client differs from the historical implementation and keeps game-state emulation testable without encryption/session machinery.

## Historical source

Primary historical reference used for this checklist:

- KisaragiSan, `cgssapi.py` (2021), a public Python module for the CGSS API.

Older projects such as `deresuteme` and `StarlightStageSpoofer` are useful corroborating references, but all old findings remain hypotheses until the final client specimen confirms them.
