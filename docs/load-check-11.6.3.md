# CGSS Android 11.6.3 `/load/check` reconstruction

This note records the point at which the final Android 11.6.3 cold-start
transport is sufficiently reconstructed to implement the first clean-room
bootstrap response.  Findings below are based on the supplied 11.6.3 IL2CPP v31
specimen and its arm64 `libil2cpp.so`; older community clients were used only as
cross-checks after the current native control flow had been identified.

## Final-client native targets

For the exact arm64 binary with SHA-256
`2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5`:

| Managed method | arm64 RVA |
| --- | ---: |
| `Cute.NetworkTask.SetResponseData` | `0x050cae58` |
| `Cute.NetworkTask.CheckResult` | `0x050cae60` |
| `Cute.NetworkTask.Parse` | `0x050c437c` |
| `Cute.VersionCheckTask.Parse` | `0x050c5400` |
| `Cute.CryptAES.decrypt` | `0x050c2434` |
| `Cute.CryptAES.DecryptRJ256` | `0x050c2438` |
| `Cute.Cryptographer.encode` | `0x050c0294` |
| `Cute.Cryptographer.decode` | `0x050c3688` |
| `Cute.Certification.VersionCheckTaskExec` | `0x050bde1c` |
| `<VersionCheckTaskExec>d__43.MoveNext` | `0x050bf3c8` |

## Response wire path: proven inverse of the request

The current HTTP completion callback performs the following sequence before it
calls `NetworkTask.SetResponseData`:

```text
HTTP response ASCII body
  -> Cute.CryptAES.decrypt
  -> outer Base64 decode
  -> split final 32 bytes as dynamic AES key
  -> AES-256-CBC decrypt (IV = hex-decoded UDID without dashes)
  -> inner Base64 text
  -> Convert.FromBase64String
  -> MessagePack.MessagePackSerializer.ToJson
  -> LitJson parse
  -> NetworkTask.SetResponseData(JsonData)
  -> CheckResult / Parse
```

`DecryptRJ256` independently confirms the envelope details.  It takes the final
32 decoded bytes as the 256-bit key, uses the remaining bytes as ciphertext,
reconstructs the 16-byte IV from the current certification UDID, and follows the
same 128-bit-block CBC/PKCS7-compatible path as request encryption.

Therefore the existing `server.cgss_codec.encode_body` routine is valid for
server responses as well as synthetic requests.

## Request header UDID can be recovered by the server

The final client still runs the UDID through `Cute.Cryptographer.encode` before
putting it into the request header.  The current `Cryptographer.decode` native
routine at `0x050c3688` proves the reversible layout:

```text
encoded = hex4(plaintext string length)
        + repeated 4-character noise groups
        + random suffix

plaintext character i = chr(encoded_payload[2 + 4*i] - 10)
```

The decoder stops after the length declared by the four hexadecimal prefix
characters, so the random suffix has no semantic value.

`server/header_codec.py` implements the clean-room inverse.  Consequently the
bootstrap server does not need a separately configured raw UDID: it can recover
it from the request header and immediately use it as the body AES IV.

## Current result-code constants

IL2CPP field default values on `Cute.NetworkTask` decode to:

| Meaning | Current 11.6.3 value |
| --- | ---: |
| success | `1` |
| session error | `201` |
| application-version error | `204` |
| resource-version error | `214` |

The resource-version value is therefore current-client evidence, not merely a
legacy downloader convention.

## `data_headers` behavior

`NetworkTask.Parse` unconditionally returns:

```text
(int)ResponseData["data_headers"]["result_code"]
```

So the absolute minimum structurally valid response contains a top-level
`data_headers` map with integer `result_code`.

Common response processing additionally establishes these rules:

- `data_headers.sid` is optional; when present it is copied into
  `Cute.Certification.SessionId` before later result processing.
- `data_headers.app_ver` is optional and participates in local app-version
  persistence.
- `data_headers.required_res_ver` is optional; when present it is persisted to
  local `RES_VER` and can cause the current bootstrap/tutorial state machine to
  continue, reload, or reset as appropriate.
- `VersionCheckTask.Parse` only enters its extra `data` parsing on success and
  treats its live-suspension/popup fields as optional.  A large `data` object is
  therefore not required for the first preservation response.

## Preservation resource negotiation

The final 11.6.3 application binary contains default resource revision
`10133000`; maintained final-resource tooling identifies later resource revision
`10133800`.

The first compatibility implementation models the transition as:

```text
client: POST /load/check, RES-VER: 10133000
server: result_code = 214
        required_res_ver = "10133800"

client persists/reloads its RES_VER state according to final-client common
result handling

client: POST /load/check, RES-VER: 10133800
server: result_code = 1
```

The server must tolerate a process/title restart between these two requests; it
must not depend on an in-memory retry sequence.

## Implemented clean-room bootstrap core

The repository now contains:

- `server/cgss_codec.py` — MessagePack/AES request+response envelope;
- `server/header_codec.py` — final-client `Cryptographer.decode` for UDID header;
- `server/load_check.py` — result-code/resource negotiation response builder;
- `server/bootstrap_core.py` — complete transport-independent exchange:
  request headers/body -> raw UDID -> decoded MessagePack params -> version
  negotiation -> encrypted final-client response.

`bootstrap_core.process_load_check_request` intentionally does not validate
production authentication/integrity values (`PARAM`, account credentials or
SID salt).  That is sufficient for a preservation server under our control and
keeps production-static secrets out of the repository.

## Synthetic end-to-end proof

Regression tests construct a final-format request with:

1. an obfuscated `UDID` header;
2. a current-format encrypted MessagePack body;
3. `RES-VER=10133000`;

then feed only HTTP-like headers + body into the bootstrap core.  The test proves
that the server:

1. recovers the raw UDID;
2. decrypts and deserializes the request;
3. returns `214 + required_res_ver=10133800`;
4. encrypts that response with the final-client envelope;
5. can decode its emitted response back to the exact expected object.

A second exchange with `RES-VER=10133800` proves the success (`1`) path.

## What remains dynamic rather than cryptographic

The control-plane codec and minimum `/load/check` response contract are now
statically reconstructed.  The remaining proof is runtime integration:

- run the actual 11.6.3 client against the compatibility endpoint;
- confirm its TLS/certificate behavior and choose the least invasive redirect;
- capture one sanitized real `/load/check` fixture to freeze as a golden test;
- observe whether the 214 response causes immediate retry, title reset, or
  process restart for the chosen clean test-state;
- continue the same method for `/load/index` and `/load/title`.

The current analysis environment has no Android emulator/ADB target, so those
items cannot be honestly claimed as executed here.  They are no longer blockers
to understanding the response cryptography or the minimum `load/check` schema.
