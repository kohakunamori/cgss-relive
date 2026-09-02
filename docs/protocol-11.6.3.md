# CGSS Android 11.6.3 control-plane transport

This document records the clean-room reconstruction of the final Android 11.6.3 client's request transport from its IL2CPP metadata and arm64 native code.

The goal is compatibility for preservation. No live account credentials or captured session values are recorded here.

## Provenance

Client specimen:

- app `11.6.3` / versionCode `438`
- Unity `2022.3.56f1`
- IL2CPP metadata v31
- arm64 `libil2cpp.so` SHA-256 `2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5`
- `global-metadata.dat` SHA-256 `2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586`

All native addresses below are relative virtual addresses for that exact arm64 `libil2cpp.so` and must not be assumed stable across another binary.

## IL2CPP token -> native mapping

Unity 2022 IL2CPP uses per-image `Il2CppCodeGenModule` method-pointer arrays. For metadata v31, a managed method's native pointer is selected by its metadata token RID:

```text
rid = method.token & 0x00ffffff
native = image.codeGenModule.methodPointers[rid - 1]
```

For this specimen the `Assembly-CSharp.dll` code-generation module was resolved from its relocated module-name pointer:

```text
Il2CppCodeGenModule RVA : 0x07e54bc0
methodPointerCount      : 146863
methodPointers RVA      : 0x08371ed0
```

Selected current-client mappings:

| Managed method | Token | arm64 RVA |
| --- | --- | --- |
| `Cute.NetworkTask.PrepareHeaders` | `0x060088b8` | `0x050c9f90` |
| `Cute.NetworkTask.PreparePostData` | `0x060088b9` | `0x050cae4c` |
| `Cute.NetworkTask.CreateBody` | `0x060088bd` | `0x050cb93c` |
| `Cute.NetworkTask.AddHeaderSessionId` | `0x060088c2` | `0x050ca1c8` |
| `Cute.NetworkTask.AddHeaderParam` | `0x060088c3` | `0x050ca264` |
| `Cute.NetworkTask.AddHeaderVersion` | `0x060088c5` | `0x050ca64c` |
| `Cute.CryptAES.EncryptRJ256` | `0x060087b9` | `0x050c1c9c` |
| `Cute.CryptAES.DecryptRJ256` | `0x060087ba` | `0x050c2438` |
| `Cute.Cryptographer.generateIvString` | `0x060087c1` | `0x050c359c` |
| `Cute.Cryptographer.generateKeyString` | `0x060087c2` | `0x050c2bac` |
| `Cute.Cryptographer.ComputeHash` | `0x060087c5` | `0x050c3824` |
| `Cute.Cryptographer.MakeMd5` | `0x060087c6` | `0x050c3990` |
| `Cute.Certification.VersionCheckTaskExec` | `0x06008763` | `0x050bde1c` |
| `Cute.VersionCheckTask.SetParameter` | `0x0600881d` | `0x050bf6b8` |
| `Cute.BootNetwork.SetupNetworkCertification` | `0x06008850` | `0x050c7208` |

## Inner request representation

`NetworkTask.CreateBody` confirms this sequence:

```text
params object
  -> LitJson.JsonMapper.ToJson
  -> MessagePack.MessagePackSerializer.FromJson
  -> Convert.ToBase64String
  -> CryptAES.EncryptRJ256
  -> UTF-8 bytes (HTTP body)
```

Conceptually:

```text
plain = Base64(MessagePack(params))
```

The same `plain` value is used while constructing `PARAM`.

## Body envelope

`CryptAES.EncryptRJ256` configures `RijndaelManaged` as a 256-bit key / 128-bit block cipher and uses the normal CBC/PKCS7-compatible path observed in the historical client family.

The current 11.6.3 native flow is:

```text
keyString = generateKeyString()        # 32 ASCII characters
key       = UTF8(keyString)            # 32 bytes -> AES-256
iv        = HexDecode(UDID.remove("-")) # 16 bytes
cipher    = AES-256-CBC-PKCS7(key, iv, UTF8(plain))
body      = Base64(cipher || key)
```

The dynamic key is deliberately appended to the encrypted envelope. Consequently a compatibility server can decode the control-plane body without a hidden shared body-encryption secret.

The repository implementation is `server/cgss_codec.py`.

### Current key-generation behavior

The original client generates a 32-character ASCII key by building random formatted material, converting it to ASCII bytes, Base64-encoding it and taking the first 32 characters. A compatibility server does not need to reproduce that PRNG byte-for-byte; any 32-byte ASCII AES key is interoperable because the key itself travels in the envelope.

## `PARAM`

`Cute.NetworkTask.AddHeaderParam` was traced through the final native binary.

Before hashing, it sets the inherited `PostParams.viewer_id` and `timezone` fields, serializes `Params` through the same JSON -> MessagePack -> Base64 path, obtains the task URL's `Uri.AbsolutePath`, then calls `Cute.Cryptographer.ComputeHash`.

`ComputeHash` is SHA-1 over UTF-8 input and emits lowercase two-digit hexadecimal bytes.

Current formula:

```text
PARAM = hex_lower(
    SHA1(
        UTF8(
            UDID
          + viewerId.ToString()
          + Uri(taskUrl).AbsolutePath
          + Base64(MessagePack(params))
        )
    )
)
```

For a local compatibility server this header can initially be observed rather than enforced. Once request fixtures are stable it can be validated by `server.cgss_codec.compute_param`.

## `viewer_id` request field

The final client still wraps the numeric viewer ID before MessagePack serialization.

`Cryptographer.generateIvString` performs 16 iterations of a client RNG producing values in the `1..8` range and concatenates their decimal representation, yielding a 16-character IV string.

Then:

```text
viewer_id_plain = viewerId.ToString()
ivString        = 16 generated ASCII digits
cipher_b64      = AES256Crypt.Encrypt(viewer_id_plain, ivString)
params.viewer_id = ivString + cipher_b64
```

`AES256Crypt.Encrypt` uses:

- a 32-byte UTF-8 client-static key;
- the UTF-8 bytes of the 16-character `ivString` as IV;
- Rijndael/AES with a 128-bit block, CBC mode and PKCS7-compatible padding;
- Base64 output.

The current static key was recovered locally from the client, but its plaintext is intentionally not committed. Its SHA-256 fingerprint is:

```text
a06aea3ce810a206870e69bfe3bc1d71fff29194e949292004e7c54267d757ad
```

A future local extractor can supply it to a research-only decoder if decoding `params.viewer_id` proves necessary. The first preservation server can treat this field as opaque.

## `SID`

`Cute.NetworkTask.AddHeaderSessionId` calls `Cute.Certification.get_SessionId`.

If the stored session value is empty, the client first constructs:

```text
sessionId = viewerId.ToString() + UDID
```

It then calls `Cute.Cryptographer.MakeMd5`, which computes:

```text
SID = hex_lower(MD5(UTF8(sessionId + clientStaticSalt)))
```

The current static salt was recovered locally from the final client but is not committed in plaintext. SHA-256 fingerprint:

```text
ca5cbd11dcbc57e958414c758c91a6c24f2dd5727201a67981443a85c195be6a
```

`server.cgss_codec.compute_sid` therefore accepts the salt as an injected local value rather than hardcoding it.

## Resource-version negotiation implication

The response model `Cute.Header` still contains:

```text
result_code
viewer_id
udid
sid
required_res_ver
download_list
download_url
servertime
```

The 11.6.3 binary contains resource revision literal `10133000`, whereas maintained final-resource tooling identifies `10133800`. The local `load/check` implementation therefore needs to model `required_res_ver` and direct 11.6.3 toward the frozen final resource revision rather than using the binary's default resource string as the archive ceiling.

## Remaining proof obligations before M3

- Trace `CryptAES.DecryptRJ256` and response parse call sites to confirm the response envelope is exactly symmetric with the request codec.
- Produce a sanitized current `load/check` fixture from a dedicated test installation.
- Confirm exact decoded `load/check` request/response schemas and result-code behavior.
- Confirm whether the compatibility server can safely ignore `PARAM`/`SID` validation or whether any client-side state transition depends on server reflection of those values.
- Freeze and verify resource revision `10133800`.
