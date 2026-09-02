# AGENT HANDOFF — cgss-relive

This file is the authoritative continuation entry point for the current
`kohakunamori/cgss-relive` work. **Do not restart the research from scratch.**
Fetch `main`, read this file and the linked evidence documents, verify CI, and
continue directly from the pending runtime-integration milestone.

The repository may have advanced after this document was written. Always fetch
the actual current HEAD first. The work immediately preceding this handoff fixed
the final `/load/index` unit contract and reconciled
`docs/load-index-11.6.3.md`.

## Mission

Preserve and locally reimplement the final Android version of THE IDOLM@STER
CINDERELLA GIRLS STARLIGHT STAGE (CGSS / デレステ) so that an original final
11.6.3 client can eventually boot, enter Home and use preserved resources against
a local compatibility server.

This is a clean-room preservation project. Do not commit proprietary APK/XAPK
payloads, game assets, master/resource databases, raw captures containing secrets,
production account credentials, plaintext client-static keys/salts, or bulk
decompiler output.

## Final specimen

Android package:

```text
jp.co.bandainamcoent.BNEI0242
```

Final client specimen:

```text
app version:       11.6.3
versionCode:       438
Unity:             2022.3.56f1
runtime:           IL2CPP
metadata version:  31
```

High-value fingerprints:

```text
XAPK SHA-256:
609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d

arm64 libil2cpp.so SHA-256:
2d950f3bab72c73adef62a3e312c64e4e42ae0287cb2454cdec008eb9ed699c5

global-metadata.dat SHA-256:
2d31901dd94b4b774c1fda7c3a5f409dc8a1cae16078314bd42f832b33c69586
```

APK v2 signer fingerprint recorded during specimen work:

```text
SHA-256: 336ca2245718a9ca1672bf0bf2d324b29a836d899848ac0e8c08ba79097c03b3
```

## Resource version distinction — do not regress this

The final 11.6.3 executable embeds the older literal:

```text
10133000
```

The independently reproduced final **server-side resource revision** is:

```text
10133800
```

Do not collapse these into one number. `/load/check` correctly negotiates the
client from an old incoming resource version to `required_res_ver=10133800`.

## M1 final resource freeze — COMPLETE

Issue #2 is closed/completed.

The repository's GitHub-hosted workflow independently reproduces:

```text
asset-starlight-stage.akamaized.net
  -> /dl/10133800/manifests/all_dbmanifest
  -> Android_AHigh_SHigh
  -> compressed MD5 validation
  -> CGSS 16-byte wrapper + raw LZ4
  -> manifest SQLite quick_check
  -> resolve master.mdb hash
  -> download master.mdb
  -> compressed MD5 validation
  -> decode
  -> master SQLite quick_check
```

Frozen facts:

```text
Android_AHigh_SHigh compressed MD5:
1c2969956e46cf781a374245fee0d38b

all_dbmanifest SHA-256:
520962136303805b0e9f0bdf5e3d471c50a00e76e7193ee59e04b65271fe731c

decoded manifest SHA-256:
8dff2f938c0221aaccabb8278acd31161eec1c9d3553a1c1231585f693f923e9

manifest rows:          220837
unique resource hashes: 220803

master.mdb compressed MD5:
b562431407563ac40435e447d630c8a4

decoded master.mdb SHA-256:
cccb7e91f65e8a726312c1a1545c5dc0303288ab1085e8f8d123976457ab0465

master tables:   909
card_data rows: 4314
```

Final manifest suffix inventory:

```text
.unity3d  207694 -> AssetBundles
.acb       10434 -> Sound
.awb         578 -> Sound
.bdb         825 -> Generic
.bytes       820 -> Sound
.mdb           1 -> Generic
.usm         485 -> Movie
----------------
total      220837
```

`.unity3d/.acb/.awb/.bytes/.usm/.mdb` have direct final-CDN probe evidence.
`.bdb -> Generic` remains supported by maintained resource-tool evidence; the
selected final `.bdb` object currently returns 403 in all tiny-probe modes, so do
not falsely call that one direct CDN proof.

`scripts/archive-resources.py` now produces a complete content-addressed archive
plan. CI asserts:

```text
planned unique objects == 220803
skipped objects == 0
```

The bulk archive itself must stay outside Git.

Primary resource document:

```text
docs/resource-bootstrap.md
```

## Final endpoint map

A user-supplied final 11.6.3 protocol map was validated and used as a truth table
for relative API paths.

Validated groups:

```text
A: 516 records, keys 0..515 continuously covered
B: 22 VR/login-related records
```

The six final `load/*` routes are:

```text
0   VersionCheck              load/check
1   SetCacheClearFlg          load/set_cache_clear_flg
10  Title                     load/title
11  Load                      load/index
12  LoadGetExternalSiteUrl    load/get_external_site_url
13  LoadUpdateAgreementStatus load/update_agreement_status
```

Important route conclusion: the complete final A group contains **no**
`home/index` or `home/load`. The only `home/*` route is `home/update`, which is a
later customization write route. Therefore the current bootstrap target is:

```text
/load/check
  -> /load/title and/or state-dependent bootstrap work
  -> /load/index
  -> Stage.LoadTask.Parse
  -> local Home transition
```

Do not waste time searching for a nonexistent Home initialization endpoint.

`server/api_registry.py` and map-validation tooling can annotate a runtime 404
with the final group/key/name when the path is known.

Caveat: the map proves relative paths much more strongly than per-endpoint host
assignment. Do not blindly assign every one of the 538 entries to the main API
host; `ext-api`, `storages`, `stream-api` etc. remain separate host families.

## Final request transport — reconstructed

Important headers include:

```text
APP-VER
RES-VER
PARAM
SID
UDID
USER-ID
```

Request parameter pipeline:

```text
params object
 -> LitJson.JsonMapper.ToJson
 -> MessagePack.MessagePackSerializer.FromJson
 -> Base64(MessagePack bytes)
 -> CryptAES.EncryptRJ256
 -> UTF-8 HTTP body
```

Body envelope:

```text
keyString = generated 32 ASCII chars
key       = UTF8(keyString)
iv        = HexDecode(UDID with '-' removed)
cipher    = AES-256-CBC-PKCS7(key, iv, UTF8(innerBase64))
body      = Base64(cipher || key)
```

`PARAM`:

```text
hex_lower(SHA1(UTF8(
  UDID + viewerId + Uri(taskUrl).AbsolutePath + Base64(MessagePack(params))
)))
```

`viewer_id` request field has a separate AES wrapper using a recovered
client-static key. The plaintext key is intentionally not committed.

`SID` is an MD5 of the session string plus a recovered client-static salt. The
plaintext salt is intentionally not committed.

The server bootstrap path does not require production credential validation.

Core implementation:

```text
server/cgss_codec.py
server/header_codec.py
server/bootstrap_core.py
```

## Final response transport — reconstructed and tested

Final HTTP response path:

```text
ASCII response body
 -> CryptAES.decrypt
 -> outer Base64 decode
 -> split final 32 bytes as dynamic AES key
 -> AES-256-CBC using UDID-derived IV
 -> inner Base64 text
 -> Base64 decode
 -> MessagePack -> JSON
 -> LitJson JsonData
 -> NetworkTask.SetResponseData
 -> CheckResult / endpoint Parse
```

The same CGSS codec therefore encodes server responses.

Current known final result codes:

```text
success             1
session error       201
app-version error   204
resource-version    214
```

`data_headers.result_code` is the structural minimum for common parsing.

## Implemented bootstrap endpoints

Current server coverage includes:

```text
/load/check                    implemented
/load/title                    implemented
/load/index                    implemented transport + profile-backed response
/load/set_cache_clear_flg      implemented common-success response
/load/update_agreement_status  implemented common-success response
```

`/load/get_external_site_url` final parser treats `data.url` as optional, but the
route has not been filled with a fake URL because callers may actually need the
business value. Keep that conservative behavior unless runtime proves a safe
minimal response.

`server/http_server.py` uses `ThreadingHTTPServer`, supports TLS, exposes `/healthz`,
and has real socket tests.

## `/load/index` — current main blocker

Primary evidence document:

```text
docs/load-index-11.6.3.md
```

Important final parser facts:

`Stage.LoadTask.Parse`:

```text
RVA 0x04850a94
```

The full parser references hundreds of strings, but many fields are optional or
state-dependent. Do not assume all fields are required.

Direct required `common_define` prefix on the reduced path:

```text
expanding_count
expanding_jewel
expanding_max
stamina_recovery_jewel
stamina_recovery_time
room_lvup_shortening_time
room_lvup_jewel
```

Reduced direct `user_info` reads:

```text
tutorial_flag
viewer_id
name
comment
max_card_num
max_room_storage_num
friend_pt
jewel
free_jewel
gold
stamina
level
exp
fan
producer_rank
birth
sum_of_money
last_payment_date
stamina_heal_time
```

Completed tutorial candidate:

```text
tutorial_flag = 100
```

The final client normalizes this to the local completed tutorial step 1000 on the
observed bootstrap path.

### Profile layers

`server/minimal_profile.py` exposes three layers:

1. strict minimal;
2. empty Home candidate;
3. starter-visible candidate.

The starter-visible candidate is the preferred first runtime test.

Final-master starter identity is independently verified:

```text
card_id 100001 -> 島村卯月
chara_id 101
```

Synthetic local ownership state currently uses:

```text
serial_id = 1
unit_id   = 1
unit_slot = 1
leader_serial_id = 1
```

Final non-empty card core fields:

```text
serial_id
card_id
exp
step
love
skill_level
protect
```

Final unit contract:

```text
unit_id
name
serial_id_0
serial_id_1
serial_id_2
serial_id_3
serial_id_4
```

Exactly five serial slots are statically proven (`cmp w20,#5`). A later
independent final parser pass makes `unit_id` mandatory for a non-empty unit.
This point was corrected immediately before this handoff; do not regress to the
older claim that list position alone supplies the unit number.

Final `user_chara_list` item core:

```text
chara_id
fan
```

The starter-visible profile has unit tests, validators and a real HTTP -> encrypted
CGSS response -> decode round-trip. This proves serialization/encryption and
server shape, **not original-client acceptance**.

## TLS / rooted-device integration

Static inspection has not found a game-specific override of Unity
`CertificateHandler.ValidateCertificate`; manifest also does not opt into a
custom network security config/cleartext policy.

Preferred first integration strategy is therefore:

```text
original HTTPS hostname
 -> rooted test device hosts/DNS redirect
 -> test CA trusted as system CA
 -> adb reverse / local port bridge
 -> cgss-relive TLS server
```

Do not downgrade the app to HTTP as the default experiment.

Read:

```text
docs/rooted-device-integration.md
```

The repo contains certificate generation and ADB tunnel helpers. Server event
logging is deliberately sanitized and does not record UDID, SID, USER-ID, PARAM,
viewer-id payloads, or decoded request/response values.

## What has NOT been proven yet

Do not claim any of these as complete:

- original 11.6.3 runtime acceptance of our `/load/check` response;
- original 11.6.3 runtime acceptance of `/load/title`;
- original 11.6.3 runtime acceptance of any synthetic `/load/index` profile;
- successful Home entry;
- exact first API endpoint after successful `/load/index`;
- full offline gameplay/LIVE/MV support.

The current environment used by the previous agent did not have a live Android
ADB target attached, so these cannot honestly be marked done from static tests.

## Immediate next action — do this, do not restart analysis

1. Fetch current `main`; read this file, `docs/load-index-11.6.3.md`,
   `docs/rooted-device-integration.md`, `docs/resource-bootstrap.md`, and the final
   transport docs.
2. Run/verify current CI before changing protocol code.
3. If a rooted Android/ADB target is available, execute the first real 11.6.3
   integration run using the **starter-visible** profile and sanitized server
   event log.
4. Capture ADB logcat from process start through failure/Home. Keep raw logs local;
   commit only sanitized derived findings.
5. Classify the first failure precisely:
   - TLS/certificate/hostname routing;
   - `/load/check` response acceptance/resource-version retry behavior;
   - `/load/title`;
   - `/load/index` parser/schema;
   - local Home-state/content requirement;
   - next final-map endpoint.
6. If `/load/index` fails, use the final `Stage.LoadTask.Parse` native control flow
   to add **only the field proven necessary by the observed failure**. Do not dump
   an entire historical account response into the server.
7. If Home succeeds, record the next actual endpoint and implement only the next
   blocker with final-client evidence.
8. Keep Issue #3 updated and keep CI green after every protocol/profile change.

## If no device is available

Continue only high-value static work:

- inspect remaining `LoadTask.Parse` branches specifically reachable by the
  starter-visible state;
- improve deterministic validators and differential profile tests;
- inspect TLS/host code only where it changes the integration strategy;
- prepare local asset-server backing over the frozen content-addressed archive.

Do **not** spend time rediscovering request crypto, the final endpoint map, or the
10133800 bootstrap; those are already solved sufficiently for the current goal.

## Repository evidence/docs worth reading

```text
AGENT_HANDOFF.md                    # this file, continuation authority
docs/load-index-11.6.3.md           # current final parser reduction
docs/load-check-11.6.3.md           # load/check contract
docs/protocol-11.6.3.md             # final transport findings
docs/rooted-device-integration.md   # first real-client test procedure
docs/resource-bootstrap.md          # independently frozen 10133800 resources
server/minimal_profile.py            # current three load/index profile layers
server/http_server.py                # HTTP/TLS endpoint adapter
server/bootstrap_core.py             # transport-independent bootstrap processing
server/api_registry.py               # final endpoint map registry/annotation
scripts/archive-resources.py         # complete content-addressed archive planner/downloader
```

Issue status:

```text
#1 M0 final client specimen: closed
#2 M1 final 10133800 resource freeze: closed
#3 M2 final-client transport/startup sequence: open; runtime acceptance remains
```

## Working style for the next agent

The user wants continuous implementation, not another research proposal. Make
reasonable decisions without repeatedly asking for confirmation. Only ask the
user when a device, runtime observation, permission, credential-free local setup,
or other genuinely unavailable external input is required. Prefer concrete code,
tests, docs and commits over speculative prose.
