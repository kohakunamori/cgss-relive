# Sanitized runtime event analysis

Both compatibility servers can emit deliberately sanitized JSONL traces.
`scripts/analyze-runtime-events.py` validates those traces, merges independent
control/resource streams when requested, and produces a deterministic report for
final 11.6.3 integration.

Unknown fields, non-allow-listed headers and unknown synthetic resource routes
are rejected rather than copied into reports.

## Evidence language

Final static analysis proves:

- result code 214 persists `required_res_ver`;
- 214 does **not** automatically resend `/load/check` in the same network
  coroutine;
- the parent `GameInitialize` coroutine subsequently resumes into
  `AssetManager.InitializeManifest -> DownloadOrLoadForInitialize`;
- after successful `/load/index`, the static tail maps to `Home=6` or
  `Login_Bonus=7`.

The analyzer therefore records observations rather than inventing a retry:

```text
server_returned_214
observed_later_control_request_after_214
observed_resource_request_after_214
observed_successful_resource_response_after_214
observed_later_10133800_load_check_after_214
server_returned_direct_success_with_required_res_ver
observed_followup_request_after_direct_success
server_returned_success_for_10133800
observed_followup_request_after_10133800_success
```

Report schema is `3`.

## Control-server log

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter-control.jsonl `
  --api-map .\work\final_map.json
```

## Resource-server log

For the native 214 path, run the resource server before launching the client:

```powershell
python -m server.resource_server `
  --host 127.0.0.1 `
  --port 8444 `
  --version 10133800 `
  --root .\resource-cache\10133800 `
  --manifest-db .\work\resources\manifest_10133800.db `
  --cert .\work\tls\resource.chain.pem `
  --key .\work\tls\resource.key.pem `
  --event-log .\work\runtime-starter-resource.jsonl
```

Resource paths are reduced before logging to exactly these categories:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

Filename, object hash and query string never enter the sanitized event. `/healthz`
is deliberately excluded so monitoring cannot fake resource progress.

## Merge independent logs into one run

This is preferred over having two processes append to one JSONL file:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run starter=.\work\runtime-starter-control.jsonl `
  --merge-run starter=.\work\runtime-starter-resource.jsonl `
  -o .\work\runtime-starter-report.json
```

Repeated `--merge-run` entries with the same label are loaded independently and
sorted by numeric event `time`. Every event in a merged run must have a timestamp;
otherwise the analyzer rejects the merge instead of guessing chronology.

A valid native timeline can therefore look like:

```text
/load/check              result_code=214
@resource/manifest       200
@resource/AssetBundles   206
/load/index              200
```

This is stronger evidence than waiting for a second `/load/check`, which is not a
required static link.

## Phase semantics

The hard-mainline phases are:

```text
no_http_request
http_reached
load_check_reached
resource_version_214_responded
old_resource_direct_success_responded
final_version_load_check_observed
final_version_load_check_responded
resource_plane_observed
resource_plane_served
load_index_reached
post_load_index_observed
```

Not every run visits every phase. `/load/title` is reported in `reached` but does
not advance the hard phase because TitleTask is a separate user-driven branch.

`resource_plane_observed` means a sanitized `@resource/*` request was seen.
`resource_plane_served` requires at least one non-`unresolved` resource event with
HTTP status below 400.

## What the report proves

A 214 event proves only what the server returned. A later resource event proves
the client advanced into the statically expected resource stage. `/load/index`
proves it advanced beyond that stage. A later event after `/load/index` is further
acceptance evidence, but visible Home must still be observed on the original
client/runtime.

No HTTP event alone proves or disproves a TLS failure before the server. Use ADB
logcat and the routing checks in `rooted-device-integration.md` for pre-HTTP
failures.

## Native-vs-direct-success differential

Default native mode for old 10133000 returns:

```text
214 + required_res_ver=10133800
```

The diagnostic server flag:

```text
--accept-old-resource-version
```

returns success while still supplying the required final version. Run equivalent
clean states and compare them only when native mode fails to produce useful
resource evidence.

Example comparison using merged native logs plus a direct control log:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run native=.\work\runtime-native-control.jsonl `
  --merge-run native=.\work\runtime-native-resource.jsonl `
  direct=.\work\runtime-direct-control.jsonl `
  -o .\work\runtime-resource-policy-diff.json
```

If native reaches `resource_plane_served` but not `/load/index`, focus on resource
completion. If direct reaches `/load/index` while native never reaches the
resource plane, focus on the native version/resource continuation or routing.

## Starter/empty/strict differential

Only if the starter-visible profile reaches `/load/index` but fails around Home,
repeat equivalent clean states with empty/strict profiles:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl `
  empty=.\work\runtime-empty.jsonl `
  strict=.\work\runtime-strict.jsonl `
  -o .\work\runtime-profile-differential.json
```

`comparison.common_prefix_events` and `comparison.divergence_event_index` identify
the first differing sanitized signature. This is triage evidence, not permission
to add arbitrary `/load/index` fields.

## Sharing boundary

Shareable traces must remain in the strict sanitized schema. Never commit or
share UDID, SID, USER-ID, PARAM, decoded viewer/account values, decoded bodies,
resource filenames/hashes, production credentials, or raw sensitive packet
captures.
