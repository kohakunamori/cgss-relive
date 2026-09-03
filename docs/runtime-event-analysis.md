# Sanitized runtime event analysis

The compatibility server can write a deliberately sanitized JSONL trace with
`--event-log`. `scripts/analyze-runtime-events.py` turns that trace into a small,
deterministic report for final 11.6.3 integration.

The analyzer accepts only the documented `server.safe_events` schema. Unknown
top-level fields or non-allow-listed headers are rejected, so raw request or
response captures are not silently copied into reports.

## Evidence language

Final static analysis proves that result code 214 persists `required_res_ver` but
does **not** automatically resend `/load/check` inside the same network coroutine.
The analyzer therefore never labels a later `RES-VER=10133800` request as a
"retry". It records observations only:

```text
server_returned_214
observed_later_control_request_after_214
observed_later_10133800_load_check_after_214
server_returned_direct_success_with_required_res_ver
observed_followup_request_after_direct_success
server_returned_success_for_10133800
observed_followup_request_after_10133800_success
```

A later request may be caused by a higher-level resource/boot state machine. The
JSON report schema is now version `2` to make the terminology change explicit.

## First original-client run

The preferred `/load/index` profile is the corrected starter-visible candidate:

```powershell
python -m server.http_server `
  --host 127.0.0.1 `
  --port 8443 `
  --cert .\work\tls\server.chain.pem `
  --key .\work\tls\server.key.pem `
  --experimental-starter-load-index `
  --viewer-id 1 `
  --producer-name "Relive Producer" `
  --event-log .\work\runtime-starter.jsonl `
  --api-map .\work\final_map.json
```

Analyze it:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl `
  -o .\work\runtime-starter-report.json
```

The report records, without request/response values:

- whether `/load/check`, `/load/title`, and `/load/index` were observed;
- whether the server returned 214;
- whether **any later control request** was observed after that 214;
- whether a later `/load/check` arrived with `RES-VER=10133800`;
- whether the explicit old-version direct-success diagnostic was used and
  followed by another client request;
- whether a final-version `/load/check` got server success and whether another
  request followed it;
- the first server-side failure;
- the first event after the final `/load/index` event;
- final-map `api_candidates` when a logged 404 already has a known endpoint
  identity.

A response event proves what the server returned. Client acceptance requires a
later observable client action. No server event alone proves or disproves TLS;
use ADB logcat and the routing checks in `rooted-device-integration.md` for
failures before HTTP.

## Phase semantics

`phase` now follows only the statically supported hard bootstrap mainline:

```text
no_http_request
http_reached
load_check_reached
resource_version_214_responded
old_resource_direct_success_responded
final_version_load_check_observed
final_version_load_check_responded
load_index_reached
post_load_index_observed
```

Not every run visits every phase. In particular `/load/title` no longer advances
`phase`: final static analysis places TitleTask on a separate user-driven Title
branch, not as a proven link between `/load/check` and `/load/index`.

## Native-vs-direct-success differential

The server supports two controlled `/load/check` policies:

### Native 214 path

Default behavior for incoming `RES-VER=10133000`:

```text
214 + required_res_ver=10133800
```

Run and preserve the JSONL as `runtime-native.jsonl`.

### Direct-success diagnostic

Add:

```text
--accept-old-resource-version
```

The server returns success while still supplying `required_res_ver=10133800`.
Run it from an equivalent clean test state and preserve the JSONL as
`runtime-direct.jsonl`.

Compare:

```powershell
python .\scripts\analyze-runtime-events.py `
  native=.\work\runtime-native.jsonl `
  direct=.\work\runtime-direct.jsonl `
  -o .\work\runtime-resource-policy-diff.json
```

If direct success reaches `/load/index` but native 214 does not, the next target
is the higher-level resource/update state machine rather than `/load/index`
schema. If both reach `/load/index`, focus on the profile/Home transition.

The control-server JSONL does not see resource-host HTTP requests because they
are served by `server.resource_server`. Correlate timestamps with resource-server
logs when the storages host is redirected.

## Starter/empty/strict profile differential

Only if the starter-visible profile fails around `/load/index`, repeat the same
clean state with empty-Home and strict-minimal profiles:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl `
  empty=.\work\runtime-empty.jsonl `
  strict=.\work\runtime-strict.jsonl `
  -o .\work\runtime-profile-differential.json
```

`comparison.common_prefix_events` counts identical sanitized event signatures.
`comparison.divergence_event_index` and `comparison.states` show the first
differing route/status/error/resource-version/result-code state.

This is a triage aid only. Do not add a `/load/index` field unless final 11.6.3
static or runtime evidence justifies it.

## Sharing boundary

Preferred shareable artifacts are the sanitized JSONL trace and analyzer JSON
report. Keep raw ADB logcat/packet/body captures local until identifiers,
sessions, and account data have been removed. Never commit UDID, SID, USER-ID,
PARAM, decoded viewer-id values, or decoded request/response values.
