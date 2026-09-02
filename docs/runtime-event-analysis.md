# Sanitized runtime event analysis

The compatibility server can write a deliberately sanitized JSONL trace with
`--event-log`. `scripts/analyze-runtime-events.py` turns that trace into a small,
deterministic report for the current original-client integration milestone.

The analyzer accepts only the documented `server.safe_events` schema. Unknown
top-level fields or non-allow-listed headers are rejected, so a raw request or
response capture is not silently copied into an analysis report.

## First original-client run

The preferred first `/load/index` profile remains the starter-visible candidate:

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

Analyze that run:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl `
  -o .\work\runtime-starter-report.json
```

The report records, without request/response values:

- whether `/load/check`, `/load/title`, and `/load/index` were reached;
- whether the server returned a `214` resource-version result;
- whether the client subsequently sent a `/load/check` with `RES-VER=10133800`;
- whether the server returned success for that final-resource request;
- whether any later client HTTP request was observed after that success response;
- the first recorded server-side failure;
- the first event after the final `/load/index` event;
- final-map `api_candidates` when a logged 404 already has a known endpoint identity.

A server event proves that HTTP reached the compatibility server. A success event
for `RES-VER=10133800` proves only what the server returned; it is not labeled as
client acceptance unless a later request is actually observed. Likewise, no event
does **not** prove or disprove TLS by itself; use ADB logcat and the routing checks
in `rooted-device-integration.md` for failures before HTTP.

## Three-profile differential

Only if the starter-visible profile fails around `/load/index`, repeat the same
clean test state with the empty-Home and strict-minimal profiles. Keep one JSONL
file per run, then compare them together:

```powershell
python .\scripts\analyze-runtime-events.py `
  starter=.\work\runtime-starter.jsonl `
  empty=.\work\runtime-empty.jsonl `
  strict=.\work\runtime-strict.jsonl `
  -o .\work\runtime-differential.json
```

`comparison.common_prefix_events` is the number of identical sanitized event
signatures shared by all supplied runs. `comparison.divergence_event_index` and
`comparison.states` show the first differing route/status/error/resource-version
state. This is a triage aid only: any new `/load/index` field must still be backed
by final 11.6.3 parser or runtime evidence before it enters a synthetic profile.

## Sharing boundary

Preferred shareable artifacts are the sanitized JSONL trace and/or the analyzer's
JSON report. Keep ADB logcat and any raw packet/body capture local until identifiers,
sessions, and account data have been removed. In particular, do not commit UDID,
SID, USER-ID, PARAM, decoded `viewer_id`, or decoded request/response values.
