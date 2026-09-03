# Sanitized runtime event analysis

The compatibility stack emits deliberately sanitized control/resource JSONL.
`scripts/analyze-runtime-events.py` validates those traces, merges independent
server streams, optionally attaches strict category-only device logcat evidence,
and produces a deterministic final-11.6.3 integration report.

Unknown fields, non-allow-listed headers, unknown synthetic resource routes and
non-whitelisted device fields are rejected rather than copied into reports.

## Evidence language

Final static analysis proves:

- result code 214 persists `required_res_ver`;
- 214 does **not** automatically resend `/load/check` in the same network
  coroutine;
- parent `GameInitialize` subsequently resumes into
  `AssetManager.InitializeManifest -> DownloadOrLoadForInitialize`;
- successful `/load/index` has a static tail to `Home=6` or `Login_Bonus=7`.

The analyzer records observations rather than inventing a retry:

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

Report schema is now **4**.

## Preferred runtime capture topology

Use `scripts/run-rooted-local-stack.py` rather than two standalone TLS servers.
It owns:

```text
API backend       127.0.0.1:8080
resource backend  127.0.0.1:8081
TLS Host mux      127.0.0.1:8445
```

The two backend logs remain independent:

```text
work/runtime-starter-control.jsonl
work/runtime-starter-resource.jsonl
```

Resource paths are reduced before logging to exactly:

```text
@resource/manifest
@resource/AssetBundles
@resource/Sound
@resource/Movie
@resource/Generic
@resource/unresolved
```

Filename, object hash and query string never enter the sanitized event. `/healthz`
is excluded so monitoring cannot fake resource progress.

## Capture package-scoped device logcat privately

For pre-HTTP TLS failures, crashes, ANRs and transport failures, run in another
PowerShell before launching the game:

```powershell
.\scripts\capture-device-logcat.ps1
```

It waits for `jp.co.bandainamcoent.BNEI0242` to appear, captures only that PID with
`logcat -v epoch`, and does **not** print raw messages to the terminal.

Raw capture goes under gitignored/private work state:

```text
work/private/cgss-logcat-<timestamp>.txt
```

On capture completion it runs `scripts/sanitize-device-logcat.py` and produces:

```text
work/runtime-device-<timestamp>.jsonl
```

The sanitized device event schema contains exactly:

```text
schema
time
source = device_logcat
category
severity
```

No tag, PID/TID, message text, URL, hostname, exception text, certificate details,
SID, UDID or matched substring is copied.

Allowed diagnostic categories are:

```text
process_crash
anr
tls_certificate_error
tls_handshake_error
dns_error
connection_refused
network_unreachable
network_timeout
http_error
unity_web_request_error
process_exit
```

**Never share the raw `work/private/...` capture.** Share only the sanitized JSONL
when needed.

## Merge control/resource streams and attach device diagnostics

Typical starter report:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run starter=.\work\runtime-starter-control.jsonl `
  --merge-run starter=.\work\runtime-starter-resource.jsonl `
  --device-log starter=.\work\runtime-device-20260903-120000.jsonl `
  -o .\work\runtime-starter-report.json
```

Repeated `--merge-run` entries with the same label are sorted by numeric event
`time`. Every server event in a merged run must have a timestamp.

`--device-log` must target an existing run label. Device events are deliberately
**not inserted into the HTTP/resource sequence**. Instead the run gains:

```text
device_diagnostics.events
device_diagnostics.categories
device_diagnostics.severities
device_diagnostics.first_event
device_diagnostics.first_failure
device_diagnostics.has_tls_error
device_diagnostics.has_process_crash
device_diagnostics.has_anr
device_diagnostics.has_network_error
```

This means a TLS logcat error can explain why the server saw no request, but it
cannot advance `phase`, fabricate resource traffic, change
`comparison.common_prefix_events`, or become an HTTP `first_failure`.

## Deterministic next-gate triage

After producing the schema-4 analyzer report, classify the first actionable
runtime gate with the separate strict post-processor:

```powershell
python .\scripts\triage-runtime-report.py `
  .\work\runtime-starter-report.json `
  -o .\work\runtime-starter-triage.json
```

The triage output is schema **1**. It deliberately does **not** copy the analyzer
report wholesale. It validates the expected sanitized report shape and emits only
an allow-listed summary for each run:

```text
classification
next_gate
reason
server_phase
first_server_failure
first_device_failure_category
visible_home_proven
```

This keeps the existing sharing boundary intact even if an arbitrary field is
injected into an input JSON file. `visible_home_proven` is always `false`; no
HTTP/resource/device-category combination is allowed to fabricate a visual Home
observation.

Representative classifications include:

```text
pre_http_tls_failure
pre_http_dns_failure
pre_http_tunnel_failure
stalled_after_214_before_resource
resource_route_unresolved
resource_response_failure
stalled_after_resource_plane
load_index_response_failure
load_index_reached_visual_gate
post_load_index_server_gap
post_load_index_observed_visual_gate
client_failure_after_load_index
```

The classifier is progress-aware. A recoverable earlier 404 does not override a
later successful `/load/index`. Conversely, a failing `/load/index` remains a
server-contract gate, and the first failure after `/load/index` is classified as a
post-index compatibility gap. For native 214, absence of an immediate second
`/load/check` is explicitly not treated as a failure.

The triage file is intended to answer “which layer is next?” after a single real
device capture. It still cannot diagnose details that were intentionally removed
from sanitized evidence; for example, `resource_route_unresolved` tells you to
identify the missing URL family from private local evidence rather than exposing a
resource filename or hash in the shareable report.

## Phase semantics

Hard server-observation phases remain:

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

`/load/title` is reported in `reached` but does not advance the hard mainline
phase.

`resource_plane_observed` means a sanitized `@resource/*` request was seen.
`resource_plane_served` requires at least one non-`unresolved` resource event with
HTTP status below 400.

A valid native server timeline can be:

```text
/load/check             result_code=214
@resource/manifest      200
@resource/Generic       200/206
/load/index             200
```

No second `/load/check` is required.

## What the report proves

A 214 event proves only what the server returned. A later resource event proves
the client advanced into the statically expected resource stage. `/load/index`
proves it advanced beyond that stage. A later event after `/load/index` is further
acceptance evidence, but visible Home still requires original-client observation.

A device `tls_certificate_error` with `no_http_request` is useful evidence that
the failure happened before the local HTTP backend. Conversely, a clean device
diagnostic section does not prove TLS success; absence of a classified log line is
not proof of absence.

## Native-vs-direct-success differential

Native old-10133000 behavior:

```text
214 + required_res_ver=10133800
```

Diagnostic only:

```text
--accept-old-resource-version
```

Compare equivalent clean states only when native mode fails to produce useful
resource evidence.

Example:

```powershell
python .\scripts\analyze-runtime-events.py `
  --merge-run native=.\work\runtime-native-control.jsonl `
  --merge-run native=.\work\runtime-native-resource.jsonl `
  --device-log native=.\work\runtime-native-device.jsonl `
  --merge-run direct=.\work\runtime-direct-control.jsonl `
  --merge-run direct=.\work\runtime-direct-resource.jsonl `
  --device-log direct=.\work\runtime-direct-device.jsonl `
  -o .\work\runtime-resource-policy-diff.json
```

HTTP/resource `comparison` remains based only on server-event signatures; device
summaries are attached per run for diagnosis.

Run `triage-runtime-report.py` on the resulting differential report as well. Each
run is classified independently; the original analyzer `comparison` remains the
authority for the first cross-run HTTP signature divergence.

## Starter/empty/strict differential

Only if the starter profile reaches `/load/index` but fails around Home, repeat
equivalent clean states with empty/strict profiles. Use the server sequence
comparison to identify the first differing observable action; do not infer missing
JSON fields from device categories alone.

## Sharing boundary

Shareable traces must remain in the strict sanitized schemas. Never commit or
share UDID, SID, USER-ID, PARAM, decoded viewer/account values, decoded bodies,
resource filenames/hashes, production credentials, raw logcat, or raw packet
captures.
