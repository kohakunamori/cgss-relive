# C9-driven runtime contracts and blocker loop

This layer connects the sanitized final-client semantic database to the local
compatibility server **without** turning parser evidence into fabricated success
responses.

## Evidence boundary

The final tail-aware C9 SQLite is static/semantic evidence.  It proves route/task,
flat request/response parser-field, state-mutation and state-consumer relationships
at the evidence levels documented in `docs/analysis/C7B-C9-SEMANTIC-HANDOFF-2026-09-04.md`.
It does not prove that an arbitrary JSON value is a valid runtime response body.

Accordingly:

- specialized reconstructed bootstrap handlers remain authoritative;
- a C9-known but otherwise unimplemented route returns HTTP **501** with
  `contract_known_template_missing` in the sanitized event log;
- a route absent from C9 remains HTTP **404**;
- only an explicit local data template can turn a non-bootstrap route into a
  normal encrypted `result_code=1` response;
- the nine final-client HTTP path-collision groups cannot use path-only templates.

A server 200/1 response is still only server behavior.  It is not untouched-client
acceptance or visible-UI success until a later client action/device observation
proves that.

## Final semantic input

Use the tail-aware C9 artifact produced by workflow run `33838319342`:

- artifact: `9924031141` (`final-client-c9-client-semantic-db-tail-aware`)
- artifact zip SHA256:
  `7fd383f3e0337d37c6c849dba78b1ae9d4818dd694fe1c20038e4fd83ce09980`
- `contracts-semantic-11.6.3.sqlite` SHA256:
  `a85922db2c106de3412cac511c8183ea34559eed8f844ef5186467f76dcdd8fd`

`server.semantic_contracts.SemanticContractIndex` opens the DB read-only and
requires:

- `PRAGMA quick_check = ok`
- 538 endpoint records
- 526 unique HTTP paths
- nine duplicate-route groups
- the required C9 tables/views

Do not substitute an older C6/C9 SQLite unless the expected counts/hashes and the
consumer of the file are intentionally updated together.

## Runtime route recognition

Start the control server with:

```bash
python -m server.http_server \
  --semantic-db /path/to/contracts-semantic-11.6.3.sqlite \
  --event-log work/runtime-control.jsonl \
  --experimental-starter-load-index
```

For a known unimplemented final route the response is intentionally 501.  The
sanitized event may include only public/derived contract metadata such as:

```json
{
  "route": "/story/start",
  "status": 501,
  "error": "contract_known_template_missing",
  "contract_candidates": [
    {
      "endpoint_id": 48,
      "group": "A",
      "key": 47,
      "enum": "StoryStart",
      "status": "proven-static",
      "request_field_count": 0,
      "response_field_count": 2,
      "required_response_field_count": 0,
      "unknown_response_field_count": 0,
      "exact_state_mutation_count": 3
    }
  ]
}
```

No UDID/SID/viewer/account values, request values, response values, native bytes,
or resource identifiers are added to this event schema.

## Explicit response templates

Templates are local runtime inputs, not generated from flat fields.  Schema 1:

```json
{
  "schema": 1,
  "routes": {
    "/story/start": {
      "endpoint_id": 48,
      "data": {
        "...": "reconstructed values backed by endpoint-specific evidence"
      },
      "evidence": "brief provenance note"
    }
  }
}
```

Then run:

```bash
python -m server.http_server \
  --semantic-db /path/to/contracts-semantic-11.6.3.sqlite \
  --response-templates /path/to/local-response-templates.json \
  --event-log work/runtime-control.jsonl \
  --experimental-starter-load-index
```

The server supplies `data_headers`, `result_code=1`, `servertime`, SID propagation,
and CGSS response encryption.  The template supplies only the reconstructed `data`
object.

The template loader rejects:

- a route absent from C9;
- an endpoint ID that does not exactly match the route candidate;
- any of the final path-collision routes;
- non-object `data`;
- extra schema keys.

Do not use `{}` merely to get a green HTTP status.  A template should be added only
after endpoint-specific parser/runtime evidence supports the required shape and
safe values.

## Rooted-device stack

The same inputs are accepted by the supervised stack:

```bash
python scripts/run-rooted-local-stack.py \
  --semantic-db /path/to/contracts-semantic-11.6.3.sqlite \
  --response-templates /path/to/local-response-templates.json
```

Omit `--response-templates` on the first run.  This deliberately stops at the first
known-but-unimplemented post-bootstrap endpoint and gives a deterministic semantic
blocker rather than silently returning a fake success.

## Analyze the first blocker

`analyze-runtime-events.py` report schema 5 accepts the sanitized
`contract_candidates` extension:

```bash
python scripts/analyze-runtime-events.py \
  --merge-run starter=work/runtime-starter-control.jsonl \
  --merge-run starter=work/runtime-starter-resource.jsonl \
  -o work/runtime-analysis.json
```

When the server records `contract_known_template_missing`, the report phase becomes:

```text
semantic_contract_blocker_observed
```

and `semantic_contract_blocker` contains:

- route and event index;
- candidate endpoint IDs;
- whether HTTP path identity is ambiguous;
- only sanitized C9 aggregate counts;
- one of two next actions:
  - `reconstruct_required_response_shape_then_supply_explicit_template`
  - `resolve_endpoint_identity_before_template`

The 501 remains `first_failure`.  The phase does not claim endpoint acceptance.

## Deterministic C10 catalog

`scripts/export-runtime-contract-catalog.py` converts the C9 DB to a sanitized
JSON/Markdown route catalog for development.  The CI artifact is:

- workflow run: `33839546247`
- artifact: `9924426549` (`final-client-c10-runtime-contract-catalog`)
- artifact zip digest:
  `sha256:d5f66ed33d3b7250603643e5e96b11cdafff01aeac153df9c6a9632e569dc982`

The catalog contains routes, endpoint identities, flat field names/types/
requiredness and state/subsystem counts.  It intentionally contains no response
body values and cannot be used as an automatic success-template generator.

## Iteration rule

For real-client preservation work, repeat this loop:

1. run with the fixed final resources and C9 semantic recognition;
2. preserve the first 501/other failure in sanitized server/device evidence;
3. identify the exact endpoint record (resolve path collisions first);
4. derive the smallest endpoint-specific response shape/value semantics from
   native/parser/runtime evidence;
5. add one explicit local template or specialized handler;
6. rerun and require a later client action before calling the blocker accepted;
7. continue until the untouched client reaches and visibly renders the preserved
   Home, then apply the same rule to later offline features.
