# CGSS 11.6.3 server-facing semantic analysis handoff — 2026-09-04

Branch: `analysis/server-contracts-11.6.3`

This note records the batch semantic work completed after C7a. It is intentionally
about static/client-semantic evidence. Nothing here is untouched-device/UI success.

## Evidence boundary

Keep these levels separate:

1. native/static parser or direct-xref evidence;
2. sanitized contract/semantic artifact success;
3. untouched client reached/accepted an endpoint;
4. actual device/UI-visible success.

This work reaches levels 1–2 only. No rooted-device or visible-Home validation was
performed during this tranche.

`endpoint -> state mutation` in C9 is an exact C7a endpoint-candidate binding.
`endpoint -> state -> consumer` is a **state-surface inference**: the endpoint is
known to mutate a state type and C7b proves a direct reader xref from that same
state type to a consumer. It is useful feature-discovery evidence, but is not
endpoint-specific control-flow proof.

## C7b — state readers and direct consumers

Implementation:

- `scripts/analyze-state-consumers.py`
- `.github/workflows/analyze-state-consumers.yml`
- analyzer commit `a1144ab341caff5a359efd9ece86ec8e0ad16b4a`
- workflow commit `b4953b1a415cb164aa77f44c681b6b8ac691b576`

Exact-specimen run:

- run `33837151997`
- artifact `9923665139` — `final-client-c7b-state-consumers`

First real artifact statistics:

- C7a state types: 171
- reader methods: 2,235
- unique reader RVAs: 2,235
- shared reader RVAs: 0
- direct reader xrefs: 10,416
- unique reader -> consumer relations: 7,522
- unique consumer methods: 4,005
- strictly game-owned consumer methods: 3,964
- state types with readers: 165 / 171
- state types with direct consumers: 138 / 171
- endpoint -> state -> unique consumer-method bridges: 72,249
- direct edge kinds: 10,303 `BL`, 113 direct `B` tail edges
- promoted relation edge kinds: 7,414 `BL`, 108 `B-tail`
- unresolved direct xrefs: 5, all `B-tail`; unresolved `BL`: 0
- ambiguous reader RVA xrefs: 0
- ambiguous managed caller xrefs: 0

Six C7a state types currently have no reader-like method under the conservative
reader-verb selector:

- `Stage.TempData.AnniversaryTempData`
- `Stage.TempData.LiveResultTempData.EventRailData`
- `Stage.TempData.LiveResultTempData.UserUpdateInfoData`
- `Stage.TempData.NameCardListTempData`
- `Stage.WorkLotteryData.LotteryData.LotteryTicket`
- `Stage.WorkReTowerFloorData`

### C7b refinement

A first refinement incorrectly tested for a self-tail relation. Actual data showed
three **zero-offset tail thunks**: the branch instruction is at the consumer method
start, but its target reader RVA is different. Those edges are evidence and must
not be deleted.

Corrected refined run:

- run `33837477757`
- artifact `9923752401` — `final-client-c7b-state-consumers-refined`
- artifact zip digest `sha256:f2ca8d10106aeff0a0c5fdff1bfe0e45116e96826d047af57dce9bd3be5aba79`
- refined JSON sha256 `1d34656cf2b8d76e59b68a41454650eefa97b364878c09e7236349cb057728d5`

Refinement preserves all 7,522 promoted relations and annotates:

- zero-offset direct-`B` tail thunks: 3
- compiler-generated lambda relations: 304
- async/iterator state-machine relations: 128
- regular relations: 7,090
- unresolved xrefs by edge kind: `B-tail=5`, `BL=0`

Indirect `BR/BLR`, interface dispatch and generic/runtime dispatch are **not**
recovered by C7b and remain conservative unknowns.

## C8 — conservative subsystem classification

Implementation:

- `scripts/classify-state-consumer-subsystems.py`
- `.github/workflows/classify-state-consumer-subsystems.yml`
- corrected classifier commit `d925187283484bd209a01ff0f2870924012f0212`

Successful run:

- run `33837662678`
- artifact `9923813313` — `final-client-c8-state-consumer-subsystems`
- artifact digest `sha256:777be6c293d364f43e1077f8dbd46bf46d9d0c5433b53e73ee3b37c1bcde9d6e`
- JSON sha256 `65cda85797fef329c6a721af2c4fd9f9f3ac1a04ad8ebb793287a5c4a133e522`

Evidence policy:

- declaring consumer owner/type: strongest lexical evidence;
- consumer method: next;
- state type and reader name: weaker supporting evidence;
- upstream API route: context only, **never classification proof**.

Real result:

- relations: 7,522
- classified: 6,135 (81.56%)
- ambiguous: 363
- unknown: 1,024
- confidence: high 5,131; medium 98; low 906; ambiguous 363; unknown 1,024
- consumer methods receiving multiple classified subsystem labels: 37
- endpoint -> state -> subsystem bridges: 2,336

Relation counts by classified subsystem:

- card/idol 2,076
- event 1,279
- live 1,211
- story/commu 378
- gacha 266
- room 263
- live-result 200
- shop 115
- home 106
- shared-core 96
- mission 77
- profile 37
- friend/social 18
- payment 13

Do not interpret 81.56% as feature completeness. It is the share of C7b direct
reader-consumer relations that received a conservative subsystem label.

## C9 — unified client semantic DB

Implementation:

- `scripts/build-client-semantic-db.py`
- initial builder commit `8d9d986a8cb6434321e9e0f28e4bfe73db8e4b3d`

The DB preserves independent C6 `endpoint_id` values. `(route, enum)` is not a
unique endpoint identity. In particular `/tool/signup_migration` / `SignUpMigration`
still has two endpoint rows: endpoint 4 (`A`, key 3, `proven-static`) and endpoint
519 (`B`, key 2, `unresolved`).

Added normalized surfaces:

- `subsystems`
- `state_mutations`
- `state_readers`
- `state_consumers`
- `endpoint_state_mutations`
- `endpoint_state_consumers`
- `endpoint_subsystems`
- `endpoint_state_consumer_methods` view
- `endpoint_state_edges` view
- `endpoint_semantics` view

The initial C9 build was successful, but was later superseded after C5 tail-aware
requiredness refinement. Use the final tail-aware C9 artifact below.

## C5 managed direct-tail refinement

New analyzer/workflow:

- `scripts/classify-response-requiredness-tail-aware.py`
- `.github/workflows/refine-response-requiredness-tail-aware.yml`
- analyzer commit `ce338e1959b9aaebb9efffa1fbd0d9b853bff26d`
- workflow commit `b33aff680e9e3043b0908790b2ffd3009af3f96d`

Policy:

- direct unconditional external ARM64 `B` is a legal CFG exit **only** when the
  statically decoded target exactly equals an Il2CppDumper `ScriptMethod` start;
- unknown external `B` remains incomplete;
- conditional external target remains incomplete;
- `BR/BRAA/BRAB` remains incomplete;
- direct-index `required-path` must dominate every reachable known exit: normal
  `RET` plus validated managed tail-call exits.

Successful run:

- run `33838117207`
- artifact `9923983560` — `final-client-c5-response-wire-contracts-tail-aware`
- artifact digest `sha256:1f8ebe1c6084efb10ac3532518c4c33036c1f88fb48c4a37a1a43ebabed6b1c2`
- JSON sha256 `b4636bec68e6e5a2312f23eec8e2be7afa5befab388e53ade8e72920dd4e7a43`

Original C5 had 26 incomplete CFGs: 11 direct external-tail methods and 15 indirect
branch methods. Exact refinement validates only 5 of the 11 direct-tail methods;
the other 6 stay unknown because their targets do not meet the managed-method-start
criterion.

Result:

- complete CFGs: 339 -> 344
- incomplete CFGs: 26 -> 21
- validated managed tail methods/edges: 5 / 5
- remaining incomplete: 15 `indirect-branch`, 6 `unverified-external-tail-branch`
- access `unknown-cfg`: 454 -> 444
- access `required-path`: 24 -> 31
- access `conditional-direct`: 1,792 -> 1,795
- contract `unknown-cfg`: 258 -> 250
- contract `required-path`: 24 -> 30
- contract `conditional-direct`: 1,530 -> 1,532

Validated managed tail targets include:

- `StageMinigame.ArcadeCommonJsonParser$$EachOnPlayerArray`
- `Stage.NetworkUtil$$SetRelianceMissionRewardData`
- `Stage.NetworkUtil$$SetBusOpenedData`
- `Stage.NetworkUtil$$CheckReplaceLiveMv`
- `LitJson.JsonData$$op_Explicit`

Do not auto-promote the other six direct external `B` cases without new evidence.

## Refined C6

Workflow:

- `.github/workflows/build-server-facing-contract-db-tail-aware.yml`
- final assertion-fix commit `7cee26a2da49ecca98025802407b56152c0ea2dd`

Successful run:

- run `33838272300`
- artifact `9924013286` — `final-client-c6-server-facing-contract-db-tail-aware`
- artifact digest `sha256:5493b811ba7d08f28702d3f1f9bc32e3790a5540f1005aca95fde3cdc424d1fe`
- SQLite sha256 `4c623a2d2ac7e6b5968d907c292160e52b25dee0355bf7041d436a38e77daedb`

C6 remains:

- endpoints 538
- endpoints with request contracts 284
- endpoints with response contracts 331
- request bindings 1,047
- response bindings 1,916
- unbound request contracts 0
- unbound response contracts 82

Endpoint-bound response requiredness changed from the old C6:

- `required-path`: 19 -> 21
- `unknown-cfg`: 290 -> 288
- `conditional-direct`: 1,485 (unchanged)
- optional-conditional: 114
- optional-defaulted: 8

The smaller endpoint-bound delta versus the full C5 delta is expected: some refined
C5 field contracts are among the 82 response contracts that are still unbound to a
C6 endpoint.

## Final tail-aware C9 — use this artifact

Workflow:

- `.github/workflows/build-client-semantic-db-tail-aware.yml`
- commit `f1ac80300c8d41d689130da3016e6d73e0badaa1`

Successful run:

- run `33838319342`
- artifact `9924031141` — `final-client-c9-client-semantic-db-tail-aware`
- artifact digest `sha256:7fd383f3e0337d37c6c849dba78b1ae9d4818dd694fe1c20038e4fd83ce09980`
- semantic SQLite sha256 `a85922db2c106de3412cac511c8183ea34559eed8f844ef5186467f76dcdd8fd`

The actual downloaded artifact was queried after CI:

- `PRAGMA quick_check = ok`
- endpoints / `endpoint_semantics`: 538 / 538
- state mutations: 1,358
- state readers: 2,235
- state consumer relations: 7,522
- exact endpoint -> mutation links: 1,476
- inferred endpoint -> state -> consumer relation bridges: 105,072
- inferred endpoint -> state -> unique consumer-method bridges: 72,249
- inferred endpoint -> state -> subsystem links: 2,336
- unmatched C7a endpoint candidates: 0
- refined endpoint-bound response requiredness: `required-path=21`, `unknown-cfg=288`

Example actual query results from `endpoint_semantics`:

`/live/end` (endpoint 58):

- request fields: 3
- response fields: 39
- exact state mutation links: 55
- inferred unique state consumer methods: 2,678

The 2,678 number is not 2,678 `/live/end` direct callees. It is the deduplicated
state-surface bridge described above.

`/story/start` (endpoint 48):

- response fields: 2
- exact state mutation links: 3
- inferred unique consumer methods: 3
- inferred subsystem: `story-commu`

## What remains unknown / next static work

Do not redo C0–C9 from scratch. The important unresolved surfaces are now narrower:

1. C7b indirect dispatch: `BR/BLR`, interface/generic dispatch, helper bridges not
   represented as a direct reader xref.
2. The six C5 direct external `B` targets that fail exact `ScriptMethod`-start
   validation. They need thunk/PLT/helper-specific evidence, not blanket promotion.
3. The 15 C5 indirect-branch parser methods remain `unknown-cfg` by design.
4. C8 leaves 363 ambiguous and 1,024 unknown reader-consumer relations; do not
   force them by route-name heuristics.
5. 82 response field contracts remain unbound at C6 endpoint level.
6. Actual untouched-client acceptance/UI success still requires device evidence.

The semantic DB is now suitable as the source for generated local-server models,
route skeletons and deterministic archival templates. Generation should consume
the DB rather than hand-writing 538 routes, and generated code must carry the
exact-vs-inferred evidence distinction through to tests and response templates.
