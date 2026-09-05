# SERVER DOMAIN HANDOFF — CGSS preservation server

Authoritative continuation note for the server-domain/business phase on:

```text
analysis/server-contracts-11.6.3
```

Read together with `CLIENT_CONTRACT_HANDOFF.md`, `docs/server-domain-model-v0.md`
and `docs/load-index-11.6.3.md`.

## Evidence boundary

Keep these levels separate:

1. preservation design/policy;
2. final-client static/native/parser evidence + server CI/integration tests;
3. target-client runtime endpoint acceptance;
4. real-device/UI-visible success.

The work below is level 1/2. It does **not** prove new target-client or UI success.

## Current continuation point

Domain-design baseline:

```text
2a42e89af5cee120b6a67144108f96597f2319e1
```

Latest stable code/test commit at this handoff refresh:

```text
259baa554b60662f1e71b6c210ef15a10e5a0473
tests: cover full UnitEdit compatibility round trip
```

Successful verification at that commit:

```text
33949415863  Test preservation domain core  success
33949415860  CI                             success
```

Always re-read branch HEAD before writing because multiple agents may use the same
branch.

## Architecture now implemented

```text
CGSS 11.6.3 client
        |
        v
CGSS wire adapter
        |
        v
application/controller
        |
        v
preservation domain service
        |
        +--> SQLite mutable semantic user state
        |
        +--> read-only master.mdb projection

client numeric IDs + client-only compatibility state
        |
        `--> separate compatibility SQLite store
```

Rules:

- DB schema != API response DTO;
- DB schema != client `Work*`/`Savedata*` layout;
- immutable master data remains separate;
- client numeric IDs are not domain primary-key semantics;
- exact/inferred/policy evidence stays explicit;
- SQLite worker threads open their own short-lived connections;
- static/CI success is never reported as client/UI success.

## Domain core / D1 state

Implemented:

- Evidence / EvidenceStatus / EvidenceKind
- ChangeSet / EntityChange / ResourceChange / Reward
- Clock / Random / Id providers
- PlayerProfile
- PlayerResource
- CardOwnership
- Unit / UnitMember
- FeatureUnlock
- HomeStateSnapshot

## CardOwnership — final 11.6.3 semantics

Exact-specimen workflow:

```text
33910221352  Analyze WorkCardData field semantics  success
```

Durable card state includes:

```text
master_card_id
level
experience
skill_level
star_lesson_step
love
is_protected
favorite
```

Final-client proven-static mappings:

```text
wire step    -> CardOwnership.star_lesson_step
wire love    -> CardOwnership.love
wire protect -> CardOwnership.is_protected
```

`favorite` is independent from protection. Its exact network mutation contract is
not yet closed; do not infer that it shares A:29 toggle semantics.

## SQLite semantic-domain schema v2

`server/domain/persistence.py`:

```text
SCHEMA_VERSION = 2
```

v1 -> v2 migration:

```text
locked -> is_protected
add star_lesson_step DEFAULT 0
add love DEFAULT 0
```

## Compatibility SQLite schema v2

`server/adapters/identity_store.py` now uses:

```text
SCHEMA_VERSION = 2
```

Stable identity tables remain:

```text
card_identity_bindings
unit_identity_bindings
```

Mappings:

```text
(player_id, domain user_card_id) -> positive CGSS serial_id
(player_id, domain unit_id)      -> positive CGSS unit_id
(player_id, CGSS serial_id)      -> domain user_card_id
(player_id, CGSS client unit_id) -> domain unit_id
```

New compatibility-only mutable tables:

```text
unit_compatibility_slots
  player_id
  domain_unit_id
  position
  dress_type
  dress_2d_type
  dress_storage_id

player_unit_preferences
  player_id
  main_domain_unit_id
```

These fields remain outside the semantic Unit/UnitMember model because current
final-client evidence proves their client/wire persistence role, not a richer
server-domain business meaning.

Migration tests prove v1 identity rows survive v1 -> v2 migration.

## Domain-backed `/load/index`

Current read path:

```text
SQLite archival profile
 -> PreservationProfileService
 -> HomeStateSnapshot
 -> compatibility identity/cosmetic state
 -> final-client /load/index adapter
 -> CGSS codec/HTTP
```

Unit cosmetics are omitted when no compatibility state exists. This preserves the
exact final-parser result that the formatted keys are guarded/optional.

After an exact A:19 write persists them, `/load/index` projects:

```text
dress_type_{0..4}
dress_2d_type_{0..4}
dress_storage_id_{0..4}
```

No `main_unit_id` field is invented in `/load/index`; no exact startup field for
that selection has been established.

## A:29 MemberProtect — first complete write loop

Exact final route/request:

```text
group/key : A:29
ApiType   : MemberProtect
path      : member/protect_card
task      : Stage.MemberProtectCardTask
request   : MemberProtectCardTaskParam.serial_ids : int[]
```

Exact response parser consumes:

```text
data
protect_card_list
```

The durable field and response membership are `PROVEN_STATIC / EXACT`. Production
server mutation internals are unavailable; preservation toggle semantics remain
`PROVEN_STATIC / INFERRED`.

Application/integration:

```text
server/application/member_protect.py
tests/test_domain_application_member_protect_http.py
33947000143  Test preservation domain core  success
```

## A:19 MemberUnitEdit exact contract — CLOSED

Exact final route:

```text
group/key : A:19
ApiType   : MemberUnitEdit
path      : unit/edit
task      : Stage.MemberUnitEditTask
```

Exact request DTO:

```text
MemberUnitEditTaskParam
  unit_info_list : UnitInfo[]
  main_unit_id   : int

UnitInfo
  unit_id           : int
  serial_ids        : int[]
  dress_types       : int[]
  dress_2d_types    : int[]
  dress_storage_ids : int[]
```

Exact `SetParameter` evidence shows the five parallel slot families come from:

```text
serial_ids        <- WorkUnitData.UnitData.GetUnitSerial
 dress_types      <- WorkUnitData.UnitData.GetCostumeId
 dress_2d_types   <- WorkUnitData.UnitData.GetCostume2dId
 dress_storage_ids<- WorkUnitData.UnitData.GetClosetId
```

### A:19 response semantics — exact empty endpoint data

Final `MemberUnitEditTask.Parse()` is exactly:

```text
0x489D1B8: mov x1, xzr
0x489D1BC: b Stage.BaseTask$$Parse
```

Therefore endpoint-specific response data is exactly empty and the preservation
handler returns common success with:

```json
{"data": {}}
```

### `main_unit_id` identity semantics — CLOSED EXACT

Targeted final-client workflow:

```text
33948716385  Analyze UnitEdit endpoint  success
```

Managed layout establishes:

```text
WorkUnitData.UnitData._unitId : ObscuredInt @ 0x10
```

The exact bounded native caller flow is:

```text
WorkUnitData.GetMainUnit()
 -> load returned UnitData + 0x10
 -> CodeStage.AntiCheat.ObscuredTypes.ObscuredInt.op_Implicit
 -> int
 -> MemberUnitEditTask.SetParameter(mainUnit,...)
 -> request main_unit_id
```

Therefore observed final-client `main_unit_id == WorkUnitData.UnitData._unitId` is
`PROVEN_STATIC / EXACT`, not a slot-number guess.

The application reverse-resolves positive client `main_unit_id` through the stable
compatibility unit identity map and persists the corresponding domain-unit
reference in `player_unit_preferences`.

`main_unit_id == 0` remains only an adapter-safe preservation sentinel for “no
saved main unit”; no observed final UI caller path has been shown to emit zero. Do
not promote zero-sentinel behavior to exact production semantics.

## A:19 semantic + compatibility persistence

Semantic membership command:

```text
PreservationUnitService.replace_members(...)
```

Properties:

- validates all target units and owned cards before first semantic write;
- replaces one or more Unit membership lists in one semantic DB transaction;
- preserves unit slot/name;
- duplicate unit updates rejected;
- serial 0 represents an empty final-client member slot.

Application layer:

```text
server/adapters/unit_edit.py
server/application/unit_edit.py
```

Before any persistent mutation it resolves/validates:

```text
all client unit IDs
all positive card serial IDs
all four five-slot arrays
main_unit_id
```

Then:

```text
serial membership
 -> semantic domain SQLite

dress/costume arrays + main-unit selection
 -> compatibility SQLite
```

### Cross-DB atomicity limitation

The semantic domain DB and compatibility DB are intentionally separate SQLite
files. Each side is internally transactional, but there is no distributed
transaction spanning both files. A compatibility-DB I/O failure after the semantic
commit can theoretically leave a split state.

This limitation is explicit and must not be described as full composite atomicity.
All ordinary validation failures happen before either store is mutated.

## SECOND COMPLETE SERVER-SIDE WRITE LOOP — A:19 CLOSED

Full encrypted integration test:

```text
tests/test_domain_application_unit_edit_http.py
33949415863  Test preservation domain core  success
33949415860  CI                             success
```

The tested chain is:

```text
/load/index
 -> serial slots [1,2,0,0,0]
 -> no invented dress/costume keys

POST /unit/edit
 -> serial_ids [3,0,1,0,0]
 -> dress_types [101,0,202,0,0]
 -> dress_2d_types [11,0,22,0,0]
 -> dress_storage_ids [1001,0,2002,0,0]
 -> main_unit_id 1
 -> exact response data={}

/load/index
 -> serial slots [3,0,1,0,0]
 -> persisted dress_type_0..4
 -> persisted dress_2d_type_0..4
 -> persisted dress_storage_id_0..4

reopen semantic SQLite
 -> Unit.members remains changed

reopen compatibility SQLite
 -> main domain unit remains selected
 -> all five cosmetic compatibility slots remain saved
```

This closes the server-side A:19 membership + client compatibility round trip.
It does **not** prove patched/final target-client runtime acceptance or UI success.

## Runnable domain server

Current dynamic routes:

```text
/load/index
/member/protect_card
/unit/edit
```

Generic application transport remains endpoint-agnostic:

```text
server/application_http.py
server/bootstrap_core.py::process_application_request
```

## Immediate continuation

Do not redo A:19 route/request/response/main-unit work.

Next write-state slice should be recovered from exact final 11.6.3 evidence. Current
preferred target:

```text
favorite-card mutation
```

Procedure:

1. filter the exact final API map for favorite/member/card candidates;
2. identify the exact task/request DTO from final `dump.cs`;
3. bounded native analysis only for the task SetParameter/Parse and immediate caller;
4. determine whether mutation is explicit bool/set/unset/toggle before writing
   domain logic;
5. project only fields the final response parser actually consumes;
6. add encrypted HTTP -> SQLite -> readback integration test;
7. if favorite-card has no standalone route, follow the exact final caller to the
   actual state mutation endpoint rather than inventing one.

Then proceed to Story/Commu and Live state transitions.

## Broader remaining gaps

- master.mdb semantic mappings for idol/item/story/music/mission/etc.;
- more durable `user_info` fields vs compatibility policy;
- startup snapshot vs shared-response delta conventions;
- favorite-card network mutation semantics;
- Story/Commu state transitions;
- Live start/end/reward transitions;
- patched-client runtime acceptance;
- actual device/UI-visible Home/features.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3`; confirm HEAD before writing.
2. Do not redo C0-C9/bootstrap protocol archaeology.
3. Treat card step/love/protect durable mappings as closed final-client evidence.
4. Treat A:29 request/response as exact; toggle algorithm remains inferred.
5. Treat A:19 route/request/empty response/main-unit identity as exact final 11.6.3 evidence.
6. Treat A:19 membership + costume/main compatibility server round-trip as closed.
7. Keep semantic domain and client compatibility state separated.
8. Remember A:19 semantic+compatibility writes are not a distributed transaction.
9. Reuse `server/application_http.py` for new dynamic endpoints.
10. Update this file with commit SHA + CI run after every coherent tranche.
11. Never report static/CI success as real-device or UI success.
