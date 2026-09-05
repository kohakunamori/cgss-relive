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

Latest stable code commit before this handoff refresh:

```text
af7f68d6bb069f008505276f83a99dd9a2e92f00
tests: cover encrypted UnitEdit persistence loop
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
        +--> SQLite mutable user state
        |
        +--> read-only master.mdb projection

client numeric serial/unit identities
        |
        `--> separate compatibility identity SQLite store
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

`favorite` is independent from protection.

## SQLite domain schema v2

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

Migration and round-trip tests are green:

```text
33946077505  Test preservation domain core  success
```

## Persistent compatibility identities

`server/adapters/identity_store.py` persists:

```text
(player_id, domain user_card_id) -> positive CGSS serial_id
(player_id, domain unit_id)      -> positive CGSS unit_id
```

and reverse lookup:

```text
(player_id, CGSS serial_id)       -> domain user_card_id
(player_id, CGSS client unit_id)  -> domain unit_id
```

The mapping is stable across restarts and stays outside the domain model.

## Domain-backed `/load/index`

Current read path:

```text
SQLite archival profile
 -> PreservationProfileService
 -> HomeStateSnapshot
 -> compatibility identity map
 -> final-client /load/index adapter
 -> CGSS codec/HTTP
```

Server integration run:

```text
33909792669  Test preservation domain core  success
```

It proves:

1. HTTP `/load/index` reads mutable SQLite state;
2. a DB mutation is visible on the next request;
3. client numeric card/unit identities stay stable.

## A:29 MemberProtect exact contract

Exact final 11.6.3 route/request:

```text
group/key : A:29
ApiType   : MemberProtect
path      : member/protect_card
task      : Stage.MemberProtectCardTask
request   : MemberProtectCardTaskParam.serial_ids : int[]
```

There is no wire protect bool.

Adapter:

```text
server/adapters/member_protect.py
```

parses exactly `serial_ids[]` without manufacturing a state flag.

## A:29 exact response semantics — CLOSED

Response-semantic exact-specimen workflow:

```text
run       33946538333
conclusion success
artifact  final-client-card-protect-endpoint
artifact id 9963511531
artifact digest sha256:255f5cb275baf58bb5c7cf1ef0ac0b2e6cedd07f48fb991ff10ce329df122a53
```

`MemberProtectCardTask.Parse()` references exactly the relevant response keys:

```text
data
protect_card_list
```

For every requested serial the final client:

1. resolves `WorkCardData.GetCardDataWithSerial(serial)`;
2. writes `false` directly to the `_isProtect` backing state;
3. scans `response.data.protect_card_list`;
4. if the serial is present, writes `true` back to `_isProtect`.

Therefore the final-client-visible response contract is proven:

```json
{
  "data": {
    "protect_card_list": [1, 7, 42]
  }
}
```

The durable field and response membership are `PROVEN_STATIC / EXACT`. The
production server's internal mutation code is unavailable; the preservation command
currently uses toggle semantics and marks that algorithm `PROVEN_STATIC / INFERRED`.
Do not promote the toggle algorithm to exact without stronger production/runtime
evidence.

## FIRST COMPLETE SERVER-SIDE WRITE LOOP — A:29 CLOSED

Application:

```text
server/application/member_protect.py
SQLiteMemberProtectHandler
```

Integration test:

```text
tests/test_domain_application_member_protect_http.py
33947000143  Test preservation domain core  success
```

The real project codec + HTTP loop proves:

```text
/load/index protect=0
 -> encrypted POST /member/protect_card
 -> SQLite mutation
 -> exact protect_card_list response
 -> next /load/index protect=1
```

and a second request returns the card to protect=0 under the preservation toggle
algorithm.

## A:19 MemberUnitEdit exact contract — CLOSED

Targeted exact-final workflow:

```text
run       33948379527
conclusion success
artifact  final-client-unit-edit-endpoint
artifact id 9964039219
```

Exact final route:

```text
group/key : A:19
ApiType   : MemberUnitEdit
path      : unit/edit
task      : Stage.MemberUnitEditTask
```

Exact managed request DTO:

```text
MemberUnitEditTaskParam : BaseParam
  unit_info_list : MemberUnitEditTaskParam.UnitInfo[]
  main_unit_id   : int

MemberUnitEditTaskParam.UnitInfo
  unit_id           : int
  serial_ids        : int[]
  dress_types       : int[]
  dress_2d_types    : int[]
  dress_storage_ids : int[]
```

Exact task methods:

```text
MemberUnitEditTask.SetParameter
RVA 0x489CD08
void SetParameter(int mainUnit, Dictionary<int,int> unitDataList)

MemberUnitEditTask.Parse
RVA 0x489D1B8
protected override int Parse()
```

`SetParameter` exact/native evidence shows:

- `mainUnit` is written into request `main_unit_id`;
- it iterates the unit-data dictionary;
- it calls `ModifyMemberUnitLocal` before/while constructing request state;
- per member position it reads `GetUnitSerial`, `GetCostumeId`, `GetCostume2dId`,
  and `GetClosetId`;
- therefore the serial and three dress/costume arrays are real parallel client
  compatibility state, not historical-server guesses.

## A:19 response semantics — EXACT EMPTY ENDPOINT DATA

The final `MemberUnitEditTask.Parse()` body is exactly eight bytes / two ARM64
instructions:

```text
0x489D1B8: mov x1, xzr
0x489D1BC: b Stage.BaseTask$$Parse
```

Therefore A:19 consumes only the common task response and has no endpoint-specific
response members. The preservation handler returns:

```json
{"data": {}}
```

through the existing common success envelope/codec. This is final-client
`PROVEN_STATIC / EXACT` response-consumer evidence, not a guessed empty template.

## Unit domain mutation command

Implemented:

```text
server/domain/unit_services.py
PreservationUnitService.replace_members(...)
```

Properties:

- replaces one or more existing Unit membership lists atomically;
- validates all units and referenced owned cards before first write;
- duplicate unit updates rejected;
- invalid unit/card rejects the entire batch with no partial mutation;
- preserves Unit slot and name;
- identical membership is a no-op;
- no domain schema migration was required;
- member ordering/positions are `PROVEN_STATIC / EXACT` from final WorkUnitData and
  `/load/index user_unit_list` semantics.

Compatibility identity store now supports reverse client-unit lookup as well as
reverse card-serial lookup.

## A:19 application/wire adapter

Implemented:

```text
server/adapters/unit_edit.py
server/application/unit_edit.py
```

The request adapter preserves all exact request arrays and does not invent costume
semantics.

The application controller currently closes the semantic membership portion:

```text
client unit_id
 -> compatibility domain-unit lookup

serial_ids[0..4]
 -> zero = empty client slot
 -> positive serial -> domain owned-card lookup
 -> UnitMember(position, user_card_id)
 -> atomic PreservationUnitService.replace_members
```

It validates that all four parallel arrays contain exactly the final-client standard
five unit slots. `main_unit_id` and the three dress/costume arrays are intentionally
not persisted into the semantic Unit model yet because their durable server-domain
meaning is not closed.

`SQLiteMemberUnitEditHandler` opens short-lived SQLite domain/identity connections
per HTTP worker request.

## SECOND COMPLETE SERVER-SIDE WRITE LOOP — A:19 CLOSED FOR MEMBERSHIP

Runnable domain server now registers:

```text
/load/index
/member/protect_card
/unit/edit
```

UnitEdit integration tests:

```text
tests/test_domain_application_unit_edit.py
tests/test_domain_application_unit_edit_http.py
33948525124  Test preservation domain core  success
```

The encrypted HTTP integration test proves:

```text
/load/index
 -> unit serial slots [1,2,0,0,0]

POST /unit/edit
 -> exact request unit_info_list/main_unit_id shape
 -> membership serial slots [3,0,1,0,0]
 -> exact common success with data={}
 -> SQLite domain mutation

/load/index
 -> same stable client unit_id
 -> serial slots [3,0,1,0,0]

reopen SQLite
 -> Unit.members remains [(0,card:3),(2,card:1)]
```

This closes the server-side **unit membership** write loop. It does not yet claim
that `main_unit_id` or dress/costume selection persistence is closed, and it does
not prove target-client runtime/UI acceptance.

## Generic dynamic HTTP application extension

Implemented:

```text
server/application_http.py
server/bootstrap_core.py::process_application_request
```

It remains endpoint-agnostic:

```text
encrypted CGSS request
 -> common decode
 -> registered application handler(decoded request)
 -> endpoint data mapping
 -> common success envelope
 -> common CGSS encryption
```

Business logic is not embedded into the bootstrap HTTP server.

## Immediate continuation — UnitEdit residual state

Do not redo the A:19 route/request/response work. The next targeted questions are:

1. `main_unit_id` exact identity semantics.
   - caller gets `WorkUnitData.GetMainUnit()`;
   - an internal value is converted to an int and passed to
     `MemberUnitEditTask.SetParameter(mainUnit, ...)`;
   - determine whether this is client `unit_id`, unit slot, or another value before
     persisting it.
2. dress/costume arrays:
   - `dress_types[]`
   - `dress_2d_types[]`
   - `dress_storage_ids[]`
   They are exact request-side compatibility state, but their durable server/domain
   persistence boundary remains unresolved.
3. Prefer a separate compatibility-state store for pure wire/client persistence if
   evidence does not justify promoting these fields into semantic Unit/UnitMember.
4. After these residuals, start the next write-state slice: favorite-card or a
   Story/Commu state transition.

## Broader remaining gaps

- master.mdb semantic mappings for card/idol/item/story/music/mission/etc.;
- more durable `user_info` fields vs compatibility policy;
- startup snapshot vs shared response delta conventions;
- Unit main-selection/costume persistence;
- Story/Commu state transitions;
- Live start/end/reward transitions;
- patched-client runtime acceptance;
- actual device/UI-visible Home/features.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3`; confirm HEAD before writing.
2. Do not redo C0-C9/bootstrap protocol archaeology.
3. Treat card step/love/protect durable semantics as closed final-client evidence.
4. Treat A:29 request and `protect_card_list` response as exact; toggle algorithm
   remains inferred.
5. Treat A:19 route/request DTO and `Parse -> BaseTask.Parse` response behavior as
   exact final 11.6.3 evidence.
6. Treat A:19 unit membership persistence as closed server-side; do not claim
   `main_unit_id` or costume persistence is closed yet.
7. Preserve domain / client-ID / wire DTO / transport / master-data layer separation.
8. Reuse `server/application_http.py` for new dynamic endpoints.
9. Update this file with commit SHA + CI run after every coherent tranche.
10. Never report static/CI success as real-device or UI success.
