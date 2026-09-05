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
1c8a2ebbfc750982f32be3ebd3350e56afd532cf
ci: cover dynamic application HTTP routes
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
(player_id, CGSS serial_id) -> domain user_card_id
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
3. client numeric card identity stays stable.

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

Sanitized report:

```text
member-protect-response-semantics-11.6.3.json
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

The list is server-authoritative resulting protection membership for the request.
The preservation adapter emits only the protected subset of requested serials; that
is sufficient for the exact final parser and avoids claiming that production
returned a global protected-card list.

## A:29 mutation algorithm evidence

The durable field and response membership are `PROVEN_STATIC / EXACT`.

The production server's internal mutation code is unavailable. The preservation
command currently uses **toggle semantics**, marked:

```text
EvidenceStatus.PROVEN_STATIC
EvidenceKind.INFERRED
```

Reasoning/evidence:

- the network request contains only `serial_ids[]`, no desired bool;
- the final client uses the same MemberProtect action for protection state changes;
- UI helpers carry local bool state but the task strips that to serial IDs;
- response membership communicates the resulting state;
- no paired unprotect network request has been recovered;
- `ChangeProtectIcon()` derives bool state from list membership.

Do not promote toggle from `INFERRED` to `EXACT` without stronger production/runtime
evidence.

## Domain mutation commands

Exact state setter:

```text
PreservationProfileService.set_card_protection(...)
```

A:29 preservation command:

```text
PreservationProfileService.toggle_card_protection(player_id, user_card_ids)
```

Properties:

- validates all ownership before mutation;
- updates the batch in one transaction;
- returns normalized `ChangeSet`;
- duplicate IDs are rejected because duplicate-toggle semantics are unrecovered;
- empty batch is a no-op;
- resulting `is_protected` values are durable SQLite state.

Domain/identity command tests:

```text
33946293619  Test preservation domain core  success
```

## A:29 application layer

Implemented:

```text
server/application/member_protect.py
```

Flow:

```text
serial_ids[]
 -> compatibility serial -> domain card lookup
 -> validate whole batch
 -> inferred atomic toggle command
 -> read resulting HomeStateSnapshot
 -> exact protect_card_list response projection
```

Thread-safe SQLite facade:

```text
SQLiteMemberProtectHandler
```

opens short-lived domain/identity connections per HTTP request.

## Generic dynamic HTTP application extension

Implemented:

```text
server/application_http.py
server/bootstrap_core.py::process_application_request
```

It is endpoint-agnostic:

```text
encrypted CGSS request
 -> common decode
 -> registered application handler(decoded request)
 -> endpoint data mapping
 -> common success envelope
 -> common CGSS encryption
```

Unregistered routes delegate to the existing HTTP handler unchanged. Business logic
is not embedded into the bootstrap server.

## FIRST COMPLETE SERVER-SIDE WRITE LOOP — CLOSED

Integration test:

```text
tests/test_domain_application_member_protect_http.py
```

Successful workflow:

```text
33947000143  Test preservation domain core  success
```

The test uses real project CGSS body/header codecs and real HTTP sockets:

```text
/load/index
 -> serial_id=1, protect=0

POST /member/protect_card
 request data: serial_ids=[1]
 -> domain SQLite mutation
 -> response data.protect_card_list=[1]

/load/index
 -> same serial_id=1, protect=1

POST /member/protect_card again
 -> response data.protect_card_list=[]

/load/index
 -> same serial_id=1, protect=0
```

This proves the server-side chain:

```text
CGSS encrypted request
 -> exact request adapter
 -> persistent identity resolution
 -> domain command
 -> SQLite mutation
 -> exact response adapter
 -> CGSS encrypted response
 -> subsequent domain-backed load/index reflects mutation
```

It does **not** prove untouched/patched target-client acceptance yet.

## Immediate continuation

1. expose the domain-backed load/index + A:29 application handlers through a direct
   local preservation-server runner/config;
2. run the same A:29 exchange against the patched/final client when device runtime is
   ready;
3. keep the static starter-template path as differential fallback;
4. start the next write-state slice, preferably UpdateUnit, using the same pattern:

```text
exact request
 -> domain command
 -> exact/minimal response
 -> next load/index state persistence
```

5. then recover favorite-card state, Story/Commu, Live and other domains.

## Broader remaining gaps

- master.mdb semantic mappings for card/idol/item/story/music/mission/etc.;
- more durable `user_info` fields vs compatibility policy;
- startup snapshot vs shared response delta conventions;
- Unit/deck mutation semantics;
- Story/Commu state transitions;
- Live start/end/reward transitions;
- patched-client runtime acceptance;
- actual device/UI-visible Home/features.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3`; confirm HEAD before writing.
2. Do not redo C0-C9/bootstrap protocol archaeology.
3. Treat card step/love/protect durable semantics as closed final-client evidence.
4. Treat A:29 request and `protect_card_list` response as exact.
5. Treat A:29 toggle algorithm as `PROVEN_STATIC / INFERRED`, not exact.
6. Preserve domain / client-ID / wire DTO / transport / master-data layer separation.
7. Reuse `server/application_http.py` for new dynamic endpoints.
8. Update this file with commit SHA + CI run after every coherent tranche.
9. Never report static/CI success as real-device or UI success.
