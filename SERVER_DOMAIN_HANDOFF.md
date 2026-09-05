# SERVER DOMAIN HANDOFF — CGSS preservation server

Authoritative continuation note for the server-domain/business phase on:

```text
analysis/server-contracts-11.6.3
```

Read together with `CLIENT_CONTRACT_HANDOFF.md`, `docs/server-domain-model-v0.md`
and `docs/load-index-11.6.3.md`.

## Objective and evidence boundary

The implementation unit is a preservation domain model, not one database/table per
HTTP endpoint. The final client contract work remains the evidence source. A thin
client compatibility patch may remove obsolete transport/auth/infrastructure, while
original parser/state/UI/gameplay behavior remains the compatibility target.

Keep these levels separate:

1. preservation design/policy;
2. final-client static semantic evidence + server CI/integration tests;
3. runtime endpoint acceptance by the target client;
4. real-device/UI-visible success.

Nothing here proves a new real-device Home success.

## Current continuation point

Domain-design baseline:

```text
2a42e89af5cee120b6a67144108f96597f2319e1
```

Latest branch HEAD at this refresh:

```text
ab7d45c1c1ff3a916c1208b49d999e53d2dd4e5a
ci: trace member protect native call flow
```

Always re-read branch HEAD before writing because multiple agents may use this same
branch.

## Implemented layering

```text
CGSS 11.6.3 client
        |
        v
CGSS compatibility adapter
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

- database schema != response DTO schema;
- database schema != client `Work*` / `Savedata*` layout;
- master data stays read-only and referenced by stable IDs;
- client numeric IDs are not silently made domain primary keys;
- preservation defaults are explicit policy;
- exact / inferred / policy evidence stays distinguishable;
- do not disable SQLite thread checks just to satisfy `ThreadingHTTPServer`.

## Domain core

`server/domain/core.py` / `providers.py` provide:

- Evidence / EvidenceStatus / EvidenceKind
- Reward
- ResourceChange / EntityChange / ChangeSet
- Clock / FixedClock / SystemClock
- RandomSource / SeededRandomSource
- IdGenerator / SequentialIdGenerator

D1 semantic entities in `server/domain/models.py`:

- PlayerProfile
- PlayerResource
- CardOwnership
- UnitMember
- Unit
- FeatureUnlock
- HomeStateSnapshot

## CardOwnership semantics — final 11.6.3 proven-static

A targeted exact-specimen pass (`Analyze WorkCardData field semantics`, run
`33910221352`) closed the three previously ambiguous card fields.

Current `CardOwnership` durable card state includes:

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

Final-client evidence:

- wire `step` is stored in card `_step` and read through `get_starLessonStep()`;
- star-rank/card UI consumers use that value;
- wire `love` maps to independent card `_love` and is consumed by LoveMax / LIVE /
  gift-related logic;
- wire `protect` maps to independent `_isProtect` state;
- `CardData.SetResponseProtect(int protectFlag)` writes that protection state;
- `favorite` is independent and must not be conflated with protect.

Therefore `/load/index` now maps directly:

```text
CardOwnership.star_lesson_step -> step
CardOwnership.love             -> love
CardOwnership.is_protected     -> protect (0/1)
```

`CardLoadIndexBinding` now carries only the stable positive client `serial_id`.

## SQLite mutable state — schema v2

`server/domain/persistence.py` currently uses:

```text
SCHEMA_VERSION = 2
```

Mutable tables remain:

```text
schema_metadata
players
player_resources
user_cards
units
unit_members
feature_unlocks
```

v1 -> v2 migration:

```text
locked -> is_protected
add star_lesson_step INTEGER NOT NULL DEFAULT 0
add love             INTEGER NOT NULL DEFAULT 0
```

Migration tests prove an old v1 protected/locked card preserves the boolean state,
while newly introduced progression values default to zero.

Relevant successful domain run after the migration:

```text
33946077505  Test preservation domain core  success
```

## Persistent compatibility identities

`server/adapters/identity_store.py` persists:

```text
(player_id, domain user_card_id) -> positive CGSS serial_id
(player_id, domain unit_id)      -> positive CGSS unit_id
```

It also now provides the reverse lookup needed by mutation endpoints:

```text
(player_id, CGSS serial_id) -> domain user_card_id
```

The numeric client identity stays adapter state rather than domain PK semantics.

## Domain-backed `/load/index`

The current path is:

```text
SQLite archival profile
 -> PreservationProfileService
 -> HomeStateSnapshot
 -> stable compatibility IDs
 -> final-11.6.3 load/index adapter
 -> existing CGSS codec/HTTP stack
```

`SQLiteDomainLoadIndexData` opens short-lived SQLite connections inside each HTTP
worker thread instead of sharing one connection with `check_same_thread=False`.

CI run `33909792669` proves at server-integration level:

1. first real HTTP `/load/index` reads stamina=100 from SQLite;
2. persisted domain state changes to stamina=42;
3. second HTTP `/load/index` returns 42;
4. the client card serial remains stable between both responses.

This is not target-client runtime acceptance.

## First mutation command: card protection

`PreservationProfileService.set_card_protection(player_id, user_card_id, bool)` is
implemented and route-agnostic.

Properties:

- validates ownership;
- updates `CardOwnership.is_protected` transactionally;
- repeated assignment to the existing state is a no-op;
- returns normalized `ChangeSet`;
- mutation evidence is `PROVEN_STATIC / EXACT` for the durable card state itself;
- route/request semantics are intentionally tracked separately.

The compatibility identity store can reverse a request `serial_id` into the domain
`user_card_id`.

Tests for this command + reverse identity lookup are green:

```text
33946293619  Test preservation domain core  success
```

## Exact final endpoint: A:29 MemberProtect

Targeted exact 11.6.3 analysis closed the route and request shape:

```text
group/key : A:29
ApiType   : MemberProtect
path      : member/protect_card
task      : Stage.MemberProtectCardTask
request   : MemberProtectCardTaskParam.serial_ids : int[]
```

Exact task metadata:

```text
MemberProtectCardTask.SetParameter(int[] serialIds)
MemberProtectCardTask.Parse()
```

There is **no protect bool in the network request**. Do not bind
`set_card_protection(..., bool)` directly from request input until mutation semantics
are proven.

Related exact UI/client signatures do carry a boolean locally, e.g. callback or UI
helpers of the form:

```text
CallbackProtectFunc.Invoke(int serialId, bool flag)
ChangeListProtectCard(int serialId, bool isProtect)
```

so local UI state and network request shape must remain distinct.

## A:29 native flow evidence

Enhanced targeted workflow:

```text
run       33946353055
conclusion success
artifact  final-client-card-protect-endpoint
artifact id 9963452595
```

Sanitized reports:

```text
card-protect-endpoint-11.6.3.json
member-protect-flow-11.6.3.json
```

Direct final-client flow facts:

```text
ActionProtect(serialId)
 -> SetPeotectSerialId(...)
 -> ActionProtectCorou
 -> StartMemberProtectTask
 -> List<int>.ToArray
 -> MemberProtectCardTask.SetParameter(serialIds)
 -> NetworkManager.Connect
```

`MemberProtectCardTask.Parse()`:

- calls `BaseTask.Parse()`;
- performs multiple `LitJson.JsonData` item/count/key operations;
- resolves owned cards through `WorkCardData.GetCardDataWithSerial`;
- performs ObscuredBool conversion;
- therefore response handling is not yet proven to be empty-success.

The targeted direct-xref pass did **not** find a direct call from
`MemberProtectCardTask.Parse()` to `CardData.SetResponseProtect`. The only direct
xref to `SetResponseProtect` in that pass was from `MemberEvolutionTask.Parse()`.
This does not prove MemberProtect leaves protection untouched: it may mutate the
backing field through another path or derive/toggle state. Indirect dispatch and raw
field writes were not closed by that pass.

## Current blocker — A:29 response semantics

Do not implement the final wire handler by guessing a toggle yet.

Next exact question:

```text
MemberProtectCardTask.Parse
 -> exact response string keys
 -> response collection/object shape
 -> resulting protect value derivation
 -> direct/raw card state write or client-side toggle
```

Only after that is closed should the endpoint adapter decide between semantics such
as:

```text
serial_ids[] -> toggle each selected card
```

or

```text
serial_ids[] + server response result -> explicit resulting protection state
```

## Next implementation after response semantics close

Add a generic dynamic application-route hook to `server/http_server.py`; do not add
business logic directly into the bootstrap handler.

Target test chain:

```text
/load/index -> protect=0
POST /member/protect_card with exact encrypted request
 -> domain mutation
 -> exact/minimal proven response
/load/index -> protect=<proven resulting value>
```

If toggle semantics are proven, repeat the request and prove the second transition
back as well.

## Broader remaining work

After A:29 becomes the first complete write-state loop:

1. UpdateUnit / unit persistence command;
2. favorite-card semantics and route;
3. master.mdb semantic mappings for card/idol/item/story/music/mission;
4. additional `user_info` durable state vs compatibility-policy split;
5. startup snapshots vs shared response deltas;
6. Story/Commu and Live domain state transitions;
7. patched-client runtime acceptance;
8. actual device/UI-visible Home and feature verification.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3` and re-read HEAD.
2. Do not redo C0-C9 or bootstrap protocol research.
3. Treat `step/love/protect` as closed final-client durable card semantics.
4. Treat A:29 route/request as exact, but its response/mutation algorithm as still
   unresolved.
5. Reuse existing response-field/C5/C9 evidence before adding a new broad pass.
6. Keep domain state, client identity, endpoint DTO, codec/HTTP and master data in
   separate layers.
7. Update this handoff after each coherent tranche with exact commit/run IDs.
8. Never report CI/static success as real-device/Home success.
