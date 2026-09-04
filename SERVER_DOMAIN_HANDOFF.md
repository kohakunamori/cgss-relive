# SERVER DOMAIN HANDOFF — CGSS preservation server

Authoritative continuation note for the server-domain/business phase on:

```text
analysis/server-contracts-11.6.3
```

Read together with `CLIENT_CONTRACT_HANDOFF.md`, `docs/server-domain-model-v0.md`
and `docs/load-index-11.6.3.md`.

## Objective and evidence boundary

The implementation unit is now a preservation domain model, not one database/table
per HTTP endpoint.  The final client contract work remains the evidence source, but
the client may be minimally patched to remove obsolete transport/auth complexity.
Original parser/state/UI/gameplay behavior remains the compatibility target.

Keep these levels separate:

1. preservation design/policy;
2. final-client static semantic evidence;
3. runtime endpoint acceptance;
4. real-device/UI-visible success.

Everything in this handoff is level 1 plus previously recovered level-2 evidence and
CI integration tests.  It does **not** prove real-device Home success.

## Current branch state

Domain-design baseline:

```text
2a42e89af5cee120b6a67144108f96597f2319e1
```

Latest code commit at this refresh:

```text
5260cd32665957b73f6bba62c973c865b50fb772
```

Always re-read branch HEAD before writing because multiple agents may use this same
branch.

## Layering now implemented

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

Rules already enforced:

- database schema != response DTO schema;
- database schema != client `Work*` / `Savedata*` layout;
- master data stays read-only and is referenced by stable IDs;
- client-facing numeric IDs are not silently made domain primary keys;
- preservation defaults are explicit policy, not claimed production behavior;
- exact / inferred / policy evidence remains distinguishable;
- do not disable SQLite thread checks merely to make the HTTP server work.

## Domain core

### Wire-independent primitives

Files:

```text
server/domain/core.py
server/domain/providers.py
```

Includes:

- Evidence / EvidenceStatus / EvidenceKind
- Reward
- ResourceChange / EntityChange / ChangeSet
- Clock / FixedClock / SystemClock
- RandomSource / SeededRandomSource
- IdGenerator / SequentialIdGenerator

### D1 entities

`server/domain/models.py` currently contains:

- PlayerProfile
- PlayerResource
- CardOwnership
- UnitMember
- Unit
- FeatureUnlock
- HomeStateSnapshot

Only structural/minimal invariants are encoded.  No guessed CGSS max levels,
currency caps, unit-count rules or similar values belong here.

### Repository/persistence boundary

Files:

```text
server/domain/repositories.py
server/domain/persistence.py
server/domain/master_data.py
```

Mutable SQLite schema v1:

```text
schema_metadata
players
player_resources
user_cards
units
unit_members
feature_unlocks
```

Current persistence guarantees:

- master/resource revision binding;
- foreign keys enabled;
- nested transaction savepoints;
- UnitMember references an owned card from the same player;
- `get_home_snapshot()` returns a wire-independent aggregate.

`SQLiteMasterDataRepository` is configurable through evidence-backed
`MasterTableSpec`; raw CGSS master table/column names are not guessed inside the
domain package.

### Bootstrap/Home service

`server/domain/services.py` implements:

```text
PreservationProfileService.bootstrap_profile()
PreservationProfileService.get_home_snapshot()
```

Explicit preservation policy types:

- BootstrapPolicy
- StarterCardGrant
- InitialUnlock
- BootstrapResult

Bootstrap is transactional and idempotent for an explicit `player_id`.  Created
state is returned through a normalized `ChangeSet` and policy-generated fields are
marked as policy evidence.

## `/load/index` compatibility adapter

File:

```text
server/adapters/load_index.py
```

It converts:

```text
HomeStateSnapshot
    -> final 11.6.3 parser-oriented /load/index data
```

without importing CGSS wire names into `server/domain/*`.

Final-client evidence reused from `docs/load-index-11.6.3.md`:

- `cs_gacha_data_cenere` is the path that calls `WorkCardData.AddCardData`;
- its non-empty element hard-reads
  `serial_id/card_id/exp/step/love/skill_level/protect`;
- `user_card_list` remains empty because it is not the proven AddCardData path;
- `user_unit_list.unit_slot` is 1-based on the wire;
- final unit startup uses five `serial_id_0..4` positions;
- Home immediately resolves a unit card through owned-card serial;
- `user_chara_list=[]` is parser-safe and Home startup has no proven WorkCharaData
  dependency;
- completed tutorial response uses wire `tutorial_flag=100`.

Current exact semantic mappings include:

```text
PlayerProfile.name           -> user_info.name
PlayerProfile.producer_level -> user_info.level
PlayerProfile.experience     -> user_info.exp
CardOwnership.master_card_id -> cs_gacha_data_cenere[].card_id
CardOwnership.experience     -> cs_gacha_data_cenere[].exp
CardOwnership.skill_level    -> cs_gacha_data_cenere[].skill_level
Unit.slot                    -> unit_slot = slot + 1
UnitMember.position          -> serial_id_{position}
```

Still-unresolved `step/love/protect` remain `CardLoadIndexBinding` compatibility
values.  They have **not** been promoted into the domain model.

## Persistent compatibility identities

New file:

```text
server/adapters/identity_store.py
```

Commit:

```text
d0fce7036788d50465db17ee7ddf14aaba2d0712  server: persist client compatibility identities
```

`SQLiteCompatibilityIdentityStore` persists two mappings separately from game
business state:

```text
(player_id, domain user_card_id) -> positive CGSS serial_id
(player_id, domain unit_id)      -> positive CGSS unit_id
```

Properties:

- allocation is stable across server restarts;
- IDs are scoped per archival player;
- card and unit numeric namespaces are independent;
- domain opaque IDs remain the business identities;
- this is an adapter/preservation policy until stronger client semantics prove the
  numeric identities should be first-class domain fields.

Tests:

```text
tests/test_domain_compatibility_identity_store.py
```

## Application/controller layer

Files:

```text
server/application/__init__.py
server/application/load_index.py
```

Commits in this tranche include:

```text
f2fd6f71944ee2aebd68253831ed9b0eb3e92eb2  server: add preservation application layer
068d0ad20582302f622440179db8d41e068697b1  server: compose domain state into load index application data
b21f6185400d0e8adb6b7bf9d3508c1e25b08fde  server: expose dynamic domain load index mapping
b037bc1911fd67f53d448eec2c76ad66ceb0a77a  server: make SQLite load index provider thread safe
58696b07daa161efcbfe523dab3a5abe21591e73  server: export SQLite domain load index mapping
```

`DomainLoadIndexConfig` owns explicit application/compatibility policy such as
archival player/viewer identity, optional bootstrap policy, leader selection,
resource-kind mapping and still-unrecovered user-info scalar defaults.

`DomainLoadIndexController` performs:

```text
read/explicitly-bootstrap archival profile
    -> HomeStateSnapshot
    -> stable client card/unit identity bindings
    -> LoadIndexProjectionPolicy
    -> final-client /load/index data
```

A missing profile is **not** created unless `bootstrap_policy` was explicitly
provided.

## Dynamic HTTP-backed domain state

The existing `server.http_server` already accepts any `Mapping` as
`load_index_data`; therefore no special route fork was needed.

Two mapping facades exist:

```text
DynamicLoadIndexData
SQLiteDomainLoadIndexData
```

`DynamicLoadIndexData` is only safe when the controller/repositories themselves are
safe for the hosting thread model.

`SQLiteDomainLoadIndexData` is the ThreadingHTTPServer-safe path.  For each response
projection it opens short-lived SQLite domain + compatibility-identity connections
inside the worker thread, builds one coherent projection, and closes them.

This choice is intentional.  We do **not** use `check_same_thread=False` to share a
long-lived connection across HTTP workers.

### CI evidence for the thread boundary

The first HTTP integration attempt exposed the exact SQLite constraint:

```text
run 33909674000
sqlite3.ProgrammingError:
SQLite objects created in a thread can only be used in that same thread
```

That failure was preserved as useful architecture evidence rather than suppressed.

After switching to per-response connections:

```text
run 33909792669
Test preservation domain core
conclusion: success
```

The HTTP integration test now proves in CI:

1. `/load/index` is served through the real existing codec/HTTP stack;
2. first response reads stamina=100 from SQLite domain state;
3. the persisted domain DB is changed to stamina=42;
4. a second real HTTP `/load/index` response returns stamina=42;
5. the card's client `serial_id` remains stable between both responses.

This is a server integration result only.  It is not final-client runtime or Home
UI evidence.

Tests added/updated:

```text
tests/test_domain_application_load_index.py
tests/test_domain_application_http.py
tests/test_domain_compatibility_identity_store.py
```

CI workflow `.github/workflows/test-domain-core.yml` now installs
`server/requirements.txt` and covers `server/domain/**`, `server/adapters/**` and
`server/application/**`.

## Important commit trail for this phase

Earlier domain baseline:

```text
2334ea4721712ac1454af27fd42e3944881ca047  D1 domain models
3d6ed566ca19959f5ff4f46131dccebbe8b0f8a2  repository boundaries
98ebc9ffc7a134ce02cdb3d7ef6a7dc3fe63eee0  SQLite domain store
7147b61998c3c3919b30ef31dd6443053f7821fd  read-only master adapter
ce09667726a336219f8fa1b1308c83c723854026  bootstrap/Home services
55695db0cead281d3c3f80da2d95ade9ad49ac85  domain -> load/index projection
```

Latest tranche:

```text
d0fce7036788d50465db17ee7ddf14aaba2d0712  persistent compatibility identities
068d0ad20582302f622440179db8d41e068697b1  load-index application controller
71a5907440f42a52fdece7eb67a3db4e798a1641  controller tests
a5a3af7f04914e712e43f8392dd4c8f3ece5ffa8  application CI coverage
4da70b58b7ee7c12cc159c16e38cb4bec4befb77  HTTP integration dependencies
b037bc1911fd67f53d448eec2c76ad66ceb0a77a  thread-safe SQLite HTTP mapping
5260cd32665957b73f6bba62c973c865b50fb772  thread-safe HTTP integration test
```

Relevant successful runs:

```text
33908421104  domain -> /load/index adapter             success
33909482793  domain/application controller             success
33909792669  dynamic SQLite -> real HTTP /load/index   success
```

## Current unresolved semantic blockers

The architecture no longer needs numeric `serial_id` / `unit_id` semantics to be
guessed: stable compatibility identities are now isolated and persisted.

The highest-value unresolved card fields are:

```text
step
love
protect
```

Current exact final-client evidence proves only that the `cs_gacha_data_cenere`
AddCardData path hard-reads them.  It does **not yet** prove their business meaning.
Do not infer from English names alone.

Likely hypotheses such as “love = affection/bond”, “protect = lock flag”, or “step =
training/evolution stage” stay candidate/historical-reference until traced through
final-client state readers/consumers.

Other remaining gaps:

1. exact master.mdb semantic mappings for broader card/idol/item/story/music/mission
   domains;
2. additional user_info state versus compatibility-policy separation;
3. startup snapshots versus shared response deltas;
4. evidence-backed mutation commands such as SetFavoriteCard / UpdateUnit;
5. real-device acceptance of the domain-backed `/load/index` response;
6. real Home UI success.

## Immediate next work

Targeted static analysis only:

```text
cs_gacha_data_cenere field
    -> WorkCardData.CardData storage/setter
    -> reader methods
    -> direct consumers
    -> comparisons/UI/master lookups/mutation routes
    -> semantic classification
```

Specifically close `step`, `love`, and `protect`.  Promote a field into
`CardOwnership` only when final-client evidence supports durable game semantics.
Otherwise leave it in the compatibility adapter.

After those semantics are closed enough, next business commands are:

```text
SetFavoriteCard
UpdateUnit
```

Each must operate on domain state and return `ChangeSet`; endpoint DTO handling stays
in adapters.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3` and re-read HEAD before writing.
2. Read this file plus `docs/server-domain-model-v0.md` and
   `docs/load-index-11.6.3.md`.
3. Check newest `Test preservation domain core` run; current known-good dynamic HTTP
   run is `33909792669`.
4. Keep master schema mapping, domain state, client identity bindings, DTO projection
   and codec/HTTP transport separate.
5. Never map `step/love/protect` from naming intuition alone.
6. Update this handoff after each coherent tranche with exact commit/run IDs and
   evidence status.
7. Never report static/CI success as real-device/Home success.
