# SERVER DOMAIN HANDOFF — CGSS preservation server

Authoritative continuation note for the domain-model/server-business phase on:

```text
analysis/server-contracts-11.6.3
```

This file complements `CLIENT_CONTRACT_HANDOFF.md`. The client-contract work remains
the evidence source, but implementation focus has shifted from reproducing every
production wire detail to a thin compatibility adapter plus a coherent preservation
domain model.

## Current branch state

Current implementation tranche is based on the domain-design baseline that started
at:

```text
2a42e89af5cee120b6a67144108f96597f2319e1
```

Latest code/CI commit before this handoff refresh:

```text
7f1fb9ed4a19aec69100e0b7eb2cee55883e0efa
```

Always re-read the branch HEAD before writing because another agent may continue on
the same branch.

## Current objective

Build a local CGSS preservation server whose persistent state models game meaning,
not endpoint JSON. The client may be minimally patched to remove obsolete
transport/authentication complexity, while original client parsers, state machines,
UI and gameplay consumers remain the primary compatibility target.

Current layering:

```text
CGSS 11.6.3 client
    -> compatibility/API adapter
    -> domain command/query
    -> preservation domain service
    -> PlayerStateRepository
    -> SQLite mutable state

Frozen master.mdb/resource catalog
    -> MasterDataRepository (read-only)
```

## Evidence boundary

Keep these levels separate:

1. design/preservation policy;
2. static/client-semantic evidence;
3. runtime endpoint acceptance;
4. UI-visible/device success.

The work in this handoff is level 1 plus previously recovered level-2 contract
evidence. It does **not** claim new untouched-client runtime/Home success.

D1 domain names are semantic server-design names. They are not claims that CGSS wire
DTOs use those names or exact encodings. CGSS enum/value/null/default semantics stay
in the adapter/evidence layer.

## Design reference

Read first:

```text
docs/server-domain-model-v0.md
```

Core rules already adopted:

- database schema != response schema;
- database schema != client Work*/Savedata* layout;
- master data stays read-only and referenced by stable IDs;
- mutable commands return normalized `ChangeSet`;
- preservation-selected defaults must be marked as policy;
- exact/inferred/policy evidence must remain distinguishable.

## D0/D1 work completed

### Domain primitives

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

Initial CI run:

```text
33907074260  Test preservation domain core  success
```

### D1 semantic entities

`server/domain/models.py`:

- `PlayerProfile`
- `PlayerResource`
- `CardOwnership`
- `UnitMember`
- `Unit`
- `FeatureUnlock`
- `HomeStateSnapshot`

Structural/minimal invariants only:

- non-empty identities;
- non-negative counters;
- timezone-aware timestamps;
- positive master-data references;
- unique Unit member positions;
- one Home snapshot cannot mix different players.

No guessed unit-count, max-level, stamina-cap or similar CGSS-specific limits are
encoded.

Commit:

```text
2334ea4721712ac1454af27fd42e3944881ca047  server: add D1 preservation domain models
```

### Repository boundaries

`server/domain/repositories.py` defines:

- `MasterDataRepository`
- `PlayerStateRepository`

`PlayerStateRepository` exposes a transaction boundary so domain/application
services can make multi-row mutations atomically.

Commits:

```text
3d6ed566ca19959f5ff4f46131dccebbe8b0f8a2  server: define domain repository boundaries
38f3e76ce07a60c99eaf3597b0e5ac4136f0c60a  server: expose repository transaction boundary
```

### Versioned SQLite mutable store

`server/domain/persistence.py` implements schema version `1`.

Mutable tables:

```text
schema_metadata
players
player_resources
user_cards
units
unit_members
feature_unlocks
```

Current guarantees:

- `master_revision` / `resource_revision` can be bound to the profile DB;
- conflicting revision reopen/migration is rejected;
- SQLite foreign keys are enabled;
- Unit membership references user-owned card instances;
- a Unit cannot reference another player's card;
- nested transaction usage uses savepoints;
- `get_home_snapshot()` returns a wire-independent aggregate.

Commit:

```text
98ebc9ffc7a134ce02cdb3d7ef6a7dc3fe63eee0  server: add versioned SQLite domain store
```

### Read-only master-data adapter

`server/domain/master_data.py` implements a configurable
`SQLiteMasterDataRepository`.

Important property: **no CGSS master table/column names are hard-coded**.

The adapter takes evidence-backed `MasterTableSpec` mappings:

```text
semantic kind -> raw table + id column + selected columns
```

It opens the archived SQLite DB in read-only mode and exposes only:

```text
master_revision
contains(kind, id)
get(kind, id)
```

Identifiers are validated before SQL use. Actual mappings such as
`card -> <exact master table>` still require master/client evidence.

Commit:

```text
7147b61998c3c3919b30ef31dd6443053f7821fd  server: add read-only configurable master data adapter
```

### D1 archival bootstrap / Home service

`server/domain/services.py` implements:

```text
PreservationProfileService.bootstrap_profile()
PreservationProfileService.get_home_snapshot()
```

Bootstrap behavior is provided through explicit policy objects:

- `BootstrapPolicy`
- `StarterCardGrant`
- `InitialUnlock`
- `BootstrapResult`

Properties:

- injects `Clock` and `IdGenerator`;
- can validate master references through `MasterDataRepository`;
- performs profile/resource/card/unlock creation transactionally;
- explicit `player_id` bootstrap is idempotent;
- returns normalized `ChangeSet`;
- created card/unlock changes carry `EvidenceKind.POLICY` and a note that this is
  preservation behavior, not recovered production behavior;
- no route names or CGSS wire-field names are present in the service layer.

Commits:

```text
ce09667726a336219f8fa1b1308c83c723854026  server: add archival bootstrap and Home services
a73d0de4f744d2e3b4584489f97bc1f887f428b3  server: export master adapter and D1 profile services
```

### D1 `/load/index` compatibility projection

New adapter package:

```text
server/adapters/__init__.py
server/adapters/load_index.py
```

The adapter converts:

```text
HomeStateSnapshot
    -> final-client parser-oriented /load/index data
```

without importing wire names into `server/domain/*`.

Static evidence reused from `docs/load-index-11.6.3.md`:

- `cs_gacha_data_cenere` is the proven container that calls
  `WorkCardData.AddCardData`;
- `user_card_list` stays empty in this projection;
- `user_unit_list.unit_slot` wire value is 1-based;
- final units expose five `serial_id_0..4` slots;
- Home immediately resolves a unit card through the ownership serial;
- `user_chara_list=[]` is parser-safe and current Home startup has no proven
  `WorkCharaData` requirement;
- completed tutorial response remains `tutorial_flag=100` through the existing
  parser-safe scaffold.

The domain does **not** assume that string domain IDs equal client numeric IDs.
Adapter-only bindings are explicit:

```text
CardLoadIndexBinding
    domain user_card_id -> numeric serial_id
    + still-unrecovered step/love/protect compatibility values

UnitLoadIndexBinding
    domain unit_id -> numeric CGSS unit_id
```

`LoadIndexProjectionPolicy` owns preservation/wire defaults such as viewer id,
storage caps, producer rank, compatibility scalar defaults and resource-kind to
wire-field mapping.

`project_home_snapshot_to_load_index_data()` then maps proven semantic state:

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

while requiring explicit bindings for client numeric ownership/unit identities and
unresolved card state.

Commits:

```text
0f2641dd7159fd42d033cdf054e9b0f7656b98ac  server: add compatibility adapter package
55695db0cead281d3c3f80da2d95ade9ad49ac85  server: project domain Home state into load index DTO data
2bb7e09b1e740d5d3a2404585161b1a8b069cc50  tests: cover domain to load index projection
7f1fb9ed4a19aec69100e0b7eb2cee55883e0efa  ci: cover compatibility adapters with domain tests
```

Projection CI:

```text
33908421104  Test preservation domain core  success
```

This is static/unit-test success only, not client runtime acceptance.

## Tests and CI

Tests now include:

```text
tests/test_domain_core.py
tests/test_domain_persistence.py
tests/test_domain_master_data.py
tests/test_domain_services.py
tests/test_domain_load_index_adapter.py
```

Coverage includes:

- domain primitive invariants;
- SQLite schema/revision metadata;
- persistence round-trip;
- transaction rollback;
- cross-player Unit/card rejection;
- read-only configurable master projection;
- unsafe master identifier rejection;
- deterministic bootstrap;
- bootstrap idempotency;
- master-reference validation and whole-bootstrap rollback;
- missing Home/profile behavior;
- domain profile/resource/card/unit projection into `/load/index`;
- explicit client-ID binding requirements;
- duplicate client serial rejection;
- five-slot final Unit limit at the adapter boundary.

CI workflow:

```text
.github/workflows/test-domain-core.yml
```

runs all `test_domain_*.py` and now triggers on both `server/domain/**` and
`server/adapters/**` changes.

Relevant successful runs:

```text
33907825217  D1 persistence tranche                success
33908108704  master adapter + profile service      success
33908421104  domain -> /load/index adapter         success
```

## What is NOT yet recovered/implemented

Do not mistake the working chain for complete CGSS server semantics. Still missing:

1. exact `master.mdb` semantic mappings for card/idol/item/story/music/mission/etc.;
2. exact domain meaning of card `step`, `love`, `protect` and whether `protect`
   should map to the current domain `locked` flag;
3. durable policy for mapping domain `user_card_id` / `unit_id` to stable client
   numeric IDs across restarts;
4. exact mapping for additional `/load/index` profile/resources/unlocks beyond the
   current Home-critical slice;
5. distinction between startup snapshot fields and shared response deltas;
6. integration of the new projection with the actual `/load/index` server handler;
7. evidence-backed `SetFavoriteCard` and `UpdateUnit` domain commands;
8. runtime acceptance of a response generated from domain state;
9. actual device/UI-visible Home success.

## Immediate next work

The next chain is now narrower:

```text
SQLite archival profile
    -> PreservationProfileService
    -> HomeStateSnapshot
    -> project_home_snapshot_to_load_index_data
    -> build/encode /load/index response
    -> patched 11.6.3 client runtime
```

### Next server implementation

1. Add an application/controller layer that wires `PreservationProfileService` to
   the existing `/load/index` response wrapper without pushing codec/route details
   into the domain package.
2. Define a deterministic, persisted compatibility-ID allocator or otherwise prove
   that numeric ownership/unit IDs belong in the domain model itself.
3. Replace fixed starter-profile use with domain-backed projection behind an
   explicit experimental/runtime flag first.
4. Preserve the existing static starter template as a differential fallback until
   device acceptance is proven.

### Next evidence queue

Only do targeted reverse-engineering that answers one of these blockers:

1. exact semantics of `step`, `love`, `protect`;
2. whether ownership `serial_id` is the server-domain primary identity and how it is
   generated/persisted;
3. exact semantics of `unit_id` and slot selection across save/load;
4. which remaining `user_info` scalars need durable domain state versus fixed
   compatibility policy;
5. which startup structures are snapshots versus deltas/shared updates.

Every mapping must retain evidence status:

```text
proven-static
proven-runtime
master-data-derived
historical-reference
candidate
unresolved
```

and relation kind:

```text
exact
inferred
policy
```

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3`.
2. Confirm HEAD; do not assume `7f1fb9ed...` is still current.
3. Read `docs/server-domain-model-v0.md`, `docs/load-index-11.6.3.md` and this file.
4. Check the newest `Test preservation domain core` workflow before building on the
   domain/adapter code.
5. Keep raw master schema mapping, domain semantics, CGSS DTO projection and
   codec/HTTP handling in separate layers.
6. Do not silently convert adapter compatibility fields into database invariants.
7. Record each coherent tranche here with commit SHAs, CI run IDs, evidence status
   and unresolved questions.
8. Never report static/CI success as real-device/Home success.
