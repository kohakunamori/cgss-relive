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

Latest code commit before this handoff refresh:

```text
d284f1714860b331512bfaad26b4f1473deb626f
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

### Domain primitives already present before this tranche

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

Added `server/domain/models.py`:

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

`PlayerStateRepository` now exposes a transaction boundary so application/domain
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

`server/domain/master_data.py` now implements a configurable
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

Identifiers are validated before being used in SQL. This is infrastructure only;
actual mappings such as `card -> <exact master table>` still require master/client
evidence.

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

### Tests and CI

Tests now include:

```text
tests/test_domain_core.py
tests/test_domain_persistence.py
tests/test_domain_master_data.py
tests/test_domain_services.py
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
- missing Home/profile behavior.

CI workflow:

```text
.github/workflows/test-domain-core.yml
```

runs all `test_domain_*.py`.

Relevant successful runs:

```text
33907825217  D1 persistence tranche          success
33908108704  master adapter + profile service success
```

Test commits:

```text
a3ab6c3aa6fa2c93bcd40d483355f4cc78416c41  tests: cover D1 SQLite domain persistence
778734f48fa8ddd8807d2a129d38ca99b6558c5c  ci: extend domain tests through D1 persistence
30c027c2084e7a5069382e661d0f3abf20452051  tests: cover read-only master data adapter
d284f1714860b331512bfaad26b4f1473deb626f  tests: cover archival profile bootstrap service
```

## What is NOT yet recovered/implemented

Do not mistake the working server-domain skeleton for recovered CGSS data semantics.
Still missing:

1. exact `master.mdb` semantic mappings for card/idol/item/story/music/mission/etc.;
2. exact mapping from `/load/index` parser fields to domain entities;
3. exact master-ID vs user-instance-ID relations for startup/Home data;
4. exact enum/value semantics for profile/card/unit/unlock fields;
5. distinction between startup snapshot fields and shared response deltas;
6. CGSS adapter projection from `HomeStateSnapshot` / `ChangeSet` into 11.6.3 DTOs;
7. evidence-backed `SetFavoriteCard` and `UpdateUnit` command mappings;
8. runtime acceptance of the new adapter;
9. actual device/UI-visible Home success.

## Immediate next work — D1 adapter slice

The next implementation unit is now one explicit chain:

```text
/load/index evidence
    -> semantic field mapping
    -> HomeStateSnapshot / BootstrapResult
    -> CGSS 11.6.3 response adapter
    -> compatibility response
```

### Evidence questions to answer first

Use existing C9/C14/Cxx artifacts and only new targeted static analysis where needed:

1. Which `/load/index` response values populate profile state?
2. Which values identify owned card instances versus master-card definitions?
3. Which values define selected/default Units?
4. Which unlock/resource values are actually consumed before Home becomes stable?
5. Which structures are complete snapshots and which are delta/shared update objects?
6. Which values can safely be policy-generated when the patched client no longer
   requires production account/auth semantics?

Every mapping should be recorded with one of:

```text
proven-static
proven-runtime
master-data-derived
historical-reference
candidate
unresolved
```

and relationship kind:

```text
exact
inferred
policy
```

### Adapter implementation rule

Do **not** put `/load/index` response keys into `server/domain/*`.

Create/extend a separate compatibility/adapter layer that does:

```text
HomeStateSnapshot
    -> endpoint-specific response DTO/projection
    -> existing codec/transport layer
```

The domain package stays wire-independent.

## Later D1 commands

After the startup/Home projection is sufficiently mapped:

```text
SetFavoriteCard
UpdateUnit
```

should be added as domain commands returning `ChangeSet`, but only after the exact
client state/ID semantics for their corresponding routes are established.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3`.
2. Confirm HEAD; do not assume `d284f171...` is still current.
3. Read `docs/server-domain-model-v0.md` and this file.
4. Run/check the newest `Test preservation domain core` workflow before building on
   domain code.
5. Keep raw master schema mapping, domain semantics and CGSS DTO projection in
   separate layers.
6. Do not hard-code guessed CGSS enum/limit/value semantics into domain entities.
7. Record each coherent tranche here with commit SHAs, CI run IDs, evidence status
   and unresolved questions.
8. Never report static/CI success as real-device/Home success.
