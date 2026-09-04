# SERVER DOMAIN HANDOFF — CGSS preservation server

Authoritative continuation note for the domain-model/server-business phase on:

```text
analysis/server-contracts-11.6.3
```

This file complements `CLIENT_CONTRACT_HANDOFF.md`.  The client-contract work remains
the evidence source, but implementation focus has shifted from reproducing every
production wire detail to a thin compatibility adapter plus a coherent preservation
domain model.

## Current objective

Build a local CGSS preservation server whose persistent state models game meaning,
not endpoint JSON.  The client may be minimally patched to remove obsolete
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

Do not confuse these levels:

1. design/preservation policy;
2. static/client-semantic evidence;
3. runtime endpoint acceptance;
4. UI-visible/device success.

The work in this handoff is currently level 1 plus previously recovered level-2
contract evidence.  It does **not** claim new untouched-client runtime/Home success.

In particular, the D1 domain field names below are semantic server design names.
They are not claims that CGSS response DTOs use those names or exact encodings.
CGSS-specific enum/value/null/default semantics stay in the adapter/evidence layer.

## Baseline before this tranche

Previous HEAD:

```text
2a42e89af5cee120b6a67144108f96597f2319e1
```

Already present:

- `docs/server-domain-model-v0.md`
- `server/domain/core.py`
- `server/domain/providers.py`
- Evidence / Reward / ChangeSet primitives
- deterministic Clock / RandomSource / IdGenerator
- independent domain-core CI

The initial domain-core CI run `33907074260` completed successfully.

## Work completed in this tranche

### D1 semantic entities

Added `server/domain/models.py`:

- `PlayerProfile`
- `PlayerResource`
- `CardOwnership`
- `UnitMember`
- `Unit`
- `FeatureUnlock`
- `HomeStateSnapshot`

Important invariants currently enforced are deliberately structural/minimal:

- non-empty identities;
- non-negative counters;
- timezone-aware timestamps;
- positive master-data references;
- unique member positions within one Unit;
- Home snapshot rows must all belong to the same player.

Do not add game-specific limits (unit count, max levels, currency caps, etc.) until
backed by master/client evidence or an explicit preservation policy.

Commit:

```text
2334ea4721712ac1454af27fd42e3944881ca047  server: add D1 preservation domain models
```

### Repository boundaries

Added `server/domain/repositories.py`:

- `MasterDataRepository` — read-only `(semantic kind, master id)` access while exact
  master table schemas are still being normalized;
- `PlayerStateRepository` — mutable archival profile state independent of HTTP DTOs.

Commit:

```text
3d6ed566ca19959f5ff4f46131dccebbe8b0f8a2  server: define domain repository boundaries
```

### Versioned SQLite mutable store

Added `server/domain/persistence.py` with schema version `1` and future migration
slots.

Current mutable tables:

```text
schema_metadata
players
player_resources
user_cards
units
unit_members
feature_unlocks
```

Key design rules already encoded:

- `master_revision` / `resource_revision` can be bound to a profile database;
- reopening with a conflicting revision is rejected;
- master records are referenced by stable IDs, not copied into mutable tables;
- SQLite foreign keys are enabled;
- Unit membership references user-owned card instances;
- a Unit cannot reference a card owned by another player;
- mutating domain operations can use `transaction()`; nested use is protected by
  savepoints;
- `get_home_snapshot()` returns a wire-independent aggregate for future bootstrap /
  Home adapters.

Commit:

```text
98ebc9ffc7a134ce02cdb3d7ef6a7dc3fe63eee0  server: add versioned SQLite domain store
```

### Package exports and tests

Exports updated in `server/domain/__init__.py`.

Test coverage added in `tests/test_domain_persistence.py` for:

- schema/revision metadata;
- structural `PlayerStateRepository` conformance;
- profile/resource/card/unit/unlock round-trip;
- Home snapshot composition;
- multi-mutation rollback;
- cross-player Unit/card rejection;
- missing-player Home behavior.

CI `.github/workflows/test-domain-core.yml` now runs all `test_domain_*.py` tests.

Commits:

```text
2c5e220b6ae2f94e3814a26012ee26c46312e944  server: export D1 domain and persistence APIs
a3ab6c3aa6fa2c93bcd40d483355f4cc78416c41  tests: cover D1 SQLite domain persistence
778734f48fa8ddd8807d2a129d38ca99b6558c5c  ci: extend domain tests through D1 persistence
```

At the time this handoff note was first written, the D1 domain workflow run was:

```text
33907825217
```

Check its final conclusion before treating the D1 persistence tranche as CI-closed.

## What is intentionally NOT implemented yet

Do not mistake the schema skeleton for recovered CGSS business semantics.

Still missing:

1. a real `MasterDataRepository` implementation over archived `master.mdb`;
2. exact mapping from client/master IDs to domain references;
3. exact enum/value semantics for profile/card/unit/unlock fields;
4. `BootstrapProfile` domain service and deterministic archival-profile policy;
5. `GetHomeSnapshot` application/query service separated from repository mechanics;
6. CGSS `/load/index` / Home adapter projection into recovered client DTOs;
7. shared response-delta -> `ChangeSet` mapping;
8. runtime/device acceptance evidence for the resulting projection.

## Next implementation slice

Preferred order:

### D0 completion — master-data boundary

Implement a read-only master-data adapter without hard-coding speculative CGSS table
semantics into the domain package.  First useful capability:

```text
master revision identity
contains(kind, id)
get(kind, id)
```

A later normalization layer can map exact `master.mdb` tables/columns onto semantic
kinds as evidence improves.

### D1 service layer — archival profile/Home

Add application/domain services roughly equivalent to:

```text
BootstrapProfile
GetHomeSnapshot
SetFavoriteCard
UpdateUnit
```

Rules:

- inject `Clock` / `IdGenerator`;
- execute state mutations transactionally;
- return `ChangeSet` for mutations;
- do not expose endpoint paths or CGSS wire-field names in the service layer;
- preservation defaults must be explicitly tagged/documented as `policy` rather
  than presented as recovered production behavior.

### D1 adapter evidence queue

Use the existing client semantic DB/C-series artifacts to answer only questions that
block the first adapter:

1. Which `/load/index` values map to profile/resource/card/unit/unlock state?
2. Which returned IDs are master IDs versus user-owned instance IDs?
3. Which fields are snapshots and which are deltas/shared updates?
4. Which Home consumers actually require non-empty card/unit/unlock data?
5. What is the minimum semantically valid archival profile accepted by the patched
   11.6.3 client?

Do not resume broad C37/C38 archaeology merely to increase analysis counters.

## Agent continuation checklist

1. Fetch `analysis/server-contracts-11.6.3` and confirm HEAD before writing.
2. Read `docs/server-domain-model-v0.md` and this file.
3. Check workflow run `33907825217` (or the newest `Test preservation domain core`
   run) before assuming tests pass.
4. Keep `MasterDataRepository`, domain services and CGSS adapter separate.
5. Record every new preservation policy versus recovered semantic fact explicitly.
6. Update this handoff after each coherent implementation tranche with exact commit
   SHAs, CI run IDs and remaining evidence gaps.
7. Never report static/CI success as real-device/Home success.
