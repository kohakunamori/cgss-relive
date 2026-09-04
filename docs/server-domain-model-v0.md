# CGSS Relive preservation server domain model v0

Status: **design baseline, not a claim of complete game semantics**.

This document changes the implementation unit from individual HTTP endpoints to a
small set of preservation-domain entities and commands. The final 11.6.3 client
contract inventory remains the evidence source, but the server database must not be
made isomorphic to response JSON or to client `Work*` / `Savedata*` classes.

## 1. Design goal

The preservation server should answer this question:

> What persistent game state and deterministic business operations are sufficient
> for the final CGSS client to reproduce preserved game surfaces?

The compatibility layer may simplify transport/authentication/session machinery.
The domain layer should preserve data meaning and client-visible state transitions.

Current static work already provides a strong server-facing graph:

- 538 endpoint identities;
- 284 endpoints with bound request contracts;
- 331 endpoints with bound response contracts;
- 1,358 discovered state mutations;
- 2,235 state readers;
- 7,522 state reader -> consumer relations;
- subsystem evidence covering card/idol, event, live, story/commu, gacha, room,
  live-result, shop, home, mission, profile and social surfaces.

Those numbers describe client evidence coverage, **not domain completeness**.

## 2. Layering

```text
Patched/final CGSS 11.6.3 client
              |
              v
+------------------------------------+
| CGSS compatibility/API adapter     |
| route binding / DTO / wire mapping |
+------------------+-----------------+
                   |
             Domain command/query
                   |
                   v
+------------------------------------+
| Preservation domain services       |
| invariants / transitions / rewards |
+------------------+-----------------+
                   |
          repository interfaces
                   |
                   v
+------------------------------------+
| Preservation state store           |
| SQLite initially                   |
+------------------------------------+
              |              |
              |              +------------------+
              v                                 v
       mutable user state                 immutable master data
                                           + resource catalog
```

Rules:

1. HTTP routes never own persistence rules.
2. DTO classes never become database tables merely because the client exposes them.
3. Master data is referenced by stable IDs rather than copied into mutable rows.
4. Domain operations return a normalized `ChangeSet`; the adapter decides how that
   change is projected into a specific CGSS response DTO.
5. Every uncertain semantic mapping carries an evidence status.

## 3. Data ownership classes

### 3.1 Master data

Immutable for a frozen preservation revision and normally sourced from archived
`master.mdb` / resource metadata.

Candidate master entities include:

- IdolDefinition
- CardDefinition
- SkillDefinition
- MusicDefinition
- MusicDifficultyDefinition
- StoryDefinition / CommuDefinition
- ItemDefinition
- MissionDefinition
- RoomItemDefinition
- GachaDefinition (optional preservation surface)
- EventDefinition (optional/frozen-event surface)
- RewardDefinition / reward table metadata

The preservation DB stores only references to these IDs unless a derived cache is
needed for performance.

### 3.2 User-owned persistent state

Initial aggregate groups:

```text
Player
+- Profile
+- Wallet / resource counters
+- Settings
+- CardOwnership[]
+- IdolProgress[]
+- Unit[]
+- InventoryEntry[]
+- StoryProgress[]
+- MusicProgress[]
+- MissionProgress[]
+- Present[]
+- RoomState
+- FeatureUnlock[]
+- EventProgress[]        (when preserved)
+- SocialState            (minimal/offline representation)
```

### 3.3 Ephemeral state

Not everything returned by the server belongs in durable storage.

Examples:

- LiveSession
- pending reward calculation
- transient navigation/bootstrap flags
- request idempotency record
- temporary event/minigame session
- compatibility-session metadata

Ephemeral objects may still be persisted when required for restart-safe behavior,
but they should have explicit lifetime semantics.

## 4. Initial domain entities

Field lists below are intentionally semantic and minimal. A field is added only
when client/master evidence or a preserved feature requires it.

### PlayerProfile

```text
player_id
name
producer_level
experience
created_at
last_login_at
```

Exact CGSS field names and numeric meanings remain adapter/evidence concerns.

### Wallet

Normalized counters keyed by resource kind:

```text
player_id
resource_kind
amount
```

Do not create one database column for every currency/item-like response field.
Where the client distinguishes strongly typed currencies, the adapter may expose
explicit DTO properties while the domain still uses normalized resource kinds.

### CardOwnership

```text
user_card_id
player_id
master_card_id
level
experience
bond/love-like progression
skill_level
locked
favorite
acquired_at
```

`user_card_id` and `master_card_id` must remain distinct. Unit membership should
reference the user-owned card instance where the final client semantics require an
owned instance rather than a master definition.

### IdolProgress

Stores idol-level progression that is independent of a particular owned card.
Candidate fields are introduced only after state-consumer/master lookup evidence.

### Unit / UnitMember

```text
unit_id
player_id
slot/index
name (if user-editable)

UnitMember:
unit_id
position
user_card_id
```

The exact number and semantics of unit slots belong to master/client evidence, not
to this generic schema.

### InventoryEntry

```text
player_id
master_item_id
quantity
```

Special-cased currencies should not be duplicated here unless the client/business
logic proves they behave as inventory items.

### StoryProgress

```text
player_id
master_story_id
unlock_state
read_state
first_read_at
last_read_at
```

Unlock and read semantics may collapse or expand after exact client consumers are
mapped.

### MusicProgress

```text
player_id
master_music_id
master_difficulty_id
play_count
clear_count
best_score
full_combo-like state (only when proven)
last_played_at
```

### MissionProgress

```text
player_id
master_mission_id
progress
state
claimed_at
```

The domain should support progress updates from other commands without requiring
mission-specific code inside every API adapter.

### Present

```text
present_id
player_id
reward_kind
reward_ref_id
quantity
created_at
expires_at
claimed_at
source_kind
source_ref
```

Present contents should resolve into the same normalized reward application path as
LIVE/event/mission rewards.

### RoomState

Keep Room as a separate aggregate because layout/decor state is structurally
independent from ordinary inventory.

Initial representation:

```text
player_id
room_revision
layout/document payload (normalized later)
```

Do not freeze a guessed relational room schema until Room DTO/master semantics are
mapped sufficiently.

### FeatureUnlock

A generic feature/content gate representation:

```text
player_id
unlock_kind
master_ref_id
unlocked_at
source
```

This provides a migration-safe place for client-visible unlock state while exact
specialized models are still being recovered.

### LiveSession

```text
live_session_id
player_id
master_music_id
master_difficulty_id
unit snapshot/reference
started_at
state
compatibility metadata
```

A LIVE start/end pair should eventually behave as one domain transaction sequence,
not two unrelated endpoint handlers.

## 5. Entity relation baseline

```text
Player
  |-- CardOwnership ----> CardDefinition ----> IdolDefinition
  |       |
  |       +<-- UnitMember <-- Unit
  |
  |-- IdolProgress -----> IdolDefinition
  |-- InventoryEntry ---> ItemDefinition
  |-- StoryProgress ----> StoryDefinition
  |-- MusicProgress ----> Music/DifficultyDefinition
  |-- MissionProgress --> MissionDefinition
  |-- Present ----------> normalized Reward
  |-- FeatureUnlock ----> master entity by kind/id
  |-- RoomState
  `-- LiveSession ------> Music + difficulty + unit snapshot
```

A major ongoing reverse-engineering task is to convert client field IDs into these
foreign-key relations. Until proven, relationships are tagged `candidate` rather
than enforced with guessed semantics.

## 6. Command/query model

The server should expose domain operations rather than route-shaped business code.

Candidate commands:

```text
BootstrapProfile
UpdateProfile
SetFavoriteCard
UpdateUnit
UnlockStory
MarkStoryRead
StartLive
FinishLive
ClaimPresent
ClaimMissionReward
ConsumeItem
UpdateRoom
```

Candidate queries:

```text
GetBootstrapSnapshot
GetHomeSnapshot
GetCardCollection
GetIdolProgress
GetStoryCatalogState
GetMusicCatalogState
GetRoomSnapshot
```

One CGSS endpoint may invoke multiple domain operations, and multiple CGSS endpoints
may map to the same operation.

## 7. ChangeSet

Every mutating domain command returns a normalized mutation summary.

```text
ChangeSet
+- profile_changed
+- wallet_changes[]
+- card_changes[]
+- idol_changes[]
+- inventory_changes[]
+- unit_changes[]
+- unlock_changes[]
+- story_changes[]
+- music_changes[]
+- mission_changes[]
+- present_changes[]
+- room_changes[]
+- event_changes[]
+- emitted_rewards[]
`- metadata
```

The API adapter uses this to generate endpoint-specific response updates. This is
important because the client may receive shared user-state updates as part of many
otherwise unrelated responses.

## 8. Reward normalization

Rewards should converge on one internal representation:

```text
Reward
+- kind
+- master_ref_id (nullable for currency-like rewards)
+- quantity
+- metadata
```

Then all reward-producing operations use a single application pipeline:

```text
LIVE / mission / present / event / bootstrap grant
                  |
                  v
             Reward[]
                  |
                  v
          apply_rewards()
                  |
                  v
             ChangeSet
```

This prevents reward semantics from being duplicated across route handlers.

## 9. Time, randomness and deterministic preservation policy

Domain services receive explicit providers:

```text
Clock
RandomSource
IdGenerator
```

Default preservation mode should support deterministic behavior for tests and
reproducible archival profiles. Production-era server time, random gacha outcomes,
maintenance windows and anti-abuse state are not domain requirements unless a
preserved feature specifically needs them.

## 10. Evidence model

Every reverse-engineered mapping used by generated models/adapters should be able to
carry one of:

```text
proven-static
proven-runtime
master-data-derived
historical-reference
candidate
unresolved
```

Additionally distinguish relationship type:

```text
exact       - direct parser/state/master evidence
inferred    - state-surface/consumer bridge or other conservative inference
policy      - preservation-specific behavior chosen by this project
```

No `candidate` field/value should silently become a database invariant.

## 11. Persistence baseline

Use SQLite first. Proposed logical tables, subject to evidence-driven refinement:

```text
players
player_resources
user_cards
idol_progress
units
unit_members
inventory
story_progress
music_progress
mission_progress
presents
feature_unlocks
room_state
live_sessions
compat_sessions
schema_metadata
```

Master tables stay in the archived master DB or in a read-only indexed projection.
The mutable DB should store the frozen master/resource revision in
`schema_metadata` so a profile is always tied to the data revision it was created
against.

All mutating commands should run in a transaction.

## 12. Adapter boundary

The adapter owns CGSS-specific wire/schema details:

```text
HTTP request
 -> decode/simplified compatibility transport
 -> request DTO
 -> map DTO to DomainCommand
 -> domain service
 -> ChangeSet / DomainView
 -> map to CGSS response DTO
 -> encode response
```

The adapter may preserve original field names, enum encodings, null/default behavior
and route aliases. None of those details should leak into core persistence unless
they express actual domain semantics.

## 13. First implementation slice

Do not start by implementing all 538 routes.

Phase D0 -- infrastructure

1. domain package and evidence types;
2. SQLite repository + schema versioning;
3. deterministic Clock/RandomSource/IdGenerator;
4. ChangeSet and Reward primitives;
5. master-data read interface.

Phase D1 -- archival profile/Home

1. PlayerProfile;
2. Wallet/resources;
3. CardOwnership + minimal IdolProgress;
4. Unit/UnitMember;
5. FeatureUnlock;
6. bootstrap/home query projection.

This directly targets the current Home milestone.

Phase D2 -- content browsing

1. card/idol collection;
2. story/commu state;
3. music catalog/progress;
4. room read state.

Phase D3 -- gameplay state transitions

1. StartLive / FinishLive;
2. reward application;
3. mission propagation;
4. present claiming;
5. restart/idempotency behavior.

Event/gacha/social/economy surfaces remain later bounded contexts unless client
navigation requires a minimal compatibility response earlier.

## 14. Reverse-engineering work now driven by the domain model

Future C-series analysis should answer concrete semantic questions needed by this
model rather than continue broad protocol archaeology.

Highest-value evidence queues:

1. identify master-table foreign keys for card/idol/item/story/music/mission fields;
2. recover enum/value semantics from comparisons/switches and UI consumers;
3. distinguish snapshot fields from delta/update fields;
4. map shared response update objects into ChangeSet categories;
5. recover exact state transitions for bootstrap, favorite/unit edits, story start,
   LIVE start/end, mission/present reward paths;
6. close only parser ambiguities that block one of those operations.

## 15. Explicit non-goals for v0

- reproducing production authentication or anti-cheat state;
- duplicating all historical error codes;
- implementing payment/ranking infrastructure;
- copying all response JSON into persistent blobs;
- treating endpoint count as a measure of preservation completeness;
- claiming untouched-client runtime success from static/CI evidence.

The success metric for this design is whether a small coherent state model can drive
many client routes and survive client restarts while remaining traceable to exact or
clearly labelled inferred evidence.
