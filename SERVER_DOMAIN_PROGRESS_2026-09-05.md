# SERVER DOMAIN PROGRESS SNAPSHOT — 2026-09-05

Authoritative continuation snapshot for the active server-domain/business work on:

```text
analysis/server-contracts-11.6.3
```

This file supersedes the stale continuation point in `SERVER_DOMAIN_HANDOFF.md` for
work completed after A:19. Keep the older handoff as historical context.

## Evidence boundary

Always keep these levels separate:

1. preservation design / compatibility policy;
2. final-client static/native/parser evidence plus server CI/integration tests;
3. untouched target-client endpoint acceptance;
4. real-device/UI-visible success.

Everything recorded here is level 1/2 unless explicitly stated otherwise. Nothing
in this snapshot proves new untouched-client or UI-visible success.

## Branch checkpoint

Branch:

```text
analysis/server-contracts-11.6.3
```

Snapshot source HEAD before this documentation commit:

```text
16fcef2e26fcd7add465819a5d8c21b556a1c6e7
analysis: expose bounded story/open_v2 Parse listing
```

Relative to the previous stable handoff node:

```text
259baa554b60662f1e71b6c210ef15a10e5a0473
```

the branch was verified as:

```text
ahead:  20 commits
behind: 0 commits
```

The act of committing this snapshot advances the branch HEAD again. Re-read branch
HEAD before any subsequent write because multiple agents may use this branch.

## Closed server-side write surfaces before this snapshot

Previously closed and retained:

- A:29 `member/protect_card`
- A:19 `unit/edit`

A:19 still has the documented two-SQLite limitation: semantic-domain and
compatibility state are each internally transactional, but there is no distributed
transaction spanning both files.

## A:22 MemberFavoriteEdit — server-side loop CLOSED

Final route identity:

```text
group/key : A:22
ApiType   : MemberFavoriteEdit
path      : favorite/edit
```

New exact-final analysis surfaces added in this tranche:

```text
.github/workflows/analyze-card-favorite-endpoint.yml
.github/workflows/analyze-member-favorite-flag-encoding.yml
scripts/analyze-card-favorite-endpoint.py
scripts/analyze-member-favorite-semantics.py
scripts/analyze-member-favorite-flag-encoding.py
scripts/analyze-work-favorite-state.py
```

Implemented server layers:

```text
server/domain/card_services.py
server/adapters/member_favorite.py
server/application/member_favorite.py
server/domain_server.py
```

Tests:

```text
tests/test_domain_card_services.py
tests/test_domain_member_favorite_adapter.py
tests/test_domain_application_member_favorite_http.py
```

The preservation command is modeled as an explicit desired-state set, not a toggle.
The domain service validates the complete archival card set before mutation and
performs the semantic write in one SQLite transaction. Replay is idempotent.
Compatibility serial IDs are resolved before the domain write; an unknown serial
therefore cannot leave a partially mutated batch.

Important evidence boundary:

- `change_flags` remains a raw integer array at the wire adapter boundary;
- the client-side boolean meaning supports conversion into an explicit desired
  favorite state;
- do not promote an unsupported strict wire claim such as “only literal 0/1 is
  historically valid” unless exact final evidence establishes it.

Full tested chain:

```text
encrypted /favorite/edit
 -> compatibility serial resolution
 -> explicit favorite-state command
 -> one semantic SQLite transaction
 -> durable CardOwnership.favorite
 -> encrypted response
```

Known successful domain workflow for the closing commit:

```text
33953015651  Test preservation domain core  success
```

Closing server commit:

```text
1ce13dc55c66d740f2dec310a636a771e4a64a74
server: wire member favorite application flow
```

This is server/CI closure only, not target-client acceptance.

## A:47 StoryStart — exact-final semantics recovered; parser-safe route implemented

Final route identity:

```text
group/key : A:47
ApiType   : StoryStart
path      : story/start
```

C9 already established for endpoint 48 / `/story/start`:

```text
response fields              2
exact state mutation links   3
inferred subsystem           story/commu
```

A new bounded exact-final native pass was added:

```text
scripts/analyze-story-start-semantics.py
.github/workflows/analyze-story-start-endpoint.yml
```

Exact-final workflow:

```text
33953581085  Analyze StoryStart endpoint semantics  success
artifact      9965628466
name          final-client-story-start-endpoint
digest        sha256:8526f1884e8f657709c9bbb1b30a521c0691f833b923b84fe9e385c6aa43cd4f
```

Recovered request/parser facts:

- `StoryStartTask.SetParameter(int)` stores the supplied `story_id` into the request
  parameter;
- response parsing operates on endpoint `data`;
- the non-empty path includes `present_count` and nested temporary Story PData;
- exact state-mutating calls include:
  - `StoryTempData.ClearPData`
  - `StoryTempData.SetPData`
  - `WorkPresentData.AddPresentNumber`

The key architectural conclusion is that `/story/start` is a temporary playback
initialization surface. It must not be conflated with durable Story unlock/open
progression.

Implemented compatibility layers:

```text
server/adapters/story_start.py
server/application/story_start.py
```

The current preservation policy deliberately emits endpoint data:

```json
{}
```

because the exact parser's zero-count `data` branch clears temporary Story PData and
skips the nested PData/present-count path. This is explicitly a parser-safe
preservation compatibility response, not a captured historical production response.

Encrypted HTTP regression:

```text
tests/test_domain_application_story_start_http.py
```

It verifies:

- encrypted request/response path;
- exact integer `story_id` acceptance;
- `data={}` common-success envelope;
- string-valued or missing `story_id` is rejected rather than normalized.

Relevant server commits include:

```text
69548fbb00d4922637ed0660842cdfedee00c853  server: add parser-safe StoryStart compatibility route
483431835069bda5cc695ef7179c40d76867d1cd  tests: assert StoryStart common response envelope
```

Again, parser-safe server CI does not establish untouched-client acceptance.

## A:48 StoryReleaseEventStory / `story/open_v2` — exact-final durable progression analysis ACTIVE

This is the current preferred durable Story progression surface.

Final route identity used by the exact-final analyzer:

```text
group/key : A:48
ApiType   : StoryReleaseEventStory
path      : story/open_v2
```

New analysis surfaces:

```text
scripts/analyze-story-open-v2-semantics.py
.github/workflows/analyze-story-open-v2-endpoint.yml
```

The workflow verifies the frozen final 11.6.3 specimen hashes before analysis and
keeps raw APK/XAPK/IL2CPP/dump output outside the published artifact boundary.

The exact bounded analyzer targets only:

```text
Stage.StoryReleaseEventStoryTask.SetParameter
Stage.StoryReleaseEventStoryTask.Parse
```

and compact request-param type outlines, string literals, named direct calls and a
bounded instruction listing.

The workflow has exact assertions for request-param outline fields:

```text
story_exchange_data_id
item_id
own_num
```

and exact direct calls in `Parse`:

```text
WorkStoryData.OpenStory
WorkStoryData.AddItemOpenPrologueEventId
```

It also proves the parser references endpoint `data`.

Successful current exact-final run:

```text
33954068736  Analyze StoryOpenV2 endpoint semantics  success
artifact      9965781772
name          final-client-story-open-v2-endpoint
digest        sha256:881f406d5e89c9ffd2aa571b3f57e5513a98c551d5e2eac967e508d1a10dec0d
```

Generic CI at the same source HEAD also passed:

```text
33954068725  CI  success
```

Recent analysis commits:

```text
7f66f942bb1332c8b9ae91c9952436c7fc6c622b  analysis: trace story/open_v2 native progression semantics
16fcef2e26fcd7add465819a5d8c21b556a1c6e7  analysis: expose bounded story/open_v2 Parse listing
```

Interpretation at this point:

- `/story/start` is temporary Story playback initialization;
- `/story/open_v2` is the stronger candidate for durable Story progression because
  the exact final parser mutates `WorkStoryData` via `OpenStory` and
  `AddItemOpenPrologueEventId`;
- this interpretation is suitable for choosing the next domain slice, but the
  exact server mutation model must still be derived before persistence code is
  written.

## Files added/changed since the old A:19 handoff

The verified compare from `259baa...` to `16fcef...` includes the following main
surfaces:

```text
.github/workflows/analyze-card-favorite-endpoint.yml
.github/workflows/analyze-member-favorite-flag-encoding.yml
.github/workflows/analyze-story-start-endpoint.yml
.github/workflows/analyze-story-open-v2-endpoint.yml

scripts/analyze-card-favorite-endpoint.py
scripts/analyze-member-favorite-semantics.py
scripts/analyze-member-favorite-flag-encoding.py
scripts/analyze-work-favorite-state.py
scripts/analyze-story-start-semantics.py
scripts/analyze-story-open-v2-semantics.py

server/domain/card_services.py
server/adapters/member_favorite.py
server/application/member_favorite.py
server/adapters/story_start.py
server/application/story_start.py
server/domain_server.py

tests/test_domain_card_services.py
tests/test_domain_member_favorite_adapter.py
tests/test_domain_application_member_favorite_http.py
tests/test_domain_application_story_start_http.py
```

`SERVER_DOMAIN_HANDOFF.md` itself also changed during this span but its immediate
continuation text still trails the actual branch state. Use this snapshot first for
post-A:19 continuation.

## Immediate continuation

Do not redo A:19 UnitEdit, A:22 Favorite, or StoryStart route archaeology.

Continue from `story/open_v2` in this order:

1. consume the successful exact-final `story/open_v2` artifact;
2. map `StoryReleaseEventStoryTaskParam` fields and exact `SetParameter` caller
   semantics into a wire adapter without inventing validation rules;
3. recover the response `data` shape and the exact values/conditions feeding
   `WorkStoryData.OpenStory` and `AddItemOpenPrologueEventId`;
4. define a durable Story progression domain model only after those identities are
   known;
5. add one semantic SQLite transaction for the durable progression change;
6. expose the endpoint through the generic application transport;
7. add encrypted HTTP -> SQLite -> reopen/readback regression;
8. only then move to adjacent Story finish/read/Commu surfaces;
9. proceed to Live start/end/reward transitions after Story progression is coherent.

## Non-negotiable reporting rules

- Do not report a green analyzer as server endpoint closure.
- Do not report a green server test as untouched-client acceptance.
- Do not report untouched-client acceptance as visible UI success without device
  evidence.
- Keep compatibility IDs/policy separate from archival domain identity.
- Preserve exact vs inferred vs preservation-policy provenance in code/tests/docs.
- Re-read branch HEAD immediately before each write; never force-update over a
  concurrent agent.
