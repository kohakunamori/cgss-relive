# Server-domain + Home integration closure — 2026-09-05

This note closes the integration of the runtime-proven original-client Home line
with the server-domain/contract-analysis line for final Android CGSS 11.6.3.

## Integrated histories

Validated merge commit before documentation cleanup:

```text
1aa2f0ad7552e5c217b41516fe599f55a6ac37b4
merge: integrate server domain with Home baseline
```

Parents:

```text
4bcd88bec203e84900c3b38ca5342cbb61cb9165  client-research-fixed
97b9fb4df8c22cb7bac65dc1cab2a511fbcd18ec  analysis/server-contracts-11.6.3
```

The merge preserves the runtime-proven bootstrap surface (signup, BN consent,
migration, load/check, load/index, resource-family selection and Home starter
contract) while adding the semantic-contract/template layer and the preservation
domain/application stack.

The only textual merge conflicts were `server/bootstrap_core.py` and
`server/http_server.py`; both were resolved as a semantic union rather than by
choosing one side.

## Domain load/index correction discovered during integration

The old server-domain tests still assumed that owned `WorkCardData` came from
`cs_gacha_data_cenere`. Real-device final-11.6.3 evidence had already proved that
owned cards are loaded through `data.user_card_list -> WorkCardData.AddCardData`.

The integrated domain adapter therefore projects durable owned cards into
`user_card_list`. `cs_gacha_data_cenere` remains Cenere metadata and is not used as
the archival owned-card list.

## Automated verification

Focused regression for the merge/domain conflict fixes:

```text
11 passed
```

Combined Windows regression excluding six known pre-existing platform-only test
files:

```text
286 passed
```

Full Windows run:

```text
295 passed, 13 failed
```

The same 13 failures reproduce on the unmerged
`client-research-fixed@4bcd88b`. They are not integration regressions: twelve are
Windows SQLite/temp-file lifetime failures (`WinError 32`) and one is a Windows
path-separator assertion in the legacy analysis-target test surface.

GitHub Actions at merge commit `1aa2f0a`:

```text
33958175647  CI                           success
33958175635  Verify final CGSS resources success
```

## Original-client cold-start regression

Device:

```text
OnePlus 8T
ADB serial b57d21c6
package jp.co.bandainamcoent.BNEI0242
version 11.6.3 / versionCode 438
```

Using the integrated server code and the existing research-only API-local /
assets-official boundary shim, the untouched client cold-started through:

```text
Scene 4 -> Scene 5 -> Scene 6
/load/index Parse return_value=1
Boot callback success
Home.Start
Home.FinishLoad (twice)
Home.StartViewProcess
```

No Scene 8 (`Asset_Download`) occurred and no CGSS exception/error signal was
observed in logcat.

Gitignored evidence:

```text
work/runtime/integration-cold-home.jsonl
work/runtime/integration-cold-home.png
work/runtime-api-integration-cold.jsonl
```

The screenshot visibly shows the CGSS Home UI. Its SHA-256 for this run is:

```text
3649bc68c5e13713ea5798860ffcbfea1f12774f813d6ec14affefea741443c0
```

This is still an API-local / official-S3-asset proof. Complete offline independence
from the official CDN remains open.

## Branch disposition

After this integration, `main` is the authoritative continuation line.

Safe superseded histories:

- `client-research-fixed`: fully contained in the integration history;
- `analysis/server-contracts-11.6.3`: fully contained in the integration history.

Safe duplicate scratch refs:

- `scratch/user-chara-literal-2`;
- `scratch/user-chara-literal-3`;
- `scratch/user-chara-literal-4`.

Those three point to the same commit, which is also an ancestor of the canonical
`scratch/user-chara-literal` branch, so deleting the duplicate refs does not lose
work.

Retain because they still contain independent unmerged commits:

- `ci/reverse-build-split-integrity`;
- `feature/runtime-triage`;
- `fix/android-sdk-ci`;
- `localization/zh-cn-complete`;
- `scratch/user-chara-literal`.

Do not delete or silently fold those retained lines without a separate review.

## Continuation rule

Do not reopen bootstrap/Home closure. Continue from `main` with the first
unsupported post-Home dependency, using the integrated domain/application layer for
durable user state and keeping runtime evidence, exact static evidence, inference,
and preservation policy explicitly separated.
