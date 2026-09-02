# CGSS Android 11.6.3 final `ApiType` endpoint map

This document records how the supplied final endpoint-map delivery changes the
preservation-server plan. It does not copy raw credentials, sessions, packet captures,
or proprietary assets.

## Provenance

The supplied map is for:

- package `jp.co.bandainamcoent.BNEI0242`;
- app `11.6.3`;
- Unity `2022.3.56f1`;
- IL2CPP arm64.

The delivery describes two `ApiType.ApiList` static constructors reconstructed from
the final client:

- group A: 516 entries, key `0..515` fully covered;
- group B: 22 VR/login entries;
- relative-path mapping confidence: HIGH;
- per-endpoint host assignment: still a separate proof obligation.

Local source fingerprints used while importing the conclusions:

```text
protocol-map.md SHA-256 2dbb24ce6948f1b814443b2156133f37098ec5df06e640612221107559409b69
final_map.json  SHA-256 5d2655d40adaeab08ee6331a5a19f59f119809b47ee8571b23f16893a39766d5
```

`scripts/validate-api-map.py` validates a local copy of the delivered JSON without
filling missing keys or inventing endpoint records.

## Normal bootstrap/control surface

The complete A-group map proves the following six `load/` entries:

| key | enum | relative path | literal index |
| ---: | --- | --- | ---: |
| 0 | `VersionCheck` | `load/check` | 28434 |
| 1 | `SetCacheClearFlg` | `load/set_cache_clear_flg` | 28437 |
| 10 | `Title` | `load/title` | 28438 |
| 11 | `Load` | `load/index` | 28436 |
| 12 | `LoadGetExternalSiteUrl` | `load/get_external_site_url` | 28435 |
| 13 | `LoadUpdateAgreementStatus` | `load/update_agreement_status` | 28439 |

The current relive bootstrap server implements keys 0, 10 and 11. Those route
constants now live in `server/api_registry.py`, so the HTTP server no longer repeats
literal endpoint strings.

## Important Home implication

The final 516-entry A-group has no `home/index` or `home/load` endpoint. The only
`home/*` entry is:

```text
key 234 HomeCustomizeUpdate -> home/update
```

This invalidates the earlier working assumption that a separate Home-loading API must
follow `/load/index`. The stronger current hypothesis is:

```text
/load/check
/load/title
/load/index
    -> Stage.LoadTask.Parse establishes the account/Home state
    -> client transitions into Home locally
```

`home/update` should be treated as a later customization mutation unless runtime
traces prove otherwise.

This map proves endpoint availability, not execution order. A real-client trace is
still required to prove which calls occur for a particular installation/account
state.

## Path aliases

The final A-group contains seven legitimate path-alias groups; path strings are not
unique endpoint identifiers. Examples include:

- keys 81..84 -> `room/levelup`;
- exchange-shop/dress-shop aliases;
- three enum entries -> `special_campaign/load`;
- birthday load/card -> `birthday/load`;
- concert space load/polling -> `concert/room_polling`;
- two card-custom skill operations -> `card_custom/update_skill_custom`.

Future registries must therefore preserve `(group, key)` as the canonical identity
and treat path lookup as one-to-many.

## VR/login group

Group B is a distinct VR/login surface. Useful anchors include:

```text
key 0 LoginCheck -> vr/login/check
key 1 SignUp     -> vr/login/start_up
key 8 StartUp    -> vr/login/start_up
key 9 Load       -> vr/login/load
```

It must not be confused with normal A-group `load/index` bootstrap behavior.

## Host boundary

The supplied analysis confirms client literals for:

```text
apis.game.starlight-stage.jp
ext-api.game.starlight-stage.jp
storages.game.starlight-stage.jp
stream-api.starlight-stage.jp
asset-starlight-stage.akamaized.net
```

The map intentionally records relative paths only. Do not redirect all of these hosts
to one server until each endpoint family is assigned to its actual host by further
static analysis or runtime observation.
