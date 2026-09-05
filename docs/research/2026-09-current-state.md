# Current-state research notes — 2026-09-05

This file is the short authoritative status summary. For continuation details, read
`AGENT_HANDOFF.md` first.

## Workspace / execution

- Authoritative worktree: `D:\Project\cgss-relive`.
- Active research branch: `client-research-fixed`.
- Host/device operations use AgentDock. WebCodex is retired.
- Real-device target: OnePlus 8T, ADB serial `b57d21c6`.
- Do not touch unrelated ADB/emulator endpoints.

## Exact final Android specimen — verified

```text
package          jp.co.bandainamcoent.BNEI0242
app version      11.6.3
versionCode      438
Unity            2022.3.56f1
runtime          IL2CPP
metadata version 31
```

Frozen specimen hashes are recorded in `AGENT_HANDOFF.md` and the exact-analysis
workflow. Do not commit the XAPK, native binaries, metadata, resource databases,
or raw sensitive captures.

## Protocol — verified

```text
JSON
 -> MessagePack
 -> Base64
 -> AES-256-CBC
 -> Base64(cipher || dynamic 32-byte key)
IV = UDID-derived 16 bytes
```

Bootstrap/login/migration/load contracts are implemented in the clean-room server.
Do not re-open crypto or already-closed parser requirements without contradictory
runtime evidence.

## Frozen resource revision — verified

```text
binary/default RES_VER 10133000
final resource revision 10133800
manifest rows          220837
unique hashes          220803
master tables          909
card_data rows          4314
```

The native `/load/check` 214 transition to `10133800` has already been proven on
the original client and must not be bypassed in preservation mode.

## `/load/index` starter/Home contract — verified

The final runtime-proven starter state uses:

- `user_card_list` as the owned-card `WorkCardData.AddCardData` source;
- one owned card with `serial_id=1`;
- `user_info.leader_serial_id=1`;
- `user_info.unit_slot=1`;
- one 1-based `user_unit_list` row pointing slot 0 to serial 1;
- `cs_gacha_data_cenere={"cenere_id":1}` plus release flag
  `cenere_update_2023_start_time=1`;
- minimal `loading_tips_info` with empty possession data and zero loading count;
- `user_chara_list=[]` until a real consumer proves otherwise.

## HOME runtime closure — verified 2026-09-05

The original untouched Android 11.6.3 client completed its first-time 4927-item
Asset Download and naturally executed:

```text
AssetDownload.FinishLoadCommonData
 -> AssetDownload.FinishLoadStandardData
 -> SceneManager.ChangeView(6, is_force=false)
 -> Stage.Home.Start
 -> Stage.Home.FinishLoad
 -> Stage.Home.StartViewProcess
```

No scene, parser return, result code, verifier result, or callback was forced.
No exception/error event was observed after Home entry.

A subsequent cold start produced the scene sequence:

```text
4 -> 5 -> 6
```

with no `8` (Asset_Download), then repeated the same Home lifecycle. This proves
the first-time predownload state persisted and Home is reproducibly reachable.

Important scope note: this successful closure used the local compatibility API
plane while `/load/check` selected the S3/CDN resource family and the bulk asset
plane went to the official CDN. Therefore this proves **original-client bootstrap
and Home acceptance**, not yet complete offline independence from the official
asset CDN.

Gitignored evidence:

```text
work/runtime/home-official-assets-s3-clean.jsonl
work/runtime/asset-download-completion-live.jsonl
work/runtime/cgss-home-after-download.png
work/runtime/home-cold-after-download.jsonl
work/runtime/cgss-home-cold-verified.png
work/runtime-api-home-cold-after-download.jsonl
```

## Current next target

Bootstrap/Home is no longer the active blocker. Continue one blocker at a time:

1. observe the first unsupported post-Home API/local-state dependency from a
   natural Home interaction or scheduled Home task;
2. prove its exact parser/consumer behavior in the final specimen;
3. implement only the minimum clean-room server/state contract needed;
4. add focused tests and rerun the original client;
5. separately close full offline resource delivery so preserved operation no
   longer depends on the official asset CDN.

Never turn research-only Frida hooks into final preservation behavior, and never
force Home, parser success, verifier success, or arbitrary result codes.
