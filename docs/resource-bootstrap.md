# Resource bootstrap and archive preparation

CGSS separates the game client/control API from the downloadable resource plane. This allows the final resource set to be frozen and verified before the private-server API is complete.

## Current frozen target

As of September 2026, maintained community tooling identifies resource version:

```text
10133800
```

Treat this as the archival target while still verifying it against the final APK/client startup trace.

## Observed current bootstrap

The maintained resource implementation uses:

```text
CDN host:
  asset-starlight-stage.akamaized.net

manifest index:
  /dl/<resource_version>/manifests/all_dbmanifest

Android manifest payload:
  /dl/<resource_version>/manifests/Android_AHigh_SHigh
```

`all_dbmanifest` is a small comma-separated text index. The relevant entry is shaped as:

```text
Android_AHigh_SHigh,<32-hex MD5>,...
```

The MD5 covers the **compressed** Android manifest payload.

## CGSS compression wrapper

The downloaded manifest is a CGSS-wrapped raw LZ4 block:

```text
offset 0x00  4 bytes   wrapper/header data
offset 0x04  4 bytes   uncompressed size, uint32 little-endian
offset 0x08  8 bytes   wrapper/header data
offset 0x10  ...       raw LZ4 block
```

After decompression, `Android_AHigh_SHigh` is a SQLite database.

The repository implementation validates:

1. compressed-object MD5 against `all_dbmanifest`;
2. wrapper-declared output size;
3. SQLite magic;
4. `PRAGMA quick_check`.

## master.mdb

The resource manifest contains a `manifests` table. The current bootstrap retrieves the master DB object hash with the semantic equivalent of:

```sql
SELECT hash
FROM manifests
WHERE name = 'master.mdb'
LIMIT 1;
```

The compressed resource URL is then:

```text
/dl/resources/Generic/<hash[0:2]>/<hash>
```

The resource hash is again treated as the compressed object's MD5. The object is decoded with the same CGSS LZ4 wrapper and validated as SQLite.

## Repository tool

Default frozen-version fetch:

```powershell
python ./scripts/fetch-resource-bootstrap.py
```

Equivalent explicit invocation:

```powershell
python ./scripts/fetch-resource-bootstrap.py --version 10133800
```

Only acquire the manifest while testing:

```powershell
python ./scripts/fetch-resource-bootstrap.py --version 10133800 --manifest-only
```

Query the community truth-version helper instead of using the frozen default:

```powershell
python ./scripts/fetch-resource-bootstrap.py --latest
```

Generated proprietary data goes under `work/resources/` by default and is excluded from Git.

Expected outputs:

```text
work/resources/
  all_dbmanifest.txt
  manifest_10133800.db
  master.mdb
  resource-bootstrap.json
```

`resource-bootstrap.json` records URLs, compressed MD5s, decoded SHA-256s and sizes so an archive can be audited later without relying on filenames alone.

## Full archive phase

The bootstrap tool intentionally stops after the resource manifest and `master.mdb`. The next resource-preservation component should:

1. inspect the final manifest schema without assuming every historical column still exists;
2. enumerate every unique hash-addressed object;
3. classify resource categories (`AssetBundles`, `Generic`, audio, etc.);
4. derive the official CDN path for each category from current evidence;
5. download with bounded concurrency and resumable partial files;
6. verify compressed hashes before accepting objects;
7. store a content-addressed archive plus an immutable inventory/index;
8. support a `verify` mode that never touches the network;
9. later expose the same path contract from the local asset server.

Do not start the bulk archive downloader by guessing historical URL templates. First use the frozen manifest plus current resource tooling/client strings to prove each resource category's path rule.
