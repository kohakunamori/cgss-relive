# Resource bootstrap and archive preparation

CGSS separates the game client/control API from the downloadable resource plane.
The repository therefore freezes the final resource set independently from the
private-server API work.

## Frozen target: `10133800`

The final Android application binary is version `11.6.3` and embeds the older
resource literal `10133000`. That must not be confused with the final server-side
resource revision.

The archival target is:

```text
10133800
```

This is no longer based only on maintained community tooling. The repository's
GitHub-hosted verification workflow independently executes the complete public
CDN bootstrap against `10133800` and validates every stage before deleting the
proprietary databases from the runner.

## Independently reproduced bootstrap

The verified chain is:

```text
asset-starlight-stage.akamaized.net
    ↓
/dl/10133800/manifests/all_dbmanifest
    ↓ resolve compressed MD5 for Android_AHigh_SHigh
/dl/10133800/manifests/Android_AHigh_SHigh
    ↓ MD5
CGSS 16-byte wrapper + raw LZ4
    ↓ declared size
manifest_10133800.db (SQLite + PRAGMA quick_check)
    ↓ SELECT hash FROM manifests WHERE name='master.mdb'
/dl/resources/Generic/<hash[0:2]>/<hash>
    ↓ MD5 + CGSS LZ4
master.mdb (SQLite + PRAGMA quick_check)
```

Current frozen fingerprints:

| object | fingerprint / count |
| --- | --- |
| `Android_AHigh_SHigh` compressed MD5 | `1c2969956e46cf781a374245fee0d38b` |
| `all_dbmanifest` SHA-256 | `520962136303805b0e9f0bdf5e3d471c50a00e76e7193ee59e04b65271fe731c` |
| decoded manifest SHA-256 | `8dff2f938c0221aaccabb8278acd31161eec1c9d3553a1c1231585f693f923e9` |
| manifest rows | `220837` |
| manifest unique hashes | `220803` |
| duplicate-name groups | `0` |
| duplicate-hash groups | `31` |
| `master.mdb` compressed MD5 | `b562431407563ac40435e447d630c8a4` |
| decoded `master.mdb` SHA-256 | `cccb7e91f65e8a726312c1a1545c5dc0303288ab1085e8f8d123976457ab0465` |
| master SQLite tables | `909` |
| `card_data` rows | `4314` |

The final master inspection also independently confirms these preservation
starter candidates exist:

| card id | name | chara id | attribute | rarity |
| ---: | --- | ---: | ---: | ---: |
| `100001` | 島村卯月 | `101` | `1` | `3` |
| `200001` | 渋谷凛 | `167` | `2` | `3` |
| `300001` | 本田未央 | `234` | `3` | `3` |

Only these small semantic facts and hashes are retained in reports; the CI does
not publish `master.mdb` or the resource manifest.

## Manifest schema and inventory

The final `manifests` table has the observed columns:

```text
name TEXT PRIMARY KEY
hash TEXT NOT NULL
attr INTEGER
category TEXT
size INTEGER
decrypt_key BLOB
```

The `category` column is a **delivery group**, not a CDN directory. Final counts
are:

```text
common       5175
every      215495
tutorial_g1   135
tutorial_g2    24
tutorial_g3     8
```

Do not translate these values to `AssetBundles`, `Sound`, `Movie`, or `Generic`.

Final suffix inventory:

```text
.unity3d  207694
.acb       10434
.awb         578
.bdb         825
.bytes       820
.mdb           1
.usm         485
----------------
total      220837
```

## CDN category evidence

`scripts/probe-resource-categories.py` selects real hashes from the final
`10133800` manifest and tries the four resource directories with tiny requests.
It records only HTTP status/headers and at most one response byte; resource bodies
are never persisted.

Direct final-CDN unique hits currently prove:

```text
.unity3d -> AssetBundles
.acb     -> Sound
.awb     -> Sound
.bytes   -> Sound
.usm     -> Movie
.mdb     -> Generic
```

For example, the final `.awb` sample hash uniquely returned HTTP `206` from
`Sound` while the other candidate directories returned `403`; `.bytes` behaves
the same way.

### `.bdb` evidence boundary

The archive currently maps:

```text
.bdb -> Generic
```

This mapping is supported by current maintained CGSS resource tooling. Our own
selected final CDN sample `master_aniv_count.bdb`
(`d4a8b9354ae7e190ec6a7310f8558a59`) currently returns `403` for all four
candidate directories both with `Range: bytes=0-0` and with an ordinary GET that
reads only one byte. Therefore the repository does **not** describe the `.bdb`
route as independently CDN-probed yet.

This diagnostic is intentionally non-fatal to resource freezing: the object
routing rule remains explicit and test-covered, while its direct CDN proof is
tracked separately.

## CGSS compression wrapper

Manifest and master DB payloads use the current CGSS wrapper:

```text
offset 0x00  4 bytes   wrapper/header data
offset 0x04  4 bytes   uncompressed size, uint32 little-endian
offset 0x08  8 bytes   wrapper/header data
offset 0x10  ...       raw LZ4 block
```

The repository validates:

1. compressed MD5 against the authoritative index/hash;
2. wrapper-declared output size;
3. SQLite magic;
4. `PRAGMA quick_check`.

## Repository tools

Bootstrap the frozen version locally:

```powershell
python ./scripts/fetch-resource-bootstrap.py --version 10133800
```

Inspect a final manifest without downloading its archive:

```powershell
python ./scripts/inspect-resource-manifest.py work/resources/manifest_10133800.db
```

Verify an existing local content-addressed archive without network access:

```powershell
python ./scripts/archive-resources.py work/resources/manifest_10133800.db \
  --version 10133800 \
  --output resource-cache/10133800
```

Opt into downloading missing objects:

```powershell
python ./scripts/archive-resources.py work/resources/manifest_10133800.db \
  --version 10133800 \
  --output resource-cache/10133800 \
  --download \
  --jobs 8
```

Every accepted object is stored by compressed MD5 under:

```text
resource-cache/10133800/objects/<hash[0:2]>/<hash>
```

A downloaded object is written to a temporary `.part` file, hashed, and only then
atomically renamed into the archive.

## CI preservation boundary

`.github/workflows/verify-final-resources.yml` deliberately downloads proprietary
manifest/master data only into ephemeral GitHub runner storage. Before artifact
upload it removes:

- `manifest_10133800.db`
- `master.mdb`
- `all_dbmanifest.txt`
- compressed `.lz4` files

Only sanitized JSON reports are uploaded. The resource archive itself is never
committed or attached to CI.

The same workflow constructs a complete content-addressed archive plan from the
final manifest and asserts that:

- every manifest suffix is classified;
- no invalid hash or route conflict is skipped;
- the number of planned unique objects equals the manifest's unique-hash count.

That plan check is the repository-level proof that the frozen manifest can drive
an offline missing/corrupt verification pass without contacting the production
control API.
