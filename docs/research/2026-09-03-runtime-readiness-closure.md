# 2026-09-03 deterministic runtime-readiness closure

This note marks the point where high-value static/server-side bootstrap preparation
for the untouched final Android 11.6.3 client is intentionally close to
exhaustion. It is not a runtime-success claim.

## Final resource filename resolution

The frozen 10133800 manifest contains path-shaped names and basename collisions:

```text
rows                          220837
names containing '/'           12317
unique basenames              220652
basename collision groups        137
basename hash-conflict groups    130
```

`server.resource_server` therefore performs exact longest-relative-suffix lookup
against normalized `manifests.name`; it does not synthesize basename aliases.

The real final DB has been run through
`scripts/verify-final-manifest-resolution.py`:

```text
resolved          220837
unresolved             0
mismatched             0
unknown category        0
```

Category row totals:

```text
AssetBundles 207694
Sound         11832
Generic         826
Movie           485
```

## Fast resource preflight

`preflight-local-resources.py` schema 3 now validates:

```text
manifest DB integrity/counts
all unique object paths present/non-zero
all_dbmanifest -> Android_AHigh_SHigh compressed MD5
CGSS wrapper/LZ4 decode
wire-decoded SQLite == supplied manifest DB
master.mdb object actual MD5 == final manifest hash
```

Only aggregate/boolean evidence is emitted.

## Optional full archive audit

`scripts/audit-local-resource-objects.py` is the heavyweight integrity tier. It
computes actual MD5 for each unique manifest object and reports only aggregate
counts. It is intended after copying/storage incidents or before archival
milestones, not every rooted-device iteration.

## Host TLS readiness

`scripts/run-rooted-local-stack.py` now verifies before readiness:

```text
resource preflight schema 3
API backend health
resource backend health
TLS mux startup
API original hostname CA-chain + SAN/SNI + Host routing
storages original hostname CA-chain + SAN/SNI + Host routing
```

The local readiness TLS probe connects to loopback but verifies each exact
original hostname using the generated local CA. Wrong leaf/CA/missing SAN can no
longer produce a false host-side ready state.

## Device-side read-only gate

`prepare-device-tunnel.ps1` now defaults to host mux port 8445.

`check-rooted-device.ps1` performs no system mutation and checks the core device
conditions:

```text
ADB ready
root available
final package installed
versionName 11.6.3
versionCode 438
reverse tcp:443 -> tcp:8445
API hostname loopback mapping
storages hostname loopback mapping
```

Exact local CA bytes in common Android system directories are inspected only as
advisory evidence; root-manager certificate representation can differ.

CI parses all PowerShell helpers through the PowerShell AST parser without
executing ADB.

## Still not proven

None of the work above proves original-client acceptance. The decisive next
milestone still requires actual rooted-device runtime evidence:

```text
untouched 11.6.3 TLS acceptance
 -> /load/check 214
 -> resource-plane requests
 -> /load/index
 -> visible Home/Login Bonus -> Home
```

Only after that should the first unsupported post-Home endpoint/state be restored.
