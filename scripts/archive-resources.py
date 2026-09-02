#!/usr/bin/env python3
"""Verify or download a CGSS manifest into a content-addressed local archive.

Downloads are opt-in via ``--download``.  The default mode only verifies objects
already present under the gitignored resource cache.  Every downloaded object is
MD5-checked against the manifest hash before an atomic rename.

Extension/category mappings are promoted only after current-final evidence.  In
particular, final 10133800 manifest-backed CDN probes uniquely resolve ``.awb``
and ``.bytes`` to ``Sound``. Unknown extensions remain reported and skipped.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path

CDN_BASE = "https://asset-starlight-stage.akamaized.net"
USER_AGENT = "UnityPlayer/2022.3.56f1 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)"
UNITY_VERSION = "2022.3.56f1"
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$")
CATEGORY_BY_SUFFIX = {
    ".unity3d": "AssetBundles",
    ".acb": "Sound",
    ".awb": "Sound",
    ".bytes": "Sound",
    ".usm": "Movie",
    ".bdb": "Generic",
    ".mdb": "Generic",
}


def suffix_for_name(name: str) -> str:
    lower = name.lower()
    for suffix in CATEGORY_BY_SUFFIX:
        if lower.endswith(suffix):
            return suffix
    base = name.rsplit("/", 1)[-1]
    return "<none>" if "." not in base else "." + base.rsplit(".", 1)[-1].lower()


def category_for_name(name: str) -> str | None:
    return CATEGORY_BY_SUFFIX.get(suffix_for_name(name))


def resource_path(category: str, digest: str) -> str:
    digest = digest.lower()
    return f"/dl/resources/{category}/{digest[:2]}/{digest}"


@dataclass(frozen=True)
class ObjectPlan:
    name: str
    digest: str
    category: str
    url_path: str


@dataclass(frozen=True)
class ObjectResult:
    digest: str
    name: str
    category: str | None
    status: str
    bytes: int = 0
    detail: str | None = None


def load_plan(manifest: Path) -> tuple[list[ObjectPlan], list[ObjectResult]]:
    conn = sqlite3.connect(f"file:{manifest.as_posix()}?mode=ro", uri=True)
    plans_by_hash: dict[str, ObjectPlan] = {}
    skipped: list[ObjectResult] = []
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(manifests)")}
        if not {"name", "hash"}.issubset(columns):
            raise ValueError("manifest database is missing manifests.name/hash")
        for name, digest in conn.execute("SELECT name, hash FROM manifests ORDER BY name"):
            name = str(name)
            digest = str(digest).lower()
            category = category_for_name(name)
            if not HASH_RE.fullmatch(digest):
                skipped.append(ObjectResult(digest, name, category, "invalid_hash"))
                continue
            if category is None:
                skipped.append(ObjectResult(digest, name, None, "unknown_category", detail=suffix_for_name(name)))
                continue
            plan = ObjectPlan(name, digest, category, resource_path(category, digest))
            previous = plans_by_hash.get(digest)
            if previous is None:
                plans_by_hash[digest] = plan
            elif previous.category != category:
                skipped.append(
                    ObjectResult(
                        digest,
                        name,
                        category,
                        "route_conflict",
                        detail=f"same hash also mapped via {previous.category}:{previous.name}",
                    )
                )
        return list(plans_by_hash.values()), skipped
    finally:
        conn.close()


def object_path(root: Path, digest: str) -> Path:
    return root / "objects" / digest[:2] / digest


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_one(plan: ObjectPlan, root: Path) -> ObjectResult:
    path = object_path(root, plan.digest)
    if not path.is_file():
        return ObjectResult(plan.digest, plan.name, plan.category, "missing")
    actual = md5_file(path)
    if actual != plan.digest:
        return ObjectResult(plan.digest, plan.name, plan.category, "hash_mismatch", path.stat().st_size, actual)
    return ObjectResult(plan.digest, plan.name, plan.category, "verified", path.stat().st_size)


def download_one(plan: ObjectPlan, root: Path, *, timeout: float, retries: int) -> ObjectResult:
    destination = object_path(root, plan.digest)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file():
        checked = verify_one(plan, root)
        if checked.status == "verified":
            return checked
        destination.unlink(missing_ok=True)

    request = urllib.request.Request(
        CDN_BASE + plan.url_path,
        headers={"User-Agent": USER_AGENT, "X-Unity-Version": UNITY_VERSION},
        method="GET",
    )
    last_error = ""
    for attempt in range(max(retries, 0) + 1):
        temp_path: Path | None = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=plan.digest + ".", suffix=".part", dir=destination.parent)
            os.close(fd)
            temp_path = Path(temp_name)
            md5 = hashlib.md5()
            size = 0
            with urllib.request.urlopen(request, timeout=timeout) as response, temp_path.open("wb") as output:
                if getattr(response, "status", 200) != 200:
                    raise urllib.error.HTTPError(request.full_url, response.status, "unexpected status", response.headers, None)
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    md5.update(chunk)
                    size += len(chunk)
            actual = md5.hexdigest()
            if actual != plan.digest:
                temp_path.unlink(missing_ok=True)
                return ObjectResult(plan.digest, plan.name, plan.category, "hash_mismatch", size, actual)
            os.replace(temp_path, destination)
            return ObjectResult(plan.digest, plan.name, plan.category, "downloaded", size)
        except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
    return ObjectResult(plan.digest, plan.name, plan.category, "download_error", detail=last_error)


def summarize(results: list[ObjectResult]) -> dict[str, object]:
    statuses: dict[str, int] = {}
    total_bytes = 0
    for result in results:
        statuses[result.status] = statuses.get(result.status, 0) + 1
        total_bytes += result.bytes
    return {"statuses": dict(sorted(statuses.items())), "bytes": total_bytes, "objects": len(results)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Archive CGSS resources by manifest hash")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--version", default="10133800")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--download", action="store_true", help="download missing known-category objects")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--limit", type=int, help="debug/testing: process at most N unique known objects")
    args = parser.parse_args()

    root = args.output or Path("resource-cache") / str(args.version)
    plans, pre_results = load_plan(args.manifest)
    if args.limit is not None:
        plans = plans[: max(args.limit, 0)]

    worker = (
        (lambda plan: download_one(plan, root, timeout=args.timeout, retries=args.retries))
        if args.download
        else (lambda plan: verify_one(plan, root))
    )
    results = list(pre_results)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(args.jobs, 1)) as executor:
        for result in executor.map(worker, plans):
            results.append(result)
            if result.status not in {"verified", "downloaded"}:
                print(f"{result.status}: {result.name} {result.detail or ''}".rstrip())

    root.mkdir(parents=True, exist_ok=True)
    state = {
        "version": str(args.version),
        "manifest": str(args.manifest),
        "download_mode": bool(args.download),
        "summary": summarize(results),
        "unresolved": [asdict(result) for result in results if result.status not in {"verified", "downloaded"}],
    }
    (root / "archive-state.json").write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(state["summary"], ensure_ascii=False, sort_keys=True))

    bad = {"hash_mismatch", "download_error", "route_conflict", "invalid_hash"}
    return 2 if any(result.status in bad for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
