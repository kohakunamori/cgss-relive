#!/usr/bin/env python3
"""Inspect a CGSS master.mdb without copying or publishing the database.

The output is intentionally small: SQLite integrity, database hash/schema counts,
and optional existence checks for explicitly requested card IDs. This is suitable
for preservation CI because proprietary database contents remain transient.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inspect_master(path: Path, *, card_ids: list[int] | None = None) -> dict[str, Any]:
    card_ids = card_ids or []
    conn = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        quick_check = [str(row[0]) for row in conn.execute("PRAGMA quick_check")]
        tables = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        report: dict[str, Any] = {
            "database": str(path),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
            "quick_check": quick_check,
            "table_count": len(tables),
            "has_card_data": "card_data" in tables,
        }

        if "card_data" in tables:
            columns = [str(row[1]) for row in conn.execute("PRAGMA table_info(card_data)")]
            report["card_data"] = {
                "columns": columns,
                "row_count": int(conn.execute("SELECT COUNT(*) FROM card_data").fetchone()[0]),
            }
            requested: list[dict[str, Any]] = []
            if card_ids:
                useful = [name for name in ("id", "name", "chara_id", "rarity", "attribute") if name in columns]
                if "id" not in useful:
                    raise ValueError("card_data exists but has no id column")
                select_sql = ", ".join(f'"{name}"' for name in useful)
                for card_id in card_ids:
                    row = conn.execute(
                        f"SELECT {select_sql} FROM card_data WHERE id=? LIMIT 1",
                        (int(card_id),),
                    ).fetchone()
                    if row is None:
                        requested.append({"id": int(card_id), "present": False})
                    else:
                        item = {name: value for name, value in zip(useful, row)}
                        item["present"] = True
                        requested.append(item)
            report["requested_cards"] = requested
        else:
            report["requested_cards"] = [
                {"id": int(card_id), "present": False} for card_id in card_ids
            ]
        return report
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect a CGSS master.mdb with a sanitized report")
    parser.add_argument("master", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--card-id", action="append", type=int, default=[])
    args = parser.parse_args()

    report = inspect_master(args.master, card_ids=args.card_id)
    text = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
