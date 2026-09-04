#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sqlite3
from typing import Any

SCHEMA_VERSION = 1

USER_VISIBLE_HINTS = (
    "name",
    "title",
    "text",
    "message",
    "comment",
    "description",
    "explain",
    "detail",
    "caption",
    "summary",
    "notice",
    "flavor",
    "serif",
    "story",
    "word",
)

INTERNAL_HINTS = (
    "path",
    "url",
    "uri",
    "hash",
    "md5",
    "sha",
    "filename",
    "file_name",
    "asset",
    "bundle",
    "resource",
    "texture",
    "icon",
    "model",
    "voice",
    "sound",
    "acb",
    "awb",
)

JAPANESE_OR_CJK_RE = re.compile(
    r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uff66-\uff9f]"
)


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def has_text_affinity(declared_type: str | None) -> bool:
    normalized = (declared_type or "").upper()
    return any(token in normalized for token in ("CHAR", "CLOB", "TEXT"))


def classify_column(
    column_name: str,
    *,
    non_empty_count: int,
    japanese_like_count: int,
) -> tuple[str, list[str]]:
    name = column_name.lower()
    reasons: list[str] = []

    user_hint = next((hint for hint in USER_VISIBLE_HINTS if hint in name), None)
    internal_hint = next((hint for hint in INTERNAL_HINTS if hint in name), None)

    if user_hint:
        reasons.append(f"user-visible-name-hint:{user_hint}")
    if internal_hint:
        reasons.append(f"internal-name-hint:{internal_hint}")
    if japanese_like_count:
        reasons.append("contains-japanese-or-cjk")

    if non_empty_count == 0:
        return "empty", reasons or ["no-non-empty-values"]
    if user_hint:
        return "user-visible-candidate", reasons
    if internal_hint and japanese_like_count == 0:
        return "internal-candidate", reasons
    if japanese_like_count:
        return "user-visible-candidate", reasons
    return "review", reasons or ["text-column-without-strong-hint"]


def inspect_master_text(db_path: pathlib.Path) -> dict[str, Any]:
    db_path = pathlib.Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(db_path)

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "database": db_path.name,
        "tables": [],
    }

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as db:
        quick_check = [row[0] for row in db.execute("PRAGMA quick_check")]
        report["quick_check"] = quick_check

        tables = [
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]

        for table in tables:
            qtable = quote_identifier(table)
            columns = list(db.execute(f"PRAGMA table_info({qtable})"))
            text_columns = [
                {
                    "name": row[1],
                    "declared_type": row[2] or "",
                    "non_empty_count": 0,
                    "japanese_like_count": 0,
                    "max_length": 0,
                }
                for row in columns
                if has_text_affinity(row[2])
            ]
            if not text_columns:
                continue

            selected = ", ".join(
                quote_identifier(column["name"]) for column in text_columns
            )
            row_count = 0
            for row in db.execute(f"SELECT {selected} FROM {qtable}"):
                row_count += 1
                for index, value in enumerate(row):
                    if not isinstance(value, str) or not value:
                        continue
                    stats = text_columns[index]
                    stats["non_empty_count"] += 1
                    stats["max_length"] = max(stats["max_length"], len(value))
                    if JAPANESE_OR_CJK_RE.search(value):
                        stats["japanese_like_count"] += 1

            column_reports = []
            for stats in text_columns:
                classification, reasons = classify_column(
                    stats["name"],
                    non_empty_count=stats["non_empty_count"],
                    japanese_like_count=stats["japanese_like_count"],
                )
                column_reports.append(
                    {
                        **stats,
                        "classification": classification,
                        "reasons": reasons,
                    }
                )

            report["tables"].append(
                {
                    "table": table,
                    "row_count": row_count,
                    "text_columns": column_reports,
                }
            )

    all_columns = [
        column
        for table in report["tables"]
        for column in table["text_columns"]
    ]
    report["summary"] = {
        "table_count": len(tables),
        "tables_with_text_columns": len(report["tables"]),
        "text_column_count": len(all_columns),
        "user_visible_candidate_count": sum(
            column["classification"] == "user-visible-candidate"
            for column in all_columns
        ),
        "internal_candidate_count": sum(
            column["classification"] == "internal-candidate"
            for column in all_columns
        ),
        "review_count": sum(
            column["classification"] == "review" for column in all_columns
        ),
        "empty_count": sum(
            column["classification"] == "empty" for column in all_columns
        ),
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Inventory text-bearing columns in a local CGSS master.mdb without "
            "emitting proprietary source strings."
        )
    )
    parser.add_argument("master_db", type=pathlib.Path)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        help="Optional JSON output path. Parent directories are created.",
    )
    args = parser.parse_args()

    report = inspect_master_text(args.master_db)
    encoded = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")

    return 0 if report.get("quick_check") == ["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
