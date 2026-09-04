#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sqlite3
from typing import Any

SCHEMA_VERSION = 1
SAFE_KEY_PART_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def source_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def key_part(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str) and SAFE_KEY_PART_RE.fullmatch(value):
        return value
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256-" + hashlib.sha256(encoded).hexdigest()[:16]


def load_field_map(path: pathlib.Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise ValueError("unsupported field-map schema_version")
    tables = data.get("tables")
    if not isinstance(tables, dict) or not tables:
        raise ValueError("field map must define a non-empty tables object")
    return data


def _table_columns(db: sqlite3.Connection, table: str) -> set[str]:
    qtable = quote_identifier(table)
    return {row[1] for row in db.execute(f"PRAGMA table_info({qtable})")}


def build_catalog(
    db_path: pathlib.Path,
    field_map: dict[str, Any],
) -> dict[str, Any]:
    db_path = pathlib.Path(db_path)
    if not db_path.is_file():
        raise FileNotFoundError(db_path)

    entries: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as db:
        quick_check = [row[0] for row in db.execute("PRAGMA quick_check")]
        if quick_check != ["ok"]:
            raise ValueError(f"master database quick_check failed: {quick_check!r}")

        for table, config in sorted(field_map["tables"].items()):
            if not isinstance(config, dict):
                raise ValueError(f"{table}: table configuration must be an object")

            primary_key = config.get("primary_key")
            fields = config.get("fields")
            if (
                not isinstance(primary_key, list)
                or not primary_key
                or not all(isinstance(value, str) and value for value in primary_key)
            ):
                raise ValueError(f"{table}: primary_key must be a non-empty string list")
            if (
                not isinstance(fields, list)
                or not fields
                or not all(isinstance(value, str) and value for value in fields)
            ):
                raise ValueError(f"{table}: fields must be a non-empty string list")

            available = _table_columns(db, table)
            if not available:
                raise ValueError(f"{table}: table does not exist")
            missing = [name for name in [*primary_key, *fields] if name not in available]
            if missing:
                raise ValueError(f"{table}: missing columns: {', '.join(missing)}")

            selected_names = [*primary_key, *fields]
            selected = ", ".join(quote_identifier(name) for name in selected_names)
            qtable = quote_identifier(table)

            for row in db.execute(f"SELECT {selected} FROM {qtable}"):
                key_values = row[: len(primary_key)]
                value_offset = len(primary_key)
                pk_context = dict(zip(primary_key, key_values, strict=True))
                pk_token = "-".join(
                    f"{name}:{key_part(value)}"
                    for name, value in zip(primary_key, key_values, strict=True)
                )

                for index, field in enumerate(fields):
                    source = row[value_offset + index]
                    if source is None or source == "":
                        continue
                    if not isinstance(source, str):
                        raise ValueError(
                            f"{table}.{field}: configured localization field "
                            f"contains non-text value {type(source).__name__}"
                        )

                    entry_id = f"Master.{table}.{pk_token}.{field}"
                    if entry_id in seen_ids:
                        raise ValueError(f"duplicate translation id: {entry_id}")
                    seen_ids.add(entry_id)

                    entries.append(
                        {
                            "id": entry_id,
                            "source": source,
                            "source_sha256": source_sha256(source),
                            "context": {
                                "table": table,
                                "primary_key": pk_context,
                                "column": field,
                            },
                        }
                    )

    return {
        "schema_version": SCHEMA_VERSION,
        "database": db_path.name,
        "entry_count": len(entries),
        "entries": entries,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a local source-text catalog from explicitly reviewed "
            "master.mdb fields. Output contains proprietary source strings and "
            "must stay in a gitignored local path."
        )
    )
    parser.add_argument("master_db", type=pathlib.Path)
    parser.add_argument("field_map", type=pathlib.Path)
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        required=True,
        help="Output JSON path; use localization/catalogs/source/ or work/.",
    )
    args = parser.parse_args()

    field_map = load_field_map(args.field_map)
    catalog = build_catalog(args.master_db, field_map)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "schema_version": catalog["schema_version"],
                "database": catalog["database"],
                "entry_count": catalog["entry_count"],
                "output": str(args.output),
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
