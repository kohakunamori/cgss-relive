"""Read-only SQLite adapter for frozen master data.

Exact CGSS master table/column names are intentionally supplied as configuration
(``MasterTableSpec``) rather than hard-coded here.  This lets reverse-engineering
evidence define the normalization map without coupling domain services to the raw
master.mdb schema.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Any, Mapping


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _identifier(value: str, field_name: str) -> str:
    if not _IDENTIFIER_RE.fullmatch(value):
        raise ValueError(f"invalid SQLite identifier for {field_name}: {value!r}")
    return value


def _quote(value: str) -> str:
    return f'"{value}"'


@dataclass(frozen=True)
class MasterTableSpec:
    """Evidence-backed mapping from one semantic master kind to one SQLite table."""

    table: str
    id_column: str
    columns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.table, "table")
        _identifier(self.id_column, "id_column")
        columns = tuple(self.columns)
        for column in columns:
            _identifier(column, "column")
        if len(set(columns)) != len(columns):
            raise ValueError("master table columns must be unique")
        object.__setattr__(self, "columns", columns)


class SQLiteMasterDataRepository:
    """Generic read-only projection over an archived SQLite master database."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        master_revision: str,
        specs: Mapping[str, MasterTableSpec],
    ) -> None:
        if not master_revision:
            raise ValueError("master_revision must be non-empty")
        normalized: dict[str, MasterTableSpec] = {}
        for kind, spec in specs.items():
            if not kind:
                raise ValueError("master semantic kind must be non-empty")
            if kind in normalized:
                raise ValueError(f"duplicate master semantic kind {kind!r}")
            normalized[kind] = spec
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._master_revision = master_revision
        self._specs = MappingProxyType(normalized)

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        master_revision: str,
        specs: Mapping[str, MasterTableSpec],
    ) -> "SQLiteMasterDataRepository":
        resolved = Path(path).expanduser().resolve()
        uri = f"{resolved.as_uri()}?mode=ro"
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        return cls(connection, master_revision=master_revision, specs=specs)

    @property
    def master_revision(self) -> str:
        return self._master_revision

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted(self._specs))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteMasterDataRepository":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def _spec(self, kind: str) -> MasterTableSpec | None:
        return self._specs.get(kind)

    def contains(self, kind: str, master_id: int) -> bool:
        spec = self._spec(kind)
        if spec is None:
            return False
        sql = (
            f"SELECT 1 FROM {_quote(spec.table)} "
            f"WHERE {_quote(spec.id_column)} = ? LIMIT 1"
        )
        return self._conn.execute(sql, (master_id,)).fetchone() is not None

    def get(self, kind: str, master_id: int) -> Mapping[str, Any] | None:
        spec = self._spec(kind)
        if spec is None:
            return None
        if spec.columns:
            select_columns = ", ".join(_quote(column) for column in spec.columns)
        else:
            select_columns = "*"
        sql = (
            f"SELECT {select_columns} FROM {_quote(spec.table)} "
            f"WHERE {_quote(spec.id_column)} = ? LIMIT 1"
        )
        row = self._conn.execute(sql, (master_id,)).fetchone()
        if row is None:
            return None
        return MappingProxyType(dict(row))
