"""Persistent client-facing numeric identities for compatibility adapters.

The preservation domain deliberately uses opaque semantic IDs (for example
``card:1``). Final CGSS DTOs, however, expose positive numeric owned-card serials
and unit IDs. This store keeps that mapping stable across server restarts without
claiming that the client numeric identity is the domain primary-key semantics.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import sqlite3
from typing import Iterator


SCHEMA_VERSION = 1


class SQLiteCompatibilityIdentityStore:
    """Stable per-player mappings from domain IDs to CGSS numeric identifiers."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._migrate()

    @classmethod
    def open(cls, path: str | Path) -> "SQLiteCompatibilityIdentityStore":
        return cls(sqlite3.connect(str(path), isolation_level=None))

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteCompatibilityIdentityStore":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        if self._conn.in_transaction:
            yield
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK")
            raise
        else:
            self._conn.execute("COMMIT")

    def _migrate(self) -> None:
        version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"compatibility identity schema {version} is newer than supported {SCHEMA_VERSION}"
            )
        if version == 0:
            with self._transaction():
                self._conn.execute(
                    """
                    CREATE TABLE card_identity_bindings (
                        player_id TEXT NOT NULL,
                        user_card_id TEXT NOT NULL,
                        serial_id INTEGER NOT NULL CHECK (serial_id > 0),
                        PRIMARY KEY (player_id, user_card_id),
                        UNIQUE (player_id, serial_id)
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE TABLE unit_identity_bindings (
                        player_id TEXT NOT NULL,
                        domain_unit_id TEXT NOT NULL,
                        client_unit_id INTEGER NOT NULL CHECK (client_unit_id > 0),
                        PRIMARY KEY (player_id, domain_unit_id),
                        UNIQUE (player_id, client_unit_id)
                    )
                    """
                )
                self._conn.execute("PRAGMA user_version = 1")

    @staticmethod
    def _require_identity(player_id: str, domain_id: str) -> None:
        if not player_id:
            raise ValueError("player_id must be non-empty")
        if not domain_id:
            raise ValueError("domain identity must be non-empty")

    @staticmethod
    def _require_numeric_identity(player_id: str, numeric_id: int) -> None:
        if not player_id:
            raise ValueError("player_id must be non-empty")
        if numeric_id <= 0:
            raise ValueError("client numeric identity must be positive")

    def _ensure(
        self,
        *,
        table: str,
        domain_column: str,
        numeric_column: str,
        player_id: str,
        domain_id: str,
    ) -> int:
        self._require_identity(player_id, domain_id)
        with self._transaction():
            row = self._conn.execute(
                f"SELECT {numeric_column} FROM {table} WHERE player_id = ? AND {domain_column} = ?",
                (player_id, domain_id),
            ).fetchone()
            if row is not None:
                return int(row[numeric_column])

            next_row = self._conn.execute(
                f"SELECT COALESCE(MAX({numeric_column}), 0) + 1 AS next_id FROM {table} WHERE player_id = ?",
                (player_id,),
            ).fetchone()
            assert next_row is not None
            next_id = int(next_row["next_id"])
            self._conn.execute(
                f"INSERT INTO {table}(player_id, {domain_column}, {numeric_column}) VALUES (?, ?, ?)",
                (player_id, domain_id, next_id),
            )
            return next_id

    def ensure_card_serial(self, player_id: str, user_card_id: str) -> int:
        return self._ensure(
            table="card_identity_bindings",
            domain_column="user_card_id",
            numeric_column="serial_id",
            player_id=player_id,
            domain_id=user_card_id,
        )

    def ensure_unit_id(self, player_id: str, domain_unit_id: str) -> int:
        return self._ensure(
            table="unit_identity_bindings",
            domain_column="domain_unit_id",
            numeric_column="client_unit_id",
            player_id=player_id,
            domain_id=domain_unit_id,
        )

    def get_card_serial(self, player_id: str, user_card_id: str) -> int | None:
        self._require_identity(player_id, user_card_id)
        row = self._conn.execute(
            "SELECT serial_id FROM card_identity_bindings WHERE player_id = ? AND user_card_id = ?",
            (player_id, user_card_id),
        ).fetchone()
        return None if row is None else int(row["serial_id"])

    def get_user_card_id(self, player_id: str, serial_id: int) -> str | None:
        """Resolve a client-facing owned-card serial back to the domain identity."""

        self._require_numeric_identity(player_id, serial_id)
        row = self._conn.execute(
            "SELECT user_card_id FROM card_identity_bindings WHERE player_id = ? AND serial_id = ?",
            (player_id, serial_id),
        ).fetchone()
        return None if row is None else str(row["user_card_id"])

    def get_unit_id(self, player_id: str, domain_unit_id: str) -> int | None:
        self._require_identity(player_id, domain_unit_id)
        row = self._conn.execute(
            "SELECT client_unit_id FROM unit_identity_bindings WHERE player_id = ? AND domain_unit_id = ?",
            (player_id, domain_unit_id),
        ).fetchone()
        return None if row is None else int(row["client_unit_id"])
