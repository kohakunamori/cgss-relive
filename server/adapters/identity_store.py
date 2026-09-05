"""Persistent client-facing identities and compatibility-only mutable unit state.

The preservation domain deliberately uses opaque semantic IDs (for example
``card:1``). Final CGSS DTOs expose positive numeric owned-card serials and unit
IDs, plus client-facing unit costume/selection state that is useful for round-trip
compatibility but is not yet part of the semantic domain model.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from typing import Iterator, Sequence


SCHEMA_VERSION = 2


@dataclass(frozen=True)
class UnitCompatibilitySlot:
    """One final-client unit slot's three costume compatibility identifiers."""

    position: int
    dress_type: int
    dress_2d_type: int
    dress_storage_id: int

    def __post_init__(self) -> None:
        if self.position < 0:
            raise ValueError("unit compatibility slot position must be non-negative")
        for name, value in (
            ("dress_type", self.dress_type),
            ("dress_2d_type", self.dress_2d_type),
            ("dress_storage_id", self.dress_storage_id),
        ):
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


class SQLiteCompatibilityIdentityStore:
    """Stable mappings plus client-only UnitEdit round-trip state."""

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
    def transaction(self) -> Iterator[None]:
        """Group compatibility-store writes into one SQLite transaction."""

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
            with self.transaction():
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
            version = 1
        if version == 1:
            with self.transaction():
                self._conn.execute(
                    """
                    CREATE TABLE unit_compatibility_slots (
                        player_id TEXT NOT NULL,
                        domain_unit_id TEXT NOT NULL,
                        position INTEGER NOT NULL CHECK (position >= 0),
                        dress_type INTEGER NOT NULL CHECK (dress_type >= 0),
                        dress_2d_type INTEGER NOT NULL CHECK (dress_2d_type >= 0),
                        dress_storage_id INTEGER NOT NULL CHECK (dress_storage_id >= 0),
                        PRIMARY KEY (player_id, domain_unit_id, position)
                    )
                    """
                )
                self._conn.execute(
                    """
                    CREATE TABLE player_unit_preferences (
                        player_id TEXT PRIMARY KEY,
                        main_domain_unit_id TEXT
                    )
                    """
                )
                self._conn.execute("PRAGMA user_version = 2")

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
        with self.transaction():
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

    def get_domain_unit_id(self, player_id: str, client_unit_id: int) -> str | None:
        self._require_numeric_identity(player_id, client_unit_id)
        row = self._conn.execute(
            "SELECT domain_unit_id FROM unit_identity_bindings WHERE player_id = ? AND client_unit_id = ?",
            (player_id, client_unit_id),
        ).fetchone()
        return None if row is None else str(row["domain_unit_id"])

    def replace_unit_compatibility_slots(
        self,
        player_id: str,
        domain_unit_id: str,
        slots: Sequence[UnitCompatibilitySlot],
    ) -> None:
        """Replace all saved costume compatibility slots for one domain unit."""

        self._require_identity(player_id, domain_unit_id)
        materialized = tuple(slots)
        positions = [slot.position for slot in materialized]
        if len(set(positions)) != len(positions):
            raise ValueError("duplicate unit compatibility slot position")
        with self.transaction():
            self._conn.execute(
                "DELETE FROM unit_compatibility_slots WHERE player_id = ? AND domain_unit_id = ?",
                (player_id, domain_unit_id),
            )
            self._conn.executemany(
                """
                INSERT INTO unit_compatibility_slots(
                    player_id, domain_unit_id, position,
                    dress_type, dress_2d_type, dress_storage_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        player_id,
                        domain_unit_id,
                        slot.position,
                        slot.dress_type,
                        slot.dress_2d_type,
                        slot.dress_storage_id,
                    )
                    for slot in materialized
                ],
            )

    def get_unit_compatibility_slots(
        self,
        player_id: str,
        domain_unit_id: str,
    ) -> tuple[UnitCompatibilitySlot, ...]:
        self._require_identity(player_id, domain_unit_id)
        rows = self._conn.execute(
            """
            SELECT position, dress_type, dress_2d_type, dress_storage_id
            FROM unit_compatibility_slots
            WHERE player_id = ? AND domain_unit_id = ?
            ORDER BY position
            """,
            (player_id, domain_unit_id),
        ).fetchall()
        return tuple(
            UnitCompatibilitySlot(
                int(row["position"]),
                int(row["dress_type"]),
                int(row["dress_2d_type"]),
                int(row["dress_storage_id"]),
            )
            for row in rows
        )

    def set_main_unit(self, player_id: str, domain_unit_id: str | None) -> None:
        if not player_id:
            raise ValueError("player_id must be non-empty")
        if domain_unit_id is not None and not domain_unit_id:
            raise ValueError("main domain unit identity must be non-empty when present")
        with self.transaction():
            self._conn.execute(
                """
                INSERT INTO player_unit_preferences(player_id, main_domain_unit_id)
                VALUES (?, ?)
                ON CONFLICT(player_id) DO UPDATE SET main_domain_unit_id = excluded.main_domain_unit_id
                """,
                (player_id, domain_unit_id),
            )

    def get_main_unit(self, player_id: str) -> str | None:
        if not player_id:
            raise ValueError("player_id must be non-empty")
        row = self._conn.execute(
            "SELECT main_domain_unit_id FROM player_unit_preferences WHERE player_id = ?",
            (player_id,),
        ).fetchone()
        if row is None or row["main_domain_unit_id"] is None:
            return None
        return str(row["main_domain_unit_id"])
