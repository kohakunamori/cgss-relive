"""Versioned SQLite persistence for the preservation domain.

The mutable database stores only archival user state and revision metadata.  Frozen
CGSS master data remains behind ``MasterDataRepository`` and is not copied into
these tables.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Iterator

from .models import (
    CardOwnership,
    FeatureUnlock,
    HomeStateSnapshot,
    PlayerProfile,
    PlayerResource,
    Unit,
    UnitMember,
)


SCHEMA_VERSION = 1

_MIGRATION_1 = (
    """
    CREATE TABLE schema_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE players (
        player_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        producer_level INTEGER NOT NULL CHECK (producer_level >= 1),
        experience INTEGER NOT NULL CHECK (experience >= 0),
        created_at TEXT NOT NULL,
        last_login_at TEXT
    )
    """,
    """
    CREATE TABLE player_resources (
        player_id TEXT NOT NULL,
        resource_kind TEXT NOT NULL,
        amount INTEGER NOT NULL CHECK (amount >= 0),
        PRIMARY KEY (player_id, resource_kind),
        FOREIGN KEY (player_id) REFERENCES players(player_id) ON DELETE CASCADE
    )
    """,
    """
    CREATE TABLE user_cards (
        user_card_id TEXT PRIMARY KEY,
        player_id TEXT NOT NULL,
        master_card_id INTEGER NOT NULL CHECK (master_card_id > 0),
        level INTEGER NOT NULL CHECK (level >= 1),
        experience INTEGER NOT NULL CHECK (experience >= 0),
        skill_level INTEGER NOT NULL CHECK (skill_level >= 0),
        locked INTEGER NOT NULL CHECK (locked IN (0, 1)),
        favorite INTEGER NOT NULL CHECK (favorite IN (0, 1)),
        acquired_at TEXT NOT NULL,
        FOREIGN KEY (player_id) REFERENCES players(player_id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX user_cards_player_idx ON user_cards(player_id, user_card_id)",
    """
    CREATE TABLE units (
        unit_id TEXT PRIMARY KEY,
        player_id TEXT NOT NULL,
        slot INTEGER NOT NULL CHECK (slot >= 0),
        name TEXT,
        FOREIGN KEY (player_id) REFERENCES players(player_id) ON DELETE CASCADE
    )
    """,
    "CREATE INDEX units_player_idx ON units(player_id, slot, unit_id)",
    """
    CREATE TABLE unit_members (
        unit_id TEXT NOT NULL,
        position INTEGER NOT NULL CHECK (position >= 0),
        user_card_id TEXT NOT NULL,
        PRIMARY KEY (unit_id, position),
        FOREIGN KEY (unit_id) REFERENCES units(unit_id) ON DELETE CASCADE,
        FOREIGN KEY (user_card_id) REFERENCES user_cards(user_card_id) ON DELETE RESTRICT
    )
    """,
    """
    CREATE TABLE feature_unlocks (
        player_id TEXT NOT NULL,
        unlock_kind TEXT NOT NULL,
        master_ref_id INTEGER NOT NULL CHECK (master_ref_id > 0),
        unlocked_at TEXT NOT NULL,
        source TEXT,
        PRIMARY KEY (player_id, unlock_kind, master_ref_id),
        FOREIGN KEY (player_id) REFERENCES players(player_id) ON DELETE CASCADE
    )
    """,
)

_MIGRATIONS: dict[int, tuple[str, ...]] = {1: _MIGRATION_1}


def _encode_time(value: datetime | None) -> str | None:
    return None if value is None else value.isoformat()


def _decode_time(value: str | None) -> datetime | None:
    return None if value is None else datetime.fromisoformat(value)


class SQLiteDomainStore:
    """SQLite implementation of the initial ``PlayerStateRepository`` surface."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._conn = connection
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._savepoint_counter = 0

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        master_revision: str | None = None,
        resource_revision: str | None = None,
    ) -> "SQLiteDomainStore":
        connection = sqlite3.connect(str(path), isolation_level=None)
        store = cls(connection)
        store.migrate(
            master_revision=master_revision,
            resource_revision=resource_revision,
        )
        return store

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "SQLiteDomainStore":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run a domain operation atomically, supporting nested savepoints."""

        if not self._conn.in_transaction:
            self._conn.execute("BEGIN")
            try:
                yield
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")
            return

        self._savepoint_counter += 1
        name = f"domain_sp_{self._savepoint_counter}"
        self._conn.execute(f"SAVEPOINT {name}")
        try:
            yield
        except BaseException:
            self._conn.execute(f"ROLLBACK TO {name}")
            self._conn.execute(f"RELEASE {name}")
            raise
        else:
            self._conn.execute(f"RELEASE {name}")

    @property
    def schema_version(self) -> int:
        row = self._conn.execute("PRAGMA user_version").fetchone()
        return int(row[0])

    def get_metadata(self, key: str) -> str | None:
        if self.schema_version == 0:
            return None
        row = self._conn.execute(
            "SELECT value FROM schema_metadata WHERE key = ?",
            (key,),
        ).fetchone()
        return None if row is None else str(row["value"])

    def _set_metadata(self, key: str, value: str) -> None:
        self._conn.execute(
            """
            INSERT INTO schema_metadata(key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )

    def _bind_revision(self, key: str, value: str | None) -> None:
        if value is None:
            return
        existing = self.get_metadata(key)
        if existing is None:
            self._set_metadata(key, value)
        elif existing != value:
            raise ValueError(
                f"database {key} mismatch: stored={existing!r}, requested={value!r}"
            )

    def migrate(
        self,
        *,
        master_revision: str | None = None,
        resource_revision: str | None = None,
    ) -> None:
        current = self.schema_version
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema {current} is newer than supported {SCHEMA_VERSION}"
            )

        for version in range(current + 1, SCHEMA_VERSION + 1):
            statements = _MIGRATIONS.get(version)
            if statements is None:
                raise RuntimeError(f"missing migration for schema version {version}")
            with self.transaction():
                for statement in statements:
                    self._conn.execute(statement)
                self._conn.execute(f"PRAGMA user_version = {version}")
                self._set_metadata("schema_version", str(version))

        with self.transaction():
            self._set_metadata("schema_version", str(SCHEMA_VERSION))
            self._bind_revision("master_revision", master_revision)
            self._bind_revision("resource_revision", resource_revision)

    def save_profile(self, profile: PlayerProfile) -> None:
        self._conn.execute(
            """
            INSERT INTO players(
                player_id, name, producer_level, experience, created_at, last_login_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(player_id) DO UPDATE SET
                name = excluded.name,
                producer_level = excluded.producer_level,
                experience = excluded.experience,
                created_at = excluded.created_at,
                last_login_at = excluded.last_login_at
            """,
            (
                profile.player_id,
                profile.name,
                profile.producer_level,
                profile.experience,
                _encode_time(profile.created_at),
                _encode_time(profile.last_login_at),
            ),
        )

    def get_profile(self, player_id: str) -> PlayerProfile | None:
        row = self._conn.execute(
            "SELECT * FROM players WHERE player_id = ?",
            (player_id,),
        ).fetchone()
        if row is None:
            return None
        created_at = _decode_time(row["created_at"])
        assert created_at is not None
        return PlayerProfile(
            player_id=str(row["player_id"]),
            name=str(row["name"]),
            producer_level=int(row["producer_level"]),
            experience=int(row["experience"]),
            created_at=created_at,
            last_login_at=_decode_time(row["last_login_at"]),
        )

    def set_resource(self, resource: PlayerResource) -> None:
        self._conn.execute(
            """
            INSERT INTO player_resources(player_id, resource_kind, amount)
            VALUES (?, ?, ?)
            ON CONFLICT(player_id, resource_kind) DO UPDATE SET amount = excluded.amount
            """,
            (resource.player_id, resource.resource_kind, resource.amount),
        )

    def list_resources(self, player_id: str) -> tuple[PlayerResource, ...]:
        rows = self._conn.execute(
            """
            SELECT player_id, resource_kind, amount
            FROM player_resources
            WHERE player_id = ?
            ORDER BY resource_kind
            """,
            (player_id,),
        ).fetchall()
        return tuple(
            PlayerResource(str(row["player_id"]), str(row["resource_kind"]), int(row["amount"]))
            for row in rows
        )

    def save_card(self, card: CardOwnership) -> None:
        self._conn.execute(
            """
            INSERT INTO user_cards(
                user_card_id, player_id, master_card_id, level, experience,
                skill_level, locked, favorite, acquired_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_card_id) DO UPDATE SET
                player_id = excluded.player_id,
                master_card_id = excluded.master_card_id,
                level = excluded.level,
                experience = excluded.experience,
                skill_level = excluded.skill_level,
                locked = excluded.locked,
                favorite = excluded.favorite,
                acquired_at = excluded.acquired_at
            """,
            (
                card.user_card_id,
                card.player_id,
                card.master_card_id,
                card.level,
                card.experience,
                card.skill_level,
                int(card.locked),
                int(card.favorite),
                _encode_time(card.acquired_at),
            ),
        )

    def list_cards(self, player_id: str) -> tuple[CardOwnership, ...]:
        rows = self._conn.execute(
            "SELECT * FROM user_cards WHERE player_id = ? ORDER BY user_card_id",
            (player_id,),
        ).fetchall()
        cards: list[CardOwnership] = []
        for row in rows:
            acquired_at = _decode_time(row["acquired_at"])
            assert acquired_at is not None
            cards.append(
                CardOwnership(
                    user_card_id=str(row["user_card_id"]),
                    player_id=str(row["player_id"]),
                    master_card_id=int(row["master_card_id"]),
                    level=int(row["level"]),
                    experience=int(row["experience"]),
                    skill_level=int(row["skill_level"]),
                    locked=bool(row["locked"]),
                    favorite=bool(row["favorite"]),
                    acquired_at=acquired_at,
                )
            )
        return tuple(cards)

    def save_unit(self, unit: Unit) -> None:
        with self.transaction():
            for member in unit.members:
                row = self._conn.execute(
                    "SELECT player_id FROM user_cards WHERE user_card_id = ?",
                    (member.user_card_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"unit references unknown card {member.user_card_id!r}")
                if str(row["player_id"]) != unit.player_id:
                    raise ValueError("unit cannot reference a card owned by another player")

            self._conn.execute(
                """
                INSERT INTO units(unit_id, player_id, slot, name) VALUES (?, ?, ?, ?)
                ON CONFLICT(unit_id) DO UPDATE SET
                    player_id = excluded.player_id,
                    slot = excluded.slot,
                    name = excluded.name
                """,
                (unit.unit_id, unit.player_id, unit.slot, unit.name),
            )
            self._conn.execute("DELETE FROM unit_members WHERE unit_id = ?", (unit.unit_id,))
            self._conn.executemany(
                "INSERT INTO unit_members(unit_id, position, user_card_id) VALUES (?, ?, ?)",
                (
                    (unit.unit_id, member.position, member.user_card_id)
                    for member in unit.members
                ),
            )

    def list_units(self, player_id: str) -> tuple[Unit, ...]:
        rows = self._conn.execute(
            "SELECT * FROM units WHERE player_id = ? ORDER BY slot, unit_id",
            (player_id,),
        ).fetchall()
        result: list[Unit] = []
        for row in rows:
            member_rows = self._conn.execute(
                """
                SELECT position, user_card_id
                FROM unit_members
                WHERE unit_id = ?
                ORDER BY position
                """,
                (row["unit_id"],),
            ).fetchall()
            result.append(
                Unit(
                    unit_id=str(row["unit_id"]),
                    player_id=str(row["player_id"]),
                    slot=int(row["slot"]),
                    name=None if row["name"] is None else str(row["name"]),
                    members=tuple(
                        UnitMember(int(member["position"]), str(member["user_card_id"]))
                        for member in member_rows
                    ),
                )
            )
        return tuple(result)

    def save_feature_unlock(self, unlock: FeatureUnlock) -> None:
        self._conn.execute(
            """
            INSERT INTO feature_unlocks(
                player_id, unlock_kind, master_ref_id, unlocked_at, source
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(player_id, unlock_kind, master_ref_id) DO UPDATE SET
                unlocked_at = excluded.unlocked_at,
                source = excluded.source
            """,
            (
                unlock.player_id,
                unlock.unlock_kind,
                unlock.master_ref_id,
                _encode_time(unlock.unlocked_at),
                unlock.source,
            ),
        )

    def list_feature_unlocks(self, player_id: str) -> tuple[FeatureUnlock, ...]:
        rows = self._conn.execute(
            """
            SELECT * FROM feature_unlocks
            WHERE player_id = ?
            ORDER BY unlock_kind, master_ref_id
            """,
            (player_id,),
        ).fetchall()
        result: list[FeatureUnlock] = []
        for row in rows:
            unlocked_at = _decode_time(row["unlocked_at"])
            assert unlocked_at is not None
            result.append(
                FeatureUnlock(
                    player_id=str(row["player_id"]),
                    unlock_kind=str(row["unlock_kind"]),
                    master_ref_id=int(row["master_ref_id"]),
                    unlocked_at=unlocked_at,
                    source=None if row["source"] is None else str(row["source"]),
                )
            )
        return tuple(result)

    def get_home_snapshot(self, player_id: str) -> HomeStateSnapshot | None:
        profile = self.get_profile(player_id)
        if profile is None:
            return None
        return HomeStateSnapshot(
            profile=profile,
            resources=self.list_resources(player_id),
            cards=self.list_cards(player_id),
            units=self.list_units(player_id),
            unlocks=self.list_feature_unlocks(player_id),
        )
