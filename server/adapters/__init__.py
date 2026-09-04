"""CGSS client compatibility adapters.

Adapters own endpoint/wire DTO details and translate to/from ``server.domain``.
The preservation domain must not import this package.
"""

from .load_index import (
    CardLoadIndexBinding,
    LoadIndexProjectionPolicy,
    UnitLoadIndexBinding,
    project_home_snapshot_to_load_index_data,
)

__all__ = [
    "CardLoadIndexBinding",
    "LoadIndexProjectionPolicy",
    "UnitLoadIndexBinding",
    "project_home_snapshot_to_load_index_data",
]
