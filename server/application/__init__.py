"""Application services that compose domain state with CGSS compatibility adapters."""

from .load_index import DomainLoadIndexConfig, DomainLoadIndexController

__all__ = ["DomainLoadIndexConfig", "DomainLoadIndexController"]
