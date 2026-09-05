"""Compatibility-only application controller for A:47 ``story/start``.

``story/start`` initializes client-side temporary Story state.  No durable archival
Story progression is invented here; durable unlock/open semantics belong to the
separate final-client ``story/open_v2`` surface once that contract is closed.
"""

from __future__ import annotations

from typing import Any

from server.adapters.story_start import (
    parse_story_start_request,
    project_story_start_response_data,
)


class StoryStartController:
    """Validate the exact wire request and emit the parser-safe compatibility data."""

    def handle(self, raw_request: Any) -> dict[str, object]:
        request = parse_story_start_request(raw_request)
        return project_story_start_response_data(request)

    def __call__(self, raw_request: Any) -> dict[str, object]:
        return self.handle(raw_request)
