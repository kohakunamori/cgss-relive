"""Final-CGSS 11.6.3 compatibility adapter for A:47 ``story/start``.

Exact final native evidence establishes that ``StoryStartTask.SetParameter(int)``
stores its argument directly into ``StoryStartTaskParam.story_id``.  The response
parser reads an endpoint ``data`` object and first checks its element count.  A
zero-count object skips ``present_count`` and nested PData decoding, then clears the
client's temporary Story PData and iterates zero keys.

Accordingly, the empty response object emitted here is a parser-safe preservation
compatibility policy.  It is not claimed to be a captured or historical production
server response, and it does not by itself prove target-client runtime acceptance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


@dataclass(frozen=True)
class StoryStartRequest:
    story_id: int


def parse_story_start_request(request: Any) -> StoryStartRequest:
    """Validate the exact final request field recovered from ``SetParameter``."""

    if not isinstance(request, Mapping):
        raise ValueError("story/start request must be an object")
    if "story_id" not in request:
        raise ValueError("story/start request is missing story_id")
    story_id = request["story_id"]
    if type(story_id) is not int:
        # Managed/native evidence proves an Int32 field/store.  It does not prove a
        # positivity constraint, so do not invent one here.  ``bool`` is rejected
        # explicitly by the exact-type check despite Python's bool/int relationship.
        raise ValueError("story/start story_id must be an integer")
    return StoryStartRequest(story_id=story_id)


def project_story_start_response_data(_request: StoryStartRequest) -> dict[str, object]:
    """Return the minimal final-parser-safe endpoint data object.

    ``{}`` follows the exact zero-count branch in ``StoryStartTask.Parse``.  It is a
    preservation compatibility response, not a production-history assertion.
    """

    return {}
