#!/usr/bin/env python3
"""Join the final ApiType map to the broad NetworkTask inventory.

This is a candidate-generation pass, not a proof pass.  Exact normalized enum/task
name matches are useful anchors for later constructor analysis, but remain labelled
`candidate` until an ApiType key flow or equivalent static/runtime evidence binds
them.
"""
from __future__ import annotations

import argparse
import difflib
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1
TOP_RANKED = 3
RANKED_ACCEPT = 0.78
RANKED_MARGIN = 0.08

_SUFFIXES = ("NetworkTask", "Task", "Api", "Request", "Response")
_NOISE = {
    "task", "load", "top", "get", "set", "update", "exec", "exe", "index",
    "info", "list", "start", "end",
}


def short_name(value: str) -> str:
    return value.rsplit(".", 1)[-1]


def normalize(value: str) -> str:
    value = short_name(value)
    changed = True
    while changed:
        changed = False
        for suffix in _SUFFIXES:
            if value.endswith(suffix):
                value = value[: -len(suffix)]
                changed = True
                break
    return re.sub(r"[^a-z0-9]", "", value.lower())


def camel_tokens(value: str) -> set[str]:
    value = short_name(value)
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    tokens = {item.lower() for item in re.split(r"[^A-Za-z0-9]+", value) if item}
    return tokens - _NOISE


def endpoint_rows(raw: dict[str, Any]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for group in ("A", "B"):
        entries = raw.get(group)
        if not isinstance(entries, list):
            raise RuntimeError(f"missing {group} endpoint group")
        for entry in entries:
            if not isinstance(entry, list) or len(entry) != 4:
                raise RuntimeError(f"invalid {group} endpoint row")
            name, key, path, literal_index = entry
            if not isinstance(name, str) or not isinstance(key, int) or not isinstance(path, str) or not isinstance(literal_index, int):
                raise RuntimeError(f"invalid {group} endpoint row types")
            result.append(
                {
                    "group": group,
                    "key": key,
                    "name": name,
                    "path": path,
                    "literal_index": literal_index,
                }
            )
    return result


def similarity(endpoint: dict[str, Any], task_type: str) -> float:
    enum_norm = normalize(endpoint["name"])
    task_norm = normalize(task_type)
    enum_ratio = difflib.SequenceMatcher(None, enum_norm, task_norm).ratio()

    path_norm = re.sub(r"[^a-z0-9]", "", endpoint["path"].lower())
    path_ratio = difflib.SequenceMatcher(None, path_norm, task_norm).ratio()

    enum_tokens = camel_tokens(endpoint["name"])
    task_tokens = camel_tokens(task_type)
    token_dice = (
        (2.0 * len(enum_tokens & task_tokens) / (len(enum_tokens) + len(task_tokens)))
        if enum_tokens or task_tokens
        else 0.0
    )

    return max(
        enum_ratio,
        0.70 * enum_ratio + 0.30 * token_dice,
        0.60 * path_ratio + 0.40 * token_dice,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--api-map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    args = parser.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    api_map = json.loads(args.api_map.read_text(encoding="utf-8"))
    endpoints = endpoint_rows(api_map)
    tasks = [str(item["type"]) for item in inventory.get("tasks", [])]
    if not tasks:
        raise RuntimeError("inventory contains no tasks")

    by_normalized: dict[str, list[str]] = defaultdict(list)
    for task in tasks:
        by_normalized[normalize(task)].append(task)

    bindings: list[dict[str, Any]] = []
    exact_unique_count = 0
    ranked_primary_count = 0
    unresolved_count = 0

    for endpoint in endpoints:
        exact = sorted(by_normalized.get(normalize(endpoint["name"]), []))
        if len(exact) == 1:
            exact_unique_count += 1
            candidates = [
                {
                    "task": exact[0],
                    "score": 1.0,
                    "evidence": ["enum_name_exact"],
                }
            ]
            status = "candidate-exact-name"
            primary = exact[0]
        else:
            ranked = sorted(
                (
                    {
                        "task": task,
                        "score": round(similarity(endpoint, task), 6),
                        "evidence": ["name_path_similarity"],
                    }
                    for task in tasks
                ),
                key=lambda item: (-item["score"], item["task"]),
            )[:TOP_RANKED]
            candidates = ranked
            if (
                ranked
                and ranked[0]["score"] >= RANKED_ACCEPT
                and (len(ranked) == 1 or ranked[0]["score"] - ranked[1]["score"] >= RANKED_MARGIN)
            ):
                ranked_primary_count += 1
                status = "candidate-ranked"
                primary = ranked[0]["task"]
            else:
                unresolved_count += 1
                status = "unresolved"
                primary = None

        bindings.append(
            {
                **endpoint,
                "status": status,
                "primary_candidate": primary,
                "candidates": candidates,
            }
        )

    report = {
        "schema": SCHEMA,
        "scope": "candidate endpoint-to-NetworkTask binding; no candidate is static proof",
        "endpoint_count": len(endpoints),
        "task_count": len(tasks),
        "candidate_exact_name_count": exact_unique_count,
        "candidate_ranked_primary_count": ranked_primary_count,
        "unresolved_count": unresolved_count,
        "bindings": bindings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output is not None:
        lines = [
            "# C1 endpoint-to-task candidate binding",
            "",
            "This report generates candidates only. No row is `proven-static` solely from naming.",
            "",
            f"- endpoints: **{len(endpoints)}**",
            f"- unique exact enum/task-name candidates: **{exact_unique_count}**",
            f"- additional high-margin ranked candidates: **{ranked_primary_count}**",
            f"- unresolved: **{unresolved_count}**",
            "",
            "## Unresolved / ambiguous rows",
            "",
        ]
        for row in bindings:
            if row["status"] != "unresolved":
                continue
            candidates = ", ".join(
                f"`{item['task']}` ({item['score']:.3f})" for item in row["candidates"]
            )
            lines.append(
                f"- `{row['group']}:{row['key']} {row['name']}` `{row['path']}` -> {candidates or 'no candidate'}"
            )
        lines += [
            "",
            "Next pass: recover the ApiType key written/passed by each task constructor and use that as static binding evidence.",
            "",
        ]
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
