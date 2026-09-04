#!/usr/bin/env python3
"""C8: conservatively classify C7b state consumers into preservation subsystems.

Classification is evidence-scored and deliberately does *not* use an upstream API
route as proof of a consumer's subsystem. The same Work*/TempData state surface can
be mutated by many endpoints, so route names are retained only as contextual
metadata. Primary evidence is the consumer method/type name, with weaker support
from the state type and reader name.

Ambiguous ties and weak/no-signal relations remain explicit instead of being
forced into a feature bucket.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

SCHEMA = 1
TAXONOMY = (
    "home", "live-result", "live", "story-commu", "room", "gacha", "mission",
    "event", "profile", "card-idol", "shop", "friend-social", "payment",
    "shared-core",
)

# Tokens are intentionally concrete. Broad terms such as User/Data/Manager are not
# feature evidence by themselves.
TOKENS: dict[str, tuple[str, ...]] = {
    "home": ("Home",),
    "live-result": ("LiveResult", "ResultLive"),
    "live": ("Live", "Music", "Concert"),
    "story-commu": ("Story", "Commu", "Scenario", "Communication"),
    "room": ("Room", "Furniture"),
    "gacha": ("Gacha",),
    "mission": ("Mission", "Achievement"),
    "event": (
        "Event", "Atapon", "Carnival", "Groove", "Parade", "Tower", "Rail",
        "Tour", "Infinity", "Caravan", "Susume", "TokenEvent",
    ),
    "profile": ("Profile", "NameCard", "ProducerProfile"),
    "card-idol": ("Card", "Idol", "Chara", "Dress", "Costume", "Album"),
    "shop": ("Shop", "Store", "Exchange"),
    "friend-social": ("Friend", "Social", "Greeting"),
    "payment": ("Payment", "Billing"),
    "shared-core": (
        "WorkDataManager", "SavedataManager", "AssetManager", "NetworkManager",
        "MasterDataManager",
    ),
}


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def endpoint_key(endpoint: dict[str, Any]) -> tuple[Any, ...]:
    return (
        endpoint.get("route"), endpoint.get("enum"), endpoint.get("group"),
        endpoint.get("key"), endpoint.get("status"),
    )


def token_present(text: str, token: str) -> bool:
    # CamelCase names make strict word boundaries inappropriate. Match the exact
    # case-insensitive token as a substring, but all configured tokens are >=4
    # characters and semantically specific enough for this bounded classifier.
    return token.lower() in text.lower()


def lexical_scores(text: str, weight: int, source: str) -> tuple[Counter[str], dict[str, list[str]]]:
    scores: Counter[str] = Counter()
    evidence: dict[str, list[str]] = defaultdict(list)
    lower = text.lower()
    has_story = "story" in lower or "commu" in lower or "scenario" in lower
    has_live_result = "liveresult" in lower or "resultlive" in lower
    has_room = "room" in lower
    has_payment = "payment" in lower or "billing" in lower
    for subsystem, tokens in TOKENS.items():
        for token in tokens:
            if not token_present(text, token):
                continue
            applied = weight
            # Resolve only obvious compound-name semantics. We do not impose a
            # global arbitrary subsystem priority.
            if subsystem == "event" and token == "Event" and has_story:
                applied = max(1, weight // 4)
            elif subsystem == "live" and token == "Live" and has_live_result:
                applied = max(1, weight // 4)
            elif subsystem == "shop" and token == "Shop" and has_room:
                applied = max(1, weight // 3)
            elif subsystem == "shop" and token == "Shop" and has_payment:
                applied = max(1, weight // 2)
            scores[subsystem] += applied
            evidence[subsystem].append(f"{source}:{token}:{applied}")
    return scores, dict(evidence)


def classify(relation: dict[str, Any]) -> dict[str, Any]:
    total: Counter[str] = Counter()
    evidence: dict[str, list[str]] = defaultdict(list)
    source_scores: dict[str, dict[str, int]] = {}
    inputs = (
        ("consumer", str(relation.get("consumer_method") or ""), 10),
        ("state", str(relation.get("state_type") or ""), 3),
        ("reader", str(relation.get("reader_full_name") or ""), 2),
    )
    for source, text, weight in inputs:
        scores, ev = lexical_scores(text, weight, source)
        source_scores[source] = dict(scores)
        total.update(scores)
        for subsystem, rows in ev.items():
            evidence[subsystem].extend(rows)

    ordered = sorted(total.items(), key=lambda item: (-item[1], item[0]))
    if not ordered:
        return {
            "primary_subsystem": None,
            "status": "unknown",
            "confidence": "unknown",
            "score": 0,
            "runner_up_score": 0,
            "candidates": [],
            "evidence": {},
            "source_scores": source_scores,
        }

    top_name, top_score = ordered[0]
    second_score = ordered[1][1] if len(ordered) > 1 else 0
    candidates = [
        {"subsystem": name, "score": score}
        for name, score in ordered if score >= max(2, top_score - 3)
    ]
    consumer_top = source_scores.get("consumer", {}).get(top_name, 0)
    margin = top_score - second_score

    if consumer_top >= 8 and margin >= 3:
        status, confidence, primary = "classified", "high", top_name
    elif top_score >= 6 and margin >= 3:
        status, confidence, primary = "classified", "medium", top_name
    elif top_score >= 4 and margin >= 2:
        status, confidence, primary = "classified", "low", top_name
    else:
        status, confidence, primary = "ambiguous", "ambiguous", None

    return {
        "primary_subsystem": primary,
        "status": status,
        "confidence": confidence,
        "score": top_score,
        "runner_up_score": second_score,
        "candidates": candidates,
        "evidence": {k: evidence[k] for k, _ in ordered if k in evidence},
        "source_scores": source_scores,
    }


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--state-consumers", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    a = p.parse_args()

    src = load(a.state_consumers)
    if int(src.get("schema", 0)) not in (1, 2):
        raise RuntimeError(f"unsupported C7b schema: {src.get('schema')!r}")

    state_context = {row["state_type"]: row for row in src.get("state_types", [])}
    classified_relations = []
    status_counts: Counter[str] = Counter()
    confidence_counts: Counter[str] = Counter()
    subsystem_counts: Counter[str] = Counter()
    consumer_subsystems: dict[tuple[str, int], set[str]] = defaultdict(set)
    endpoint_state_subsystem = set()

    for relation in src.get("relations", []):
        classification = classify(relation)
        row = dict(relation)
        row["subsystem"] = classification
        classified_relations.append(row)
        status_counts[classification["status"]] += 1
        confidence_counts[classification["confidence"]] += 1
        primary = classification["primary_subsystem"]
        if primary:
            subsystem_counts[primary] += 1
            consumer_subsystems[(str(row.get("consumer_method")), int(row.get("consumer_rva", 0)))].add(primary)
            for endpoint in state_context.get(row["state_type"], {}).get("upstream_endpoints", []):
                endpoint_state_subsystem.add(endpoint_key(endpoint) + (row["state_type"], primary))

    consumer_conflicts = [
        {"consumer_method": method, "consumer_rva": rva, "subsystems": sorted(subsystems)}
        for (method, rva), subsystems in consumer_subsystems.items()
        if len(subsystems) > 1
    ]
    consumer_conflicts.sort(key=lambda x: (x["consumer_method"], x["consumer_rva"]))

    state_summary = []
    rels_by_state: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in classified_relations:
        rels_by_state[row["state_type"]].append(row)
    for state_type in sorted(state_context):
        rows = rels_by_state.get(state_type, [])
        counts = Counter(
            row["subsystem"]["primary_subsystem"]
            for row in rows if row["subsystem"]["primary_subsystem"]
        )
        state_summary.append({
            "state_type": state_type,
            "relation_count": len(rows),
            "classified_relation_count": sum(counts.values()),
            "subsystem_counts": dict(sorted(counts.items())),
            "upstream_endpoints": state_context[state_type].get("upstream_endpoints", []),
        })

    report = {
        "schema": SCHEMA,
        "source_c7b_schema": src.get("schema"),
        "scope": "C8 conservative lexical subsystem classification over C7b direct consumer evidence; upstream routes are contextual only, not classification proof",
        "taxonomy": list(TAXONOMY),
        "relation_count": len(classified_relations),
        "classified_relation_count": status_counts["classified"],
        "ambiguous_relation_count": status_counts["ambiguous"],
        "unknown_relation_count": status_counts["unknown"],
        "classification_coverage": (status_counts["classified"] / len(classified_relations)) if classified_relations else 0.0,
        "status_counts": dict(sorted(status_counts.items())),
        "confidence_counts": dict(sorted(confidence_counts.items())),
        "subsystem_counts": dict(sorted(subsystem_counts.items())),
        "consumer_method_with_multiple_subsystems_count": len(consumer_conflicts),
        "endpoint_state_subsystem_relation_count": len(endpoint_state_subsystem),
        "relations": classified_relations,
        "state_summary": state_summary,
        "consumer_subsystem_conflicts": consumer_conflicts,
        "evidence_policy": {
            "consumer_name_weight": 10,
            "state_type_weight": 3,
            "reader_name_weight": 2,
            "upstream_route_used_for_classification": False,
            "forced_unknowns": False,
        },
    }

    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if a.markdown_output:
        lines = [
            "# C8 state consumer subsystem classification", "",
            "Consumer/type lexical evidence is primary. Upstream API routes are retained only as context and are not used to force a feature label.", "",
            f"- relations: **{report['relation_count']}**",
            f"- classified: **{report['classified_relation_count']}** ({report['classification_coverage']:.1%})",
            f"- ambiguous: **{report['ambiguous_relation_count']}**",
            f"- unknown: **{report['unknown_relation_count']}**",
            f"- endpoint→state→subsystem relations: **{report['endpoint_state_subsystem_relation_count']}**",
            f"- consumer methods with conflicting classified subsystems: **{report['consumer_method_with_multiple_subsystems_count']}**", "",
            "## Subsystems", "",
        ]
        lines.extend(f"- `{name}`: **{count}** relations" for name, count in sorted(subsystem_counts.items()))
        lines.extend(["", "## Confidence", ""])
        lines.extend(f"- `{name}`: **{count}**" for name, count in sorted(confidence_counts.items()))
        a.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        a.markdown_output.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: report[k] for k in (
        "relation_count", "classified_relation_count", "ambiguous_relation_count",
        "unknown_relation_count", "classification_coverage", "subsystem_counts",
        "confidence_counts", "consumer_method_with_multiple_subsystems_count",
        "endpoint_state_subsystem_relation_count",
    )}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
