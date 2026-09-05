#!/usr/bin/env python3
"""Extract sanitized C2 request parameter object layouts from Il2CppDumper dump.cs.

The SetParameter signature pass recovers semantic arguments, but many wire payloads
are materialized into BaseParam/PostParams-derived objects.  This pass parses only
type metadata from dump.cs and emits field layouts for:

* object types referenced directly by request-role method signatures; and
* classes deriving from BaseParam/PostParams (including transitive subclasses).

No method bodies, native bytes, specimen files, or complete dump.cs content are
emitted.  Field names remain evidence candidates for request wire keys; inheritance
and later serializer data-flow still decide whether a field is actually transmitted.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCHEMA = 1

NS_RE = re.compile(r"^// Namespace:\s*(.*)$")
TYPE_RE = re.compile(
    r"^(?:\[[^\]]+\]\s*)*"
    r"(?P<prefix>(?:(?:public|private|protected|internal|abstract|sealed|static|partial|unsafe|new)\s+)*)"
    r"(?P<kind>class|struct)\s+"
    r"(?P<name>[^\s:{]+(?:<[^{}]+>)?)"
    r"(?:\s*:\s*(?P<bases>[^/{]+))?"
)
FIELD_RE = re.compile(
    r"^\s*(?:\[[^\]]+\]\s*)*"
    r"(?P<mods>(?:(?:public|private|protected|internal|static|readonly|const|volatile|unsafe|new)\s+)*)"
    r"(?P<type>[^();{}=]+?)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_<>]*)\s*;"
    r"(?:\s*//\s*(?P<offset>0x[0-9A-Fa-f]+))?\s*$"
)
C_IDENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*(?:_[A-Za-z0-9_]+)*)_o\s*\*")


@dataclass
class TypeDef:
    namespace: str
    name: str
    kind: str
    bases: list[str] = field(default_factory=list)
    fields: list[dict[str, Any]] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name


def normalize_managed_name(name: str) -> str:
    name = name.strip()
    name = re.sub(r"<.*>", "", name)
    return name.replace("/", ".")


def c_name_candidates(c_name: str) -> set[str]:
    base = c_name.strip()
    return {base, base.replace("_", ".")}


def canonical(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", normalize_managed_name(name)).lower()


def parse_dump(path: Path) -> list[TypeDef]:
    namespace = ""
    current: TypeDef | None = None
    in_fields = False
    brace_depth = 0
    result: list[TypeDef] = []

    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.rstrip()
        m = NS_RE.match(line)
        if m and current is None:
            namespace = m.group(1).strip()
            continue

        if current is None:
            tm = TYPE_RE.match(line.strip())
            if tm:
                bases = []
                if tm.group("bases"):
                    bases = [x.strip() for x in tm.group("bases").split(",") if x.strip()]
                current = TypeDef(namespace, tm.group("name"), tm.group("kind"), bases)
                brace_depth = line.count("{") - line.count("}")
                in_fields = False
            continue

        if line.strip() == "// Fields":
            in_fields = True
            continue
        if line.strip() == "// Methods":
            in_fields = False
            continue

        if in_fields:
            fm = FIELD_RE.match(line)
            if fm:
                modifiers = set((fm.group("mods") or "").split())
                row: dict[str, Any] = {
                    "name": fm.group("name"),
                    "managed_type": " ".join(fm.group("type").split()),
                    "is_static": "static" in modifiers or "const" in modifiers,
                }
                if fm.group("offset"):
                    row["offset"] = int(fm.group("offset"), 16)
                current.fields.append(row)

        brace_depth += line.count("{") - line.count("}")
        if brace_depth <= 0 and line.strip() == "}":
            result.append(current)
            current = None
            in_fields = False
            brace_depth = 0

    if current is not None:
        result.append(current)
    return result


def request_object_c_names(inventory: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for task in inventory.get("tasks", []):
        for method in task.get("role_methods", []):
            if method.get("role") != "request":
                continue
            sig = str(method.get("signature") or "")
            for c_name in C_IDENT_RE.findall(sig):
                if c_name.startswith(("System_", "MethodInfo", "Cute_NetworkTask", "Stage_NetworkTask")):
                    continue
                task_can = canonical(str(task.get("type", "")))
                if canonical(c_name) == task_can:
                    continue
                names.add(c_name)
    return names


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dump-cs", type=Path, required=True)
    p.add_argument("--inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    args = p.parse_args()

    inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    types = parse_dump(args.dump_cs)
    by_can: dict[str, list[TypeDef]] = {}
    for row in types:
        by_can.setdefault(canonical(row.full_name), []).append(row)
        by_can.setdefault(canonical(row.name), []).append(row)

    direct_c_names = request_object_c_names(inventory)
    direct_matches: set[str] = set()
    direct_unmatched: list[str] = []
    for c_name in sorted(direct_c_names):
        matches: list[TypeDef] = []
        for candidate in c_name_candidates(c_name):
            matches.extend(by_can.get(canonical(candidate), []))
        unique = {m.full_name: m for m in matches}
        if unique:
            direct_matches.update(unique)
        else:
            direct_unmatched.append(c_name)

    # Follow only the exact BaseParam/PostParams inheritance graph.  Do not use
    # fuzzy suffix matching here: broad matching can accidentally pull unrelated
    # UI/MonoBehaviour trees into a request-wire candidate set.
    lineage: set[str] = set()
    lineage_names = {
        canonical("BaseParam"), canonical("Stage.BaseParam"),
        canonical("PostParams"), canonical("Cute.PostParams"),
    }
    changed = True
    while changed:
        changed = False
        for t in types:
            full = t.full_name
            if full in lineage:
                continue
            if not any(canonical(base) in lineage_names for base in t.bases):
                continue
            lineage.add(full)
            lineage_names.add(canonical(t.full_name))
            lineage_names.add(canonical(t.name))
            changed = True

    selected = lineage | direct_matches
    reason: dict[str, set[str]] = {}
    for name in lineage:
        reason.setdefault(name, set()).add("baseparam-postparams-lineage")
    for name in direct_matches:
        reason.setdefault(name, set()).add("request-signature-object")

    rows = []
    for t in sorted((x for x in types if x.full_name in selected), key=lambda x: x.full_name):
        instance_fields = [f for f in t.fields if not f.get("is_static")]
        rows.append({
            "type": t.full_name,
            "kind": t.kind,
            "bases": t.bases,
            "selection_reason": sorted(reason.get(t.full_name, set())),
            "fields": t.fields,
            "field_count": len(t.fields),
            "instance_fields": instance_fields,
            "instance_field_count": len(instance_fields),
        })

    unique_field_names = sorted({f["name"] for r in rows for f in r["instance_fields"]})
    report = {
        "schema": SCHEMA,
        "scope": "sanitized request payload type metadata; field names are wire-key candidates, not serializer proof",
        "parsed_type_count": len(types),
        "request_signature_object_c_type_count": len(direct_c_names),
        "request_signature_object_c_types": sorted(direct_c_names),
        "unmatched_request_signature_object_c_types": direct_unmatched,
        "baseparam_postparams_lineage_type_count": len(lineage),
        "direct_request_object_type_count": len(direct_matches),
        "selected_param_type_count": len(rows),
        "selected_param_type_with_fields_count": sum(bool(r["instance_fields"]) for r in rows),
        "unique_field_name_candidate_count": len(unique_field_names),
        "unique_field_name_candidates": unique_field_names,
        "types": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.markdown_output:
        lines = [
            "# C2 request parameter type layouts", "",
            "Sanitized type/field metadata only. Field names are **wire-key candidates**, not yet serializer proof.", "",
            f"- parsed dump.cs class/struct types: **{len(types)}**",
            f"- request-signature object C types: **{len(direct_c_names)}**",
            f"- unmatched signature object C types: **{len(direct_unmatched)}**",
            f"- BaseParam/PostParams lineage types: **{len(lineage)}**",
            f"- direct request object types: **{len(direct_matches)}**",
            f"- selected types: **{len(rows)}**",
            f"- selected types with instance fields: **{sum(bool(r['instance_fields']) for r in rows)}**",
            f"- unique instance-field-name candidates: **{len(unique_field_names)}**", "",
            "## Highest-instance-field-count parameter types", "",
        ]
        for row in sorted(rows, key=lambda r: (-r["instance_field_count"], r["type"]))[:120]:
            fs = ", ".join(f"`{f['name']}:{f['managed_type']}`" for f in row["instance_fields"][:20]) or "(no instance fields)"
            lines.append(f"- `{row['type']}` ({row['instance_field_count']} instance fields) — {fs}")
        if direct_unmatched:
            lines += ["", "## Unmatched request object C names", ""]
            lines.extend(f"- `{x}`" for x in direct_unmatched)
        lines.append("")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
