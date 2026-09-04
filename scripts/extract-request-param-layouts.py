#!/usr/bin/env python3
"""Extract sanitized C2 request parameter object layouts from Il2CppDumper dump.cs.

The SetParameter signature pass recovers semantic arguments, but many wire payloads
are materialized into BaseParam/PostParams-derived objects. This pass parses only
type metadata from dump.cs and emits field layouts for:

* object types referenced directly by request-role method signatures; and
* classes deriving from BaseParam/PostParams (including transitive subclasses).

No method bodies, native bytes, specimen files, or complete dump.cs content are
emitted. Field names remain evidence candidates for request wire keys; inheritance
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
    r"(?:(?:public|private|protected|internal|static|readonly|const|volatile|unsafe|new)\s+)*"
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
                row: dict[str, Any] = {
                    "name": fm.group("name"),
                    "managed_type": " ".join(fm.group("type").split()),
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
        if not matches:
            cc = canonical(c_name)
            matches = [t for t in types if canonical(t.full_name).endswith(cc) or cc.endswith(canonical(t.full_name))]
        unique = {m.full_name: m for m in matches}
        if unique:
            direct_matches.update(unique)
        else:
            direct_unmatched.append(c_name)

    selected = set(direct_matches)
    reason: dict[str, set[str]] = {name: {"request-signature-object"} for name in direct_matches}
    changed = True
    while changed:
        changed = False
        for t in types:
            full = t.full_name
            if full in selected:
                continue
            base_cans = {canonical(x) for x in t.bases}
            base_short = {canonical(x.split(".")[-1]) for x in t.bases}
            is_param_base = bool((base_cans | base_short) & {canonical("BaseParam"), canonical("PostParams")})
            derives_selected = any(
                canonical(base).endswith(canonical(sel)) or canonical(sel).endswith(canonical(base))
                for base in t.bases for sel in selected
            )
            is_param_base = is_param_base or any(
                canonical(base).endswith(canonical("BaseParam")) or canonical(base).endswith(canonical("PostParams"))
                for base in t.bases
            )
            if is_param_base or derives_selected:
                selected.add(full)
                reason.setdefault(full, set()).add(
                    "baseparam-postparams-lineage" if is_param_base else "transitive-selected-base"
                )
                changed = True

    rows = []
    for t in sorted((x for x in types if x.full_name in selected), key=lambda x: x.full_name):
        rows.append({
            "type": t.full_name,
            "kind": t.kind,
            "bases": t.bases,
            "selection_reason": sorted(reason.get(t.full_name, {"transitive-selected-base"})),
            "fields": t.fields,
            "field_count": len(t.fields),
        })

    unique_field_names = sorted({f["name"] for r in rows for f in r["fields"]})
    report = {
        "schema": SCHEMA,
        "scope": "sanitized request payload type metadata; field names are wire-key candidates, not serializer proof",
        "parsed_type_count": len(types),
        "request_signature_object_c_type_count": len(direct_c_names),
        "request_signature_object_c_types": sorted(direct_c_names),
        "unmatched_request_signature_object_c_types": direct_unmatched,
        "selected_param_type_count": len(rows),
        "selected_param_type_with_fields_count": sum(bool(r["fields"]) for r in rows),
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
            f"- parsed dump.cs types: **{len(types)}**",
            f"- request-signature object C types: **{len(direct_c_names)}**",
            f"- unmatched signature object C types: **{len(direct_unmatched)}**",
            f"- selected BaseParam/PostParams/signature types: **{len(rows)}**",
            f"- selected types with fields: **{sum(bool(r['fields']) for r in rows)}**",
            f"- unique field-name candidates: **{len(unique_field_names)}**", "",
            "## Highest-field-count parameter types", "",
        ]
        for row in sorted(rows, key=lambda r: (-r["field_count"], r["type"]))[:120]:
            fs = ", ".join(f"`{f['name']}:{f['managed_type']}`" for f in row["fields"][:20]) or "(no instance fields)"
            lines.append(f"- `{row['type']}` ({row['field_count']}) — {fs}")
        if direct_unmatched:
            lines += ["", "## Unmatched request object C names", ""]
            lines.extend(f"- `{x}`" for x in direct_unmatched)
        lines.append("")
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text("\n".join(lines), encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
