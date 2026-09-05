#!/usr/bin/env python3
"""Derive C2 request parameter candidates from IL2CPP SetParameter signatures.

The final client exposes a large part of outbound request semantics directly in
managed method signatures even when wire-key strings are not referenced inside the
SetParameter body.  This pass parses the sanitized signatures already present in the
C2 inventory and emits semantic parameter candidates with coarse type classes.

These names are *managed semantic parameter names*, not automatically wire keys.
Object/struct parameters remain opaque here and are expanded by a later dump.cs
field-layout pass.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

SCHEMA = 1

PRIMITIVES = {
    "bool": "bool",
    "int8_t": "int",
    "uint8_t": "int",
    "int16_t": "int",
    "uint16_t": "int",
    "int32_t": "int",
    "uint32_t": "int",
    "int64_t": "int",
    "uint64_t": "int",
    "float": "float",
    "double": "float",
}


def split_params(raw: str) -> list[str]:
    parts=[]; buf=[]; depth=0
    for ch in raw:
        if ch in "<([": depth += 1
        elif ch in ">)]" and depth > 0: depth -= 1
        if ch == "," and depth == 0:
            part="".join(buf).strip()
            if part: parts.append(part)
            buf=[]
        else:
            buf.append(ch)
    part="".join(buf).strip()
    if part: parts.append(part)
    return parts


def classify_type(type_text: str) -> dict[str, Any]:
    cleaned = re.sub(r"\bconst\b", "", type_text).strip()
    pointer = "*" in cleaned
    base = cleaned.replace("*", "").strip()
    if base in PRIMITIVES:
        return {"kind": PRIMITIVES[base], "managed_c_type": cleaned}
    if base == "System_String_o":
        return {"kind": "string", "managed_c_type": cleaned}
    if base.endswith("_array"):
        return {"kind": "array", "managed_c_type": cleaned}
    if base.endswith("_o"):
        return {"kind": "object", "managed_c_type": cleaned}
    if pointer:
        return {"kind": "pointer-object", "managed_c_type": cleaned}
    return {"kind": "other", "managed_c_type": cleaned}


def parse_signature(signature: str | None) -> list[dict[str, Any]]:
    if not signature or "(" not in signature or ")" not in signature:
        return []
    raw = signature.split("(", 1)[1].rsplit(")", 1)[0]
    result=[]
    for part in split_params(raw):
        part=part.strip()
        if not part or part == "void":
            continue
        tokens=part.split()
        if len(tokens) < 2:
            continue
        name=tokens[-1].lstrip("*").strip()
        type_text=" ".join(tokens[:-1])
        # Asterisk may be attached to parameter name in C output.
        stars=len(tokens[-1]) - len(tokens[-1].lstrip("*"))
        if stars:
            type_text += " " + "*" * stars
        if name in {"__this", "method"} or name.startswith("__this"):
            continue
        info=classify_type(type_text)
        info.update({"name": name, "source": "il2cpp-method-signature"})
        result.append(info)
    return result


def main() -> int:
    p=argparse.ArgumentParser()
    p.add_argument("--request-inventory", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--markdown-output", type=Path)
    args=p.parse_args()

    inv=json.loads(args.request_inventory.read_text(encoding="utf-8"))
    methods=[]; task_rows=[]
    kind_counts={}
    with_params=0
    total_params=0
    object_types=set()
    for task in inv.get("tasks", []):
        task_methods=[]
        for method in task.get("request_methods", []):
            params=parse_signature(method.get("signature"))
            if params:
                with_params += 1
                total_params += len(params)
            for param in params:
                kind_counts[param["kind"]]=kind_counts.get(param["kind"],0)+1
                if param["kind"] in {"object","pointer-object"}:
                    object_types.add(param["managed_c_type"].replace("const ","").replace("*","").strip())
            row={
                "task": task["task"],
                "method": method["name"],
                "member": method["member"],
                "rva": int(method["rva"]),
                "signature": method.get("signature"),
                "parameters": params,
                "parameter_count": len(params),
            }
            methods.append(row); task_methods.append(row)
        task_rows.append({
            "task": task["task"],
            "methods": task_methods,
            "semantic_parameter_names": sorted({p["name"] for m in task_methods for p in m["parameters"]}),
        })

    endpoint_rows=[]
    task_index={row["task"]: row for row in task_rows}
    for endpoint in inv.get("endpoints", []):
        entries=[]
        for req_task in endpoint.get("request_tasks", []):
            task=task_index.get(req_task["task"])
            if task:
                entries.append(task)
        endpoint_rows.append({
            "group": endpoint["group"], "key": int(endpoint["key"]),
            "enum": endpoint["enum"], "route": endpoint["route"],
            "tasks": entries,
            "semantic_parameter_names": sorted({name for t in entries for name in t["semantic_parameter_names"]}),
        })

    report={
        "schema": SCHEMA,
        "scope": "C2 managed SetParameter signature parameters; semantic names are not yet proven wire keys",
        "method_count": len(methods),
        "methods_with_explicit_parameters": with_params,
        "methods_without_explicit_parameters": len(methods)-with_params,
        "semantic_parameter_count": total_params,
        "parameter_kind_counts": dict(sorted(kind_counts.items())),
        "opaque_object_type_count": len(object_types),
        "opaque_object_types": sorted(object_types),
        "methods": methods,
        "tasks": task_rows,
        "endpoints": endpoint_rows,
    }
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")

    if args.markdown_output:
        lines=[
            "# C2 request signature schema", "",
            "Managed parameter names are semantic candidates, **not automatically wire keys**.", "",
            f"- request methods: **{len(methods)}**",
            f"- methods with explicit parameters: **{with_params}**",
            f"- methods without explicit parameters: **{len(methods)-with_params}**",
            f"- semantic parameters: **{total_params}**",
            f"- opaque object types requiring field expansion: **{len(object_types)}**", "",
            "## Representative methods", "",
        ]
        ranked=sorted(methods,key=lambda row:row["parameter_count"],reverse=True)
        for row in ranked[:120]:
            params=", ".join(f"`{p['name']}:{p['kind']}`" for p in row["parameters"]) or "(none)"
            lines.append(f"- `{row['method']}` — {params}")
        lines += ["", "Next: expand object/array parameter layouts and trace serialization/wire-key helpers.", ""]
        args.markdown_output.parent.mkdir(parents=True,exist_ok=True)
        args.markdown_output.write_text("\n".join(lines),encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
