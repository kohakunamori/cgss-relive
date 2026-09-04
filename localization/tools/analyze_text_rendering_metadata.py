#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import pathlib
import re
from typing import Any

SCHEMA_VERSION = 2

TARGET_TYPES = (
    "UnityEngine.UI.Text",
    "UnityEngine.Font",
    "TMPro.TMP_Text",
    "TMPro.TextMeshProUGUI",
    "TMPro.TextMeshPro",
    "TMPro.TMP_FontAsset",
    "TMPro.TMP_Settings",
)

INTERESTING_METHODS = {
    "get_text",
    "set_text",
    "SetText",
    "SetCharArray",
    "SetTextArrayToCharArray",
    "get_font",
    "set_font",
    "get_fontSize",
    "set_fontSize",
    "get_fontStyle",
    "set_fontStyle",
    "get_enableAutoSizing",
    "set_enableAutoSizing",
    "get_fallbackFontAssetTable",
    "set_fallbackFontAssetTable",
    "get_fallbackFontAssets",
    "set_fallbackFontAssets",
}

IL2CPP_NAMESPACE_RE = re.compile(r"(?m)^// Namespace:\s*([^\r\n]*)$")
CS_NAMESPACE_RE = re.compile(r"\bnamespace\s+([A-Za-z0-9_.]+)\s*\{")
TYPE_RE = re.compile(
    r"(?m)^[ \t]*(?:(?:public|internal|private|protected|abstract|sealed|static|partial)\s+)*"
    r"(?:class|struct)\s+([A-Za-z_][A-Za-z0-9_`]*)[^\n{]*\s*\{"
)
RVA_RE = re.compile(r"// RVA:\s*(0x[0-9A-Fa-f]+)")
METHOD_NAME_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]+>)?\s*\(")


def matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError(f"unclosed brace at offset {open_index}")


def namespace_segments(text: str) -> list[tuple[str, str]]:
    """Return namespace bodies for Il2CppDumper and ordinary C# layouts."""
    comment_matches = list(IL2CPP_NAMESPACE_RE.finditer(text))
    if comment_matches:
        segments: list[tuple[str, str]] = []
        for index, match in enumerate(comment_matches):
            start = match.end()
            end = (
                comment_matches[index + 1].start()
                if index + 1 < len(comment_matches)
                else len(text)
            )
            segments.append((match.group(1).strip(), text[start:end]))
        return segments

    segments = []
    for match in CS_NAMESPACE_RE.finditer(text):
        open_index = text.find("{", match.start())
        close_index = matching_brace(text, open_index)
        segments.append((match.group(1), text[open_index + 1 : close_index]))
    return segments


def class_blocks(namespace: str, body: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    for match in TYPE_RE.finditer(body):
        open_index = body.find("{", match.start())
        close_index = matching_brace(body, open_index)
        full_name = f"{namespace}.{match.group(1)}" if namespace else match.group(1)
        blocks.append((full_name, body[open_index + 1 : close_index]))
    return blocks


def parse_methods(body: str) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    pending_rva: str | None = None
    for raw_line in body.splitlines():
        line = raw_line.strip()
        rva = RVA_RE.search(line)
        if rva:
            pending_rva = rva.group(1).lower()
            continue
        if not line or "(" not in line:
            continue
        method_match = METHOD_NAME_RE.search(line)
        if not method_match:
            continue
        name = method_match.group(1)
        if name not in INTERESTING_METHODS:
            pending_rva = None
            continue
        methods.append({"name": name, "rva": pending_rva})
        pending_rva = None
    return methods


def analyze_dump_cs(path: pathlib.Path) -> dict[str, Any]:
    text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    found: dict[str, dict[str, Any]] = {}

    for namespace, namespace_body in namespace_segments(text):
        for full_name, class_body in class_blocks(namespace, namespace_body):
            if full_name not in TARGET_TYPES:
                continue
            found[full_name] = {
                "present": True,
                "interesting_methods": parse_methods(class_body),
            }

    return {
        "schema_version": SCHEMA_VERSION,
        "targets": {
            target: found.get(target, {"present": False, "interesting_methods": []})
            for target in TARGET_TYPES
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Extract only localization-relevant Text/TMP/font type presence and "
            "method RVAs from an ephemeral Il2CppDumper dump.cs."
        )
    )
    parser.add_argument("dump_cs", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    report = analyze_dump_cs(args.dump_cs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                target: {
                    "present": data["present"],
                    "method_count": len(data["interesting_methods"]),
                }
                for target, data in report["targets"].items()
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
