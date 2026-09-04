#!/usr/bin/env python3
"""Launch the rooted local stack with final-client static service baselines.

This wrapper compiles C14+C9 static templates (C15 conservative zero-field
routes plus C18 parser-proven optional omissions), layers optional stronger
explicit templates, and delegates to the existing ``run-rooted-local-stack.py``
supervisor. Unknown arguments are passed through unchanged, so resource/TLS/
profile options remain owned by the proven supervisor.

All C15/C18 routes remain static evidence until accepted by the untouched client.
"""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from server.conservative_templates import load_conservative_empty_templates  # noqa: E402
from server.optional_omission_templates import load_optional_omission_templates  # noqa: E402
from server.response_templates import ResponseTemplateStore  # noqa: E402
from server.semantic_contracts import SemanticContractIndex  # noqa: E402


def compile_templates(
    *,
    semantic_db: Path,
    effective_runtime_catalog: Path,
    output: Path,
    explicit_templates: Path | None = None,
    enforce_final_counts: bool = True,
) -> tuple[int, int, int, int]:
    semantic = SemanticContractIndex(
        semantic_db,
        enforce_final_counts=enforce_final_counts,
    )
    c15 = load_conservative_empty_templates(
        effective_runtime_catalog,
        semantic_index=semantic,
        enforce_final_counts=enforce_final_counts,
    )
    c18 = load_optional_omission_templates(
        effective_runtime_catalog,
        semantic_index=semantic,
        enforce_final_counts=enforce_final_counts,
    )
    static_baseline = c15.merged(c18)
    compiled = static_baseline
    explicit_count = 0
    if explicit_templates is not None:
        explicit = ResponseTemplateStore.load(explicit_templates, semantic_index=semantic)
        explicit_count = explicit.count
        compiled = static_baseline.merged(explicit)

    routes = {}
    for route in compiled.routes:
        template = compiled.get(route)
        assert template is not None
        item = {
            "endpoint_id": template.endpoint_id,
            "data": copy.deepcopy(template.data),
        }
        if template.evidence is not None:
            item["evidence"] = template.evidence
        routes[route] = item
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps({"schema": 1, "routes": routes}, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return c15.count, c18.count, explicit_count, compiled.count


def build_delegate_command(
    *,
    semantic_db: Path,
    compiled_templates: Path,
    passthrough: Sequence[str],
) -> tuple[str, ...]:
    return (
        sys.executable,
        str(ROOT / "scripts" / "run-rooted-local-stack.py"),
        "--semantic-db",
        str(semantic_db),
        "--response-templates",
        str(compiled_templates),
        *passthrough,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compile static full-service baselines and launch the proven rooted local stack",
        allow_abbrev=False,
    )
    parser.add_argument("--semantic-db", type=Path, required=True)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument(
        "--explicit-templates",
        type=Path,
        help="optional stronger schema-1 endpoint templates layered over static baselines",
    )
    parser.add_argument(
        "--compiled-templates-output",
        type=Path,
        default=ROOT / "work" / "static-runtime-response-templates.json",
    )
    args, passthrough = parser.parse_known_args()

    for path, label in (
        (args.semantic_db, "semantic DB"),
        (args.effective_runtime_catalog, "effective runtime catalog"),
    ):
        if not path.is_file():
            parser.error(f"{label} is missing: {path}")
    if args.explicit_templates is not None and not args.explicit_templates.is_file():
        parser.error(f"explicit templates are missing: {args.explicit_templates}")
    forbidden = {"--semantic-db", "--response-templates"}
    if any(item.split("=", 1)[0] in forbidden for item in passthrough):
        parser.error("do not pass --semantic-db/--response-templates twice through passthrough")

    try:
        c15_count, c18_count, explicit_count, compiled_count = compile_templates(
            semantic_db=args.semantic_db.resolve(),
            effective_runtime_catalog=args.effective_runtime_catalog.resolve(),
            output=args.compiled_templates_output.resolve(),
            explicit_templates=(
                args.explicit_templates.resolve() if args.explicit_templates is not None else None
            ),
        )
    except (OSError, ValueError) as exc:
        print(f"full-service template compilation failed: {exc}", file=sys.stderr)
        return 2

    print(
        "compiled full-service template layer: "
        f"C15={c15_count}, C18={c18_count}, explicit={explicit_count}, "
        f"effective={compiled_count}; evidence=static/CI, device_acceptance=false"
    )
    command = build_delegate_command(
        semantic_db=args.semantic_db.resolve(),
        compiled_templates=args.compiled_templates_output.resolve(),
        passthrough=passthrough,
    )
    return subprocess.call(command, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
