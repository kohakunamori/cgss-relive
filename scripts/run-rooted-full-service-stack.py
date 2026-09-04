#!/usr/bin/env python3
"""Launch the rooted local stack with the opt-in C15 full-service baseline.

This wrapper compiles C14+C9 conservative templates (plus optional stronger
explicit templates) into a local schema-1 file and delegates to the existing
``run-rooted-local-stack.py`` supervisor.  All unknown arguments are passed
through unchanged, so resource/TLS/profile options remain owned by the proven
supervisor.

C15 routes are static parser candidates, not untouched-client acceptance claims.
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
from server.response_templates import ResponseTemplateStore  # noqa: E402
from server.semantic_contracts import SemanticContractIndex  # noqa: E402


def compile_templates(
    *,
    semantic_db: Path,
    effective_runtime_catalog: Path,
    output: Path,
    explicit_templates: Path | None = None,
) -> tuple[int, int, int]:
    semantic = SemanticContractIndex(semantic_db)
    baseline = load_conservative_empty_templates(
        effective_runtime_catalog,
        semantic_index=semantic,
    )
    compiled = baseline
    explicit_count = 0
    if explicit_templates is not None:
        explicit = ResponseTemplateStore.load(explicit_templates, semantic_index=semantic)
        explicit_count = explicit.count
        compiled = baseline.merged(explicit)

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
    return baseline.count, explicit_count, compiled.count


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
        description="Compile C15 service baseline and launch the proven rooted local stack",
        allow_abbrev=False,
    )
    parser.add_argument("--semantic-db", type=Path, required=True)
    parser.add_argument("--effective-runtime-catalog", type=Path, required=True)
    parser.add_argument(
        "--explicit-templates",
        type=Path,
        help="optional stronger schema-1 endpoint templates layered over C15",
    )
    parser.add_argument(
        "--compiled-templates-output",
        type=Path,
        default=ROOT / "work" / "c15-runtime-response-templates.json",
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
        baseline_count, explicit_count, compiled_count = compile_templates(
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
        f"C15={baseline_count}, explicit={explicit_count}, effective={compiled_count}; "
        "evidence=static/CI, device_acceptance=false"
    )
    command = build_delegate_command(
        semantic_db=args.semantic_db.resolve(),
        compiled_templates=args.compiled_templates_output.resolve(),
        passthrough=passthrough,
    )
    return subprocess.call(command, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
