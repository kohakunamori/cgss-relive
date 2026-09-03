#!/usr/bin/env python3
"""Run the rooted-device local CGSS stack as one supervised foreground process.

The supervisor is deliberately conservative:

1. final 10133800 local resources must pass the sanitized preflight;
2. control and resource backends are started on loopback plain HTTP;
3. both health endpoints must answer before TLS is exposed;
4. the multi-SAN TLS mux is then started on the single adb-reverse host port;
5. any unexpected child exit tears down the whole stack.

No request/body/resource identifiers are inspected by this helper. Runtime
evidence remains in the two backend sanitized JSONL logs.
"""
from __future__ import annotations

import argparse
import http.client
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


FINAL_RESOURCE_VERSION = "10133800"
DEFAULT_API_PORT = 8080
DEFAULT_RESOURCE_PORT = 8081
DEFAULT_TLS_PORT = 8445
HEALTH_TIMEOUT_SECONDS = 8.0
POLL_INTERVAL_SECONDS = 0.2
SHUTDOWN_TIMEOUT_SECONDS = 3.0


@dataclass(frozen=True)
class StackCommands:
    preflight: tuple[str, ...]
    api: tuple[str, ...]
    resource: tuple[str, ...]
    mux: tuple[str, ...]


def build_stack_commands(
    *,
    python: str,
    repo_root: Path,
    resource_root: Path,
    manifest_db: Path,
    cert: Path,
    key: Path,
    preflight_report: Path,
    control_log: Path,
    resource_log: Path,
    api_map: Path | None,
    viewer_id: int,
    producer_name: str,
    api_port: int,
    resource_port: int,
    tls_port: int,
    accept_old_resource_version: bool,
) -> StackCommands:
    preflight = (
        python,
        str(repo_root / "scripts" / "preflight-local-resources.py"),
        "--version",
        FINAL_RESOURCE_VERSION,
        "--root",
        str(resource_root),
        "--manifest-db",
        str(manifest_db),
        "--output",
        str(preflight_report),
    )

    api: list[str] = [
        python,
        "-m",
        "server.http_server",
        "--host",
        "127.0.0.1",
        "--port",
        str(api_port),
        "--experimental-starter-load-index",
        "--viewer-id",
        str(viewer_id),
        "--producer-name",
        producer_name,
        "--event-log",
        str(control_log),
    ]
    if api_map is not None:
        api.extend(("--api-map", str(api_map)))
    if accept_old_resource_version:
        api.append("--accept-old-resource-version")

    resource = (
        python,
        "-m",
        "server.resource_server",
        "--host",
        "127.0.0.1",
        "--port",
        str(resource_port),
        "--version",
        FINAL_RESOURCE_VERSION,
        "--root",
        str(resource_root),
        "--manifest-db",
        str(manifest_db),
        "--event-log",
        str(resource_log),
    )

    mux = (
        python,
        "-m",
        "server.tls_mux",
        "--host",
        "127.0.0.1",
        "--port",
        str(tls_port),
        "--cert",
        str(cert),
        "--key",
        str(key),
        "--api-backend",
        f"127.0.0.1:{api_port}",
        "--resource-backend",
        f"127.0.0.1:{resource_port}",
    )
    return StackCommands(tuple(preflight), tuple(api), resource, mux)


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{label} is missing: {path}")


def wait_for_health(port: int, process: subprocess.Popen[bytes], *, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            raise RuntimeError(f"backend exited before health check: rc={exit_code}")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            response.read()
            if response.status == 200:
                return
            last_error = RuntimeError(f"health endpoint returned HTTP {response.status}")
        except (OSError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
        time.sleep(POLL_INTERVAL_SECONDS)
    raise RuntimeError(f"health check timed out on 127.0.0.1:{port}: {type(last_error).__name__ if last_error else 'unknown'}")


def terminate_children(children: Sequence[tuple[str, subprocess.Popen[bytes]]]) -> None:
    for _, process in reversed(children):
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + SHUTDOWN_TIMEOUT_SECONDS
    for _, process in reversed(children):
        remaining = max(0.0, deadline - time.monotonic())
        if process.poll() is None:
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                process.kill()
    for _, process in reversed(children):
        if process.poll() is None:
            process.wait()


def start_child(name: str, command: Sequence[str], *, cwd: Path) -> tuple[str, subprocess.Popen[bytes]]:
    print(f"starting {name}")
    process = subprocess.Popen(tuple(command), cwd=cwd)
    return name, process


def positive_port(value: str) -> int:
    port = int(value)
    if port < 1 or port > 65535:
        raise argparse.ArgumentTypeError("port must be in 1..65535")
    return port


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Preflight and supervise the final 11.6.3 rooted-device local compatibility stack"
    )
    parser.add_argument(
        "--resource-root",
        type=Path,
        default=repo_root / "resource-cache" / FINAL_RESOURCE_VERSION,
    )
    parser.add_argument(
        "--manifest-db",
        type=Path,
        default=repo_root / "work" / "resources" / "manifest_10133800.db",
    )
    parser.add_argument(
        "--cert",
        type=Path,
        default=repo_root / "work" / "tls" / "server.chain.pem",
    )
    parser.add_argument(
        "--key",
        type=Path,
        default=repo_root / "work" / "tls" / "server.key.pem",
    )
    parser.add_argument(
        "--preflight-report",
        type=Path,
        default=repo_root / "work" / "resource-preflight.json",
    )
    parser.add_argument(
        "--control-log",
        type=Path,
        default=repo_root / "work" / "runtime-starter-control.jsonl",
    )
    parser.add_argument(
        "--resource-log",
        type=Path,
        default=repo_root / "work" / "runtime-starter-resource.jsonl",
    )
    parser.add_argument("--api-map", type=Path)
    parser.add_argument("--viewer-id", type=int, default=1)
    parser.add_argument("--producer-name", default="Relive Producer")
    parser.add_argument("--api-port", type=positive_port, default=DEFAULT_API_PORT)
    parser.add_argument("--resource-port", type=positive_port, default=DEFAULT_RESOURCE_PORT)
    parser.add_argument("--tls-port", type=positive_port, default=DEFAULT_TLS_PORT)
    parser.add_argument(
        "--accept-old-resource-version",
        action="store_true",
        help="diagnostic only: bypass native 214 while preserving required_res_ver advance",
    )
    args = parser.parse_args()

    paths = {
        "resource root": args.resource_root.resolve(),
        "manifest DB": args.manifest_db.resolve(),
        "certificate chain": args.cert.resolve(),
        "private key": args.key.resolve(),
        "preflight report": args.preflight_report.resolve(),
        "control log": args.control_log.resolve(),
        "resource log": args.resource_log.resolve(),
    }
    api_map = args.api_map.resolve() if args.api_map else None

    require_file(paths["manifest DB"], "manifest DB")
    require_file(paths["certificate chain"], "certificate chain")
    require_file(paths["private key"], "private key")
    if api_map is not None:
        require_file(api_map, "API map")

    paths["preflight report"].parent.mkdir(parents=True, exist_ok=True)
    paths["control log"].parent.mkdir(parents=True, exist_ok=True)
    paths["resource log"].parent.mkdir(parents=True, exist_ok=True)

    commands = build_stack_commands(
        python=sys.executable,
        repo_root=repo_root,
        resource_root=paths["resource root"],
        manifest_db=paths["manifest DB"],
        cert=paths["certificate chain"],
        key=paths["private key"],
        preflight_report=paths["preflight report"],
        control_log=paths["control log"],
        resource_log=paths["resource log"],
        api_map=api_map,
        viewer_id=args.viewer_id,
        producer_name=args.producer_name,
        api_port=args.api_port,
        resource_port=args.resource_port,
        tls_port=args.tls_port,
        accept_old_resource_version=args.accept_old_resource_version,
    )

    print("checking frozen final resource set")
    preflight = subprocess.run(commands.preflight, cwd=repo_root, check=False)
    if preflight.returncode != 0:
        print(f"resource preflight failed: rc={preflight.returncode}", file=sys.stderr)
        return preflight.returncode

    children: list[tuple[str, subprocess.Popen[bytes]]] = []
    try:
        api = start_child("control API", commands.api, cwd=repo_root)
        children.append(api)
        wait_for_health(args.api_port, api[1], timeout=HEALTH_TIMEOUT_SECONDS)
        print(f"control API healthy on 127.0.0.1:{args.api_port}")

        resource = start_child("resource backend", commands.resource, cwd=repo_root)
        children.append(resource)
        wait_for_health(args.resource_port, resource[1], timeout=HEALTH_TIMEOUT_SECONDS)
        print(f"resource backend healthy on 127.0.0.1:{args.resource_port}")

        mux = start_child("TLS host mux", commands.mux, cwd=repo_root)
        children.append(mux)
        time.sleep(0.5)
        if mux[1].poll() is not None:
            raise RuntimeError(f"TLS mux exited during startup: rc={mux[1].returncode}")

        print(f"rooted-device stack ready: adb reverse tcp:443 -> host tcp:{args.tls_port}")
        print("press Ctrl+C to stop all local stack processes")
        while True:
            for name, process in children:
                exit_code = process.poll()
                if exit_code is not None:
                    raise RuntimeError(f"{name} exited unexpectedly: rc={exit_code}")
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("stopping rooted-device stack")
        return 130
    except (OSError, RuntimeError) as exc:
        print(f"stack failure: {exc}", file=sys.stderr)
        return 1
    finally:
        terminate_children(children)


if __name__ == "__main__":
    raise SystemExit(main())
