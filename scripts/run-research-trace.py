#!/usr/bin/env python3
"""Launch or attach to CGSS and collect bounded research instrumentation events.

This intentionally records only structured events emitted by
client/research/frida/cgss-trace.js. It does not dump request/response payloads,
credentials, device identifiers, or arbitrary process memory.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import signal
import sys
import time

try:
    import frida
except ImportError as exc:  # pragma: no cover - environment dependency
    raise SystemExit(
        "Python package 'frida' is required. Install a matching Frida client for your device."
    ) from exc


DEFAULT_PACKAGE = "jp.co.bandainamcoent.BNEI0242"


def parse_args() -> argparse.Namespace:
    repo_root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--serial", default=None, help="ADB/Frida device id; default is USB device")
    parser.add_argument("--host", default=None, help="Frida remote host, e.g. 127.0.0.1:27042 after adb forward")
    parser.add_argument(
        "--spawn-pid-file",
        default=None,
        help="write the spawned PID here before resume; ignored for attach mode",
    )
    parser.add_argument(
        "--resume-gate-file",
        default=None,
        help="when spawning, wait for this file to exist before resuming the process",
    )
    parser.add_argument("--attach", action="store_true", help="Attach to an already-running process instead of spawning")
    parser.add_argument(
        "--pid",
        type=int,
        default=None,
        help="attach directly to this PID; avoids Android process enumeration on OEM builds where Frida enumeration is broken",
    )
    parser.add_argument(
        "--script",
        default=str(repo_root / "client" / "research" / "frida" / "cgss-trace.js"),
    )
    parser.add_argument(
        "--output",
        default=str(repo_root / "work" / "runtime" / "cgss-research-trace.jsonl"),
    )
    return parser.parse_args()


def get_device(serial: str | None, host: str | None):
    manager = frida.get_device_manager()
    if host:
        return manager.add_remote_device(host)
    if serial:
        return manager.get_device(serial, timeout=10)
    return frida.get_usb_device(timeout=10)


def main() -> int:
    args = parse_args()
    script_path = pathlib.Path(args.script).resolve()
    output_path = pathlib.Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    spawn_pid_path = pathlib.Path(args.spawn_pid_file).resolve() if args.spawn_pid_file else None
    resume_gate_path = pathlib.Path(args.resume_gate_file).resolve() if args.resume_gate_file else None
    if spawn_pid_path is not None:
        spawn_pid_path.parent.mkdir(parents=True, exist_ok=True)
        spawn_pid_path.unlink(missing_ok=True)
    if resume_gate_path is not None:
        resume_gate_path.parent.mkdir(parents=True, exist_ok=True)
        resume_gate_path.unlink(missing_ok=True)

    if not script_path.is_file():
        raise SystemExit(f"Frida script not found: {script_path}")

    source = script_path.read_text(encoding="utf-8")
    device = get_device(args.serial, args.host)
    spawned_pid: int | None = None

    if args.pid is not None:
        session = device.attach(args.pid)
    elif args.attach:
        session = device.attach(args.package)
    else:
        spawned_pid = device.spawn([args.package])
        session = device.attach(spawned_pid)

    with output_path.open("a", encoding="utf-8") as stream:
        def write_record(record: dict) -> None:
            record.setdefault("collector_time", time.time())
            stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n")
            stream.flush()
            print(json.dumps(record, ensure_ascii=False))

        def on_message(message, data) -> None:
            if message.get("type") == "send" and isinstance(message.get("payload"), dict):
                write_record({"source": "agent", **message["payload"]})
                return
            write_record(
                {
                    "source": "frida",
                    "event": "message",
                    "message": message,
                    "binary_data_present": data is not None,
                }
            )

        script = session.create_script(source)
        script.on("message", on_message)
        script.load()

        if spawned_pid is not None:
            if spawn_pid_path is not None:
                spawn_pid_path.write_text(str(spawned_pid), encoding="ascii")
            if resume_gate_path is not None:
                write_record(
                    {
                        "source": "collector",
                        "event": "spawn_paused",
                        "package": args.package,
                        "spawned_pid": spawned_pid,
                        "resume_gate_file": str(resume_gate_path),
                    }
                )
                while not resume_gate_path.exists():
                    time.sleep(0.05)
            device.resume(spawned_pid)

        write_record(
            {
                "source": "collector",
                "event": "started",
                "package": args.package,
                "spawned": spawned_pid is not None,
                "spawned_pid": spawned_pid,
                "attached_pid": args.pid,
                "script": str(script_path),
            }
        )

        stopped = False

        def request_stop(signum, frame) -> None:  # noqa: ARG001
            nonlocal stopped
            stopped = True

        old_sigint = signal.signal(signal.SIGINT, request_stop)
        old_sigterm = signal.signal(signal.SIGTERM, request_stop)
        try:
            while not stopped:
                time.sleep(0.2)
        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)
            write_record({"source": "collector", "event": "stopped"})
            try:
                script.unload()
            except Exception:
                pass
            session.detach()

    print(f"Trace saved to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
