#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path


def main() -> int:
    fake_dir = os.environ.get("RUGIX_ADMIN_FAKE_DIR")
    if not fake_dir:
        print("RUGIX_ADMIN_FAKE_DIR is not set", file=sys.stderr)
        return 2

    state = Path(fake_dir)
    args = sys.argv[1:]
    record(state, "commands.jsonl", {"timestamp": now(), "args": args})

    if args == ["system", "info", "--json"]:
        write_json(
            {
                "boot": {
                    "bootFlow": "grub",
                    "activeGroup": "a",
                    "defaultGroup": "a",
                },
                "state": {"status": "clean"},
                "slots": {
                    "system-a": {"bootGroup": "a", "status": "active"},
                    "system-b": {"bootGroup": "b", "status": "spare"},
                },
            }
        )
        return 0

    if args == ["components", "check"]:
        write_json(
            {
                "roots": [
                    {"kind": "System", "path": "/usr/share/rugix/components"},
                    {
                        "kind": "App",
                        "path": "/var/lib/rugix/apps/telemetry/2/components",
                        "app": "telemetry",
                        "generation": 2,
                    },
                ],
                "components": [
                    {
                        "source": {
                            "kind": "System",
                            "path": "/usr/share/rugix/components/core.toml",
                        },
                        "component": {
                            "id": "com.example.core",
                            "version": "1.0.0",
                            "provides": [{"id": "network", "version": "1"}],
                            "claims": [{"id": "system.root"}],
                            "requires": [],
                            "conflicts": [],
                        },
                    },
                    {
                        "source": {
                            "kind": "App",
                            "path": "/var/lib/rugix/apps/telemetry/2/components/app.toml",
                            "app": "telemetry",
                            "generation": 2,
                        },
                        "component": {
                            "id": "com.example.telemetry",
                            "version": "2.0.0",
                            "provides": [{"id": "telemetry.publisher"}],
                            "claims": [],
                            "requires": [{"id": "network"}],
                            "conflicts": [],
                        },
                    },
                ],
                "consistent": True,
                "problems": [],
            }
        )
        return 0

    if args == ["apps", "list"]:
        write_json(
            {
                "telemetry": {
                    "status": {"state": "running"},
                    "generation": 2,
                    "metadata": {"label": "Telemetry"},
                },
                "logger": {
                    "status": {"state": "stopped"},
                    "generation": 1,
                    "metadata": {"label": "Logger"},
                },
            }
        )
        return 0

    if len(args) == 3 and args[:2] == ["apps", "info"]:
        write_json(app_info(args[2]))
        return 0

    if is_url_update_command(args):
        print("fake system update download started")
        write_json({"event": "UpdateProgress", "progress": 12.4})
        print("fake system update install running")
        write_json({"event": "UpdateProgress", "progress": 100.0})
        return 0

    if is_upload_command(args):
        early_exit = state / "early-exit-next-upload"
        if early_exit.exists():
            early_exit.unlink()
            kind = "system-update" if args[0] == "update" else "app-install"
            record(
                state,
                "early-exits.jsonl",
                {
                    "timestamp": now(),
                    "kind": kind,
                    "args": args,
                },
            )
            print(f"fake {kind} failed before reading stdin", file=sys.stderr)
            return 23

        payload = sys.stdin.buffer.read()
        kind = "system-update" if args[0] == "update" else "app-install"
        record(
            state,
            "uploads.jsonl",
            {
                "timestamp": now(),
                "kind": kind,
                "args": args,
                "bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            },
        )
        print(f"fake {kind} received {len(payload)} bytes")
        return 0

    print(f"fake rugix-ctrl ran: {' '.join(args)}")
    return 0


def app_info(name: str) -> dict:
    created = "2026-06-25T12:00:00Z"
    previous = "2026-06-24T12:00:00Z"
    active_generation = 1 if name == "logger" else 2
    generations = [
        {
            "number": active_generation,
            "createdAt": created,
            "complete": True,
            "active": True,
            "lastActivated": created,
            "metadata": {"label": name},
        }
    ]
    if active_generation > 1:
        generations.append(
            {
                "number": active_generation - 1,
                "createdAt": previous,
                "complete": True,
                "active": False,
                "lastActivated": previous,
                "metadata": {"label": f"{name} previous"},
            }
        )
    return {
        "name": name,
        "status": {"state": "stopped" if name == "logger" else "running"},
        "state": {"state": "active", "generation": active_generation},
        "generations": generations,
    }


def is_url_update_command(args: list[str]) -> bool:
    return bool(args and args[0:2] == ["update", "install"] and args[-1].startswith(("http://", "https://")))


def is_upload_command(args: list[str]) -> bool:
    return bool(
        args
        and args[-1] == "-"
        and (
            args[:2] == ["update", "install"]
            or args[:2] == ["apps", "install"]
        )
    )


def write_json(value: object) -> None:
    print(json.dumps(value, separators=(",", ":")))


def record(state: Path, file_name: str, value: object) -> None:
    state.mkdir(parents=True, exist_ok=True)
    with (state / file_name).open("a", encoding="utf-8") as file:
        file.write(json.dumps(value, separators=(",", ":")) + "\n")


def now() -> str:
    return datetime.now(tz=UTC).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
