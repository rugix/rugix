"""Shared pytest fixtures for Rugix Admin browser tests."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen

import pytest


TESTS_ROOT = Path(__file__).resolve().parent
FRONTEND_ROOT = TESTS_ROOT.parent
ADMIN_ROOT = FRONTEND_ROOT.parent
RUGIX_ROOT = ADMIN_ROOT.parents[2]


@dataclass(frozen=True)
class AdminServer:
    frontend_url: str
    fake_dir: Path


@pytest.fixture(scope="session")
def browser_context_args(browser_context_args: dict) -> dict:
    return {
        **browser_context_args,
        "viewport": {"width": 1400, "height": 787},
        "device_scale_factor": 2,
    }


@pytest.fixture(scope="session")
def browser_type_launch_args(browser_type_launch_args: dict) -> dict:
    browsers_root = os.environ.get("RUGIX_ADMIN_TESTS_PLAYWRIGHT_BROWSERS")
    if not browsers_root:
        return browser_type_launch_args

    matches = sorted(Path(browsers_root).glob("chromium-*/chrome-linux64/chrome"))
    if not matches:
        matches = sorted(
            Path(browsers_root).glob(
                "chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell"
            )
        )
    if not matches:
        raise RuntimeError(
            f"no chromium under {browsers_root} - run `pnpm run test:e2e:browsers`"
        )
    return {**browser_type_launch_args, "executable_path": str(matches[-1])}


@pytest.fixture(scope="session")
def admin_server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[AdminServer]:
    work_dir = tmp_path_factory.mktemp("rugix-admin-e2e")
    fake_dir = work_dir / "fake"
    bin_dir = work_dir / "bin"
    log_dir = work_dir / "logs"
    fake_dir.mkdir()
    bin_dir.mkdir()
    log_dir.mkdir()
    (fake_dir / "commands.jsonl").write_text("")
    (fake_dir / "uploads.jsonl").write_text("")

    fake_script = TESTS_ROOT / "fixtures" / "fake_rugix_ctrl.py"
    fake_target = bin_dir / "rugix-ctrl"
    shutil.copy2(fake_script, fake_target)
    fake_target.chmod(0o755)

    admin_port = _free_port()
    frontend_port = _free_port()
    admin_address = f"127.0.0.1:{admin_port}"
    admin_url = f"http://{admin_address}"
    frontend_url = f"http://127.0.0.1:{frontend_port}"

    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "RUGIX_ADMIN_FAKE_DIR": str(fake_dir),
    }

    processes: list[subprocess.Popen] = []
    try:
        admin_log = (log_dir / "rugix-admin.log").open("wb")
        admin = subprocess.Popen(
            ["cargo", "run", "-p", "rugix-admin", "--", "--address", admin_address],
            cwd=RUGIX_ROOT,
            env=env,
            stdout=admin_log,
            stderr=subprocess.STDOUT,
        )
        processes.append(admin)
        _wait_for_url(f"{admin_url}/api/health", admin, timeout=150)

        vite_log = (log_dir / "vite.log").open("wb")
        vite = subprocess.Popen(
            [
                "pnpm",
                "exec",
                "vite",
                "--host",
                "127.0.0.1",
                "--port",
                str(frontend_port),
                "--strictPort",
            ],
            cwd=FRONTEND_ROOT,
            env={**env, "RUGIX_ADMIN_API_TARGET": admin_url},
            stdout=vite_log,
            stderr=subprocess.STDOUT,
        )
        processes.append(vite)
        _wait_for_url(frontend_url, vite, timeout=60)

        yield AdminServer(frontend_url=frontend_url, fake_dir=fake_dir)
    finally:
        for process in reversed(processes):
            _terminate(process)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def wait_for_upload(fake_dir: Path, kind: str, timeout: float = 10) -> dict:
    deadline = time.monotonic() + timeout
    uploads: list[dict] = []
    while time.monotonic() < deadline:
        uploads = read_jsonl(fake_dir / "uploads.jsonl")
        for upload in reversed(uploads):
            if upload.get("kind") == kind:
                return upload
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for {kind} upload; saw {uploads!r}")


def wait_for_command(fake_dir: Path, args: list[str], timeout: float = 10) -> dict:
    deadline = time.monotonic() + timeout
    commands: list[dict] = []
    while time.monotonic() < deadline:
        commands = read_jsonl(fake_dir / "commands.jsonl")
        for command in reversed(commands):
            if command.get("args") == args:
                return command
        time.sleep(0.1)
    raise AssertionError(f"timed out waiting for command {args!r}; saw {commands!r}")


def screenshot_path(request: pytest.FixtureRequest, name: str) -> Path:
    safe_name = (
        request.node.nodeid.replace("::", "--")
        .replace("/", "--")
        .replace("\\", "--")
    )
    path = TESTS_ROOT / "test-results" / safe_name / "screens" / f"{name}.png"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_url(url: str, process: subprocess.Popen, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{process.args!r} exited with {process.returncode}")
        try:
            with urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return
        except Exception as error:
            last_error = error
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {url}: {last_error}")


def _terminate(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
