"""Helpers shared by the system tests."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from rugix_testkit import VMHandle

BASE_PAGE = "Rugix test system: base"
"""Marker on the web page of `customized-amd64`."""

UPDATE_PAGE = "Rugix test system: update"
"""Marker on the web page of `customized-amd64-delta`, which differs only in it."""


def web_page(vm: VMHandle) -> str:
    """Return the web page that nginx serves on the VM, waiting for nginx."""
    command = ["curl", "--silent", "--fail", "http://localhost/"]
    wait_until(lambda: vm.run(command, check=False, hide=True).ok, "nginx serves")
    return vm.run(command, hide=True).stdout


def exists(vm: VMHandle, path: str) -> bool:
    """Return whether *path* exists on the VM."""
    return vm.run(["test", "-e", path], check=False, hide=True).ok


def trust_test_root(vm: VMHandle) -> None:
    """Configure Rugix Ctrl to verify bundles with the test root certificate."""
    config = '[signatures]\nroots = ["/etc/rugix/root.crt"]\n'
    vm.run(["sh", "-c", f"printf '%s' '{config}' >/etc/rugix/ctrl.toml"], hide=True)


def wait_until(
    condition: Callable[[], bool], description: str, *, timeout: float = 60
) -> None:
    """Poll *condition* every second until it holds or *timeout* expires."""
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise TimeoutError(
                f"timed out after {timeout}s waiting until {description}"
            )
        time.sleep(1)


def apps(vm: VMHandle) -> dict[str, Any]:
    """Return the output of ``rugix-ctrl apps list``."""
    return vm.run_json(["rugix-ctrl", "apps", "list"])


def app_info(vm: VMHandle, app: str) -> Any:
    """Return the output of ``rugix-ctrl apps info``."""
    return vm.run_json(["rugix-ctrl", "apps", "info", app])


def app_logs(vm: VMHandle, app: str, *args: str) -> list[Any]:
    """Return the log records that ``rugix-ctrl apps logs --json`` prints."""
    output = vm.run(
        ["rugix-ctrl", "apps", "logs", app, "--json", *args], hide=True
    ).stdout
    return [json.loads(line) for line in output.splitlines()]


def app_state(vm: VMHandle, app: str) -> str | None:
    """Return the workload state of *app*, or ``None`` if it is not installed."""
    entry = apps(vm).get(app)
    return None if entry is None else entry["status"]["state"]


def wait_for_app_state(
    vm: VMHandle, app: str, state: str, *, timeout: float = 60
) -> None:
    """Wait until the workload of *app* reaches *state*."""
    wait_until(
        lambda: app_state(vm, app) == state, f"{app} is {state}", timeout=timeout
    )


def install_app(vm: VMHandle, url: str) -> None:
    """Install an unsigned app bundle from *url*."""
    vm.run(
        ["rugix-ctrl", "apps", "install", "--insecure-skip-bundle-verification", url],
        timeout=600,
        hide=True,
    )
