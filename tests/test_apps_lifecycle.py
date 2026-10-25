"""Rugix Ctrl manages the lifecycle of binary and generic apps.

The ``hello-binary`` app runs as a systemd service that writes a marker file
and keeps running. The orchestrator script of the ``hello-generic`` app starts
a background process and writes a marker file while it runs.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from rugix_testkit import Bundler, VMHandle

from support import app_info, apps, exists, install_app, wait_for_app_state

BINARY_APP = "hello-binary"
GENERIC_APP = "hello-generic"
APPS = {BINARY_APP: "binary", GENERIC_APP: "generic"}
BINARY_SERVICE = f"rugix-app-{BINARY_APP}.service"


@pytest.fixture
def boot_system() -> str:
    return "customized-amd64-apps"


@pytest.fixture(scope="module")
def binary_app_bundle(bundler: Bundler, rugix_project: Path) -> Path:
    output = rugix_project / "apps" / "build" / "binary-hello_amd64.rugixb"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    return bundler.apps_pack(
        "binary",
        ["--app", BINARY_APP, "--service", "apps/binary-hello/hello-server.service"],
        rugix_project / "apps" / "binary-hello" / "hello-server",
        output,
    )


@pytest.fixture(scope="module")
def generic_app_bundle(bundler: Bundler, rugix_project: Path) -> Path:
    output = rugix_project / "apps" / "build" / "generic-hello_amd64.rugixb"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    return bundler.apps_pack(
        "generic",
        ["--app", GENERIC_APP],
        rugix_project / "apps" / "generic-hello" / "orchestrator",
        output,
    )


def test_app_lifecycle(
    vm: VMHandle,
    binary_app_bundle: Path,
    generic_app_bundle: Path,
    bundle_url: Callable[[Path], str],
) -> None:
    """Installed apps run their workloads. Deactivating an app stops it and
    clears its generation, while stopping it keeps the generation. Activated
    and started apps run again, the binary app also after a reboot. Removing
    the apps removes them from the list."""
    assert apps(vm) == {}

    install_app(vm, bundle_url(binary_app_bundle))
    install_app(vm, bundle_url(generic_app_bundle))
    for app, orchestrator in APPS.items():
        wait_for_app_state(vm, app, "running")
        assert exists(vm, _marker(app))
        info = app_info(vm, app)
        assert info["orchestrator"] == orchestrator
        assert (info["lifecycle"]["state"], info["lifecycle"]["generation"]) == (
            "active",
            1,
        )
        assert [entry["active"] for entry in info["generations"]] == [True]
    vm.run(["systemctl", "is-active", BINARY_SERVICE], hide=True)

    for app in APPS:
        _apps_command(vm, "deactivate", app)
        wait_for_app_state(vm, app, "stopped")
        assert apps(vm)[app].get("generation") is None
        assert not exists(vm, _marker(app))

        _apps_command(vm, "activate", app, "1")
        wait_for_app_state(vm, app, "running")

        _apps_command(vm, "stop", app)
        wait_for_app_state(vm, app, "stopped")
        assert apps(vm)[app]["generation"] == 1

        _apps_command(vm, "start", app)
        wait_for_app_state(vm, app, "running")

    vm.reboot()
    wait_for_app_state(vm, BINARY_APP, "running")
    vm.run(["systemctl", "is-active", BINARY_SERVICE], hide=True)
    assert apps(vm)[BINARY_APP]["generation"] == 1

    for app in APPS:
        _apps_command(vm, "remove", app)
    assert apps(vm) == {}


def test_staged_app_install(
    vm: VMHandle, generic_app_bundle: Path, bundle_url: Callable[[Path], str]
) -> None:
    """An app installed with `--no-activate` stays inactive until it is activated,
    and garbage collection keeps it until then. Its generation reports the origin
    supplied at installation, also after the activation."""
    origin = {"source": "system-test", "version": "1.0.0"}
    vm.run(
        [
            "rugix-ctrl",
            "apps",
            "install",
            "--insecure-skip-bundle-verification",
            "--no-activate",
            "--origin",
            json.dumps(origin),
            bundle_url(generic_app_bundle),
        ],
        timeout=600,
        hide=True,
    )
    info = app_info(vm, GENERIC_APP)
    assert info["lifecycle"]["state"] == "inactive"
    [generation] = info["generations"]
    assert (generation["number"], generation["complete"], generation["active"]) == (
        1,
        True,
        False,
    )
    assert generation["origin"] == origin
    assert generation["staged"]
    assert not exists(vm, _marker(GENERIC_APP))

    _apps_command(vm, "gc", GENERIC_APP)
    assert [g["number"] for g in app_info(vm, GENERIC_APP)["generations"]] == [1]

    _apps_command(vm, "activate", GENERIC_APP, "1")
    wait_for_app_state(vm, GENERIC_APP, "running")
    [generation] = app_info(vm, GENERIC_APP)["generations"]
    assert generation["active"]
    assert generation["origin"] == origin

    _apps_command(vm, "remove", GENERIC_APP)


def _apps_command(vm: VMHandle, *args: str) -> None:
    vm.run(["rugix-ctrl", "apps", *args], hide=True)


def _marker(app: str) -> str:
    return f"/run/rugix/state/apps/{app}/data/running"
