"""Docker Compose apps run from images that Rugix Ctrl keeps in its store.

Deactivation and removal remove the app's Rugix-owned image tags from Docker.
The bundled images stay in the content-addressed store, so reactivation loads
them from there. The logs of the app are the output of its containers.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from rugix_testkit import Bundler, VMHandle

from support import app_logs, apps, install_app, wait_for_app_state, wait_until

APP_NAME = "website"
APP_IMAGE_PREFIX = f"localhost/rugix-apps/{APP_NAME}/"
URL = "http://localhost:8080/"
EXPECTED_BODY = "Hello from Rugix Apps"


@pytest.fixture
def boot_system() -> str:
    return "customized-amd64-docker"


@pytest.fixture
def boot_timeout() -> float:
    return 600.0


@pytest.fixture(scope="module")
def website_bundle(bundler: Bundler, rugix_project: Path) -> Path:
    output = rugix_project / "apps" / "build" / "docker-compose-website_amd64.rugixb"
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    bundler.apps_pack(
        "docker-compose",
        [
            "--pull",
            "--platform",
            "linux/amd64",
            "--app",
            APP_NAME,
            "--include",
            "apps/docker-compose-website/www",
        ],
        rugix_project / "apps" / "docker-compose-website" / "docker-compose.yml",
        output,
    )
    return output


def test_apps_docker_compose(
    vm: VMHandle,
    website_bundle: Path,
    bundle_url: Callable[[Path], str],
) -> None:
    """Install the app, which serves a web page, and keep its images in the
    content-addressed store across generations, reboots, and reactivation."""
    assert apps(vm) == {}

    install_app(vm, bundle_url(website_bundle))
    wait_for_app_state(vm, APP_NAME, "running")
    assert apps(vm)[APP_NAME]["generation"] == 1
    assert _app_images(vm) != []

    files = json.loads(
        vm.run(["rugix-ctrl", "apps", "files", APP_NAME], hide=True).stdout
    )
    images = [file for file in files if file["path"].startswith("images/")]
    assert images and all("object" in image for image in images)
    store = vm.run_json(["rugix-ctrl", "store", "info"])
    stored, referenced = store["storedSize"], store["referencedSize"]
    assert store["refs"] == len(images)
    # The store keeps the content in compressed chunks.
    assert (
        isinstance(stored, int) and isinstance(referenced, int) and stored < referenced
    )
    assert vm.run_json(["rugix-ctrl", "store", "verify"])["problems"] == []

    _wait_until_serving(vm)

    vm.run(["rugix-ctrl", "apps", "deactivate", APP_NAME], hide=True)
    wait_for_app_state(vm, APP_NAME, "stopped")
    assert _app_images(vm) == []

    vm.run(["rugix-ctrl", "apps", "activate", APP_NAME, "1"], hide=True)
    _wait_until_serving(vm)

    vm.reboot()
    wait_until(
        lambda: vm.run(["docker", "info"], check=False, hide=True).ok,
        "Docker is running",
        timeout=300,
    )
    wait_for_app_state(vm, APP_NAME, "running")
    _wait_until_serving(vm)

    # A second generation with the same images shares all stored content.
    install_app(vm, bundle_url(website_bundle))
    assert apps(vm)[APP_NAME]["generation"] == 2
    _wait_until_serving(vm)
    store_after_update = vm.run_json(["rugix-ctrl", "store", "info"])
    assert store_after_update["refs"] == 2 * len(images)
    assert store_after_update["storedSize"] == stored

    vm.run(["rugix-ctrl", "apps", "remove", APP_NAME], hide=True)
    assert apps(vm) == {}
    assert _app_images(vm) == []
    store = vm.run_json(["rugix-ctrl", "store", "info"])
    assert (store["refs"], store["objects"], store["chunks"]) == (0, 0, 0)


def test_apps_docker_compose_logs(
    vm: VMHandle,
    website_bundle: Path,
    bundle_url: Callable[[Path], str],
) -> None:
    """The logs of the app contain the output of its containers by service,
    stream, and generation, also after the containers stopped."""
    install_app(vm, bundle_url(website_bundle))
    _wait_until_serving(vm)
    wait_until(
        lambda: any(
            "GET / HTTP" in record["message"] for record in app_logs(vm, APP_NAME)
        ),
        "the request is in the logs",
    )
    vm.run(["rugix-ctrl", "apps", "stop", APP_NAME], hide=True)
    wait_for_app_state(vm, APP_NAME, "stopped")

    records = app_logs(vm, APP_NAME)
    assert {(record["source"], record["generation"]) for record in records} == {
        ("web", 1)
    }
    assert {record["stream"] for record in records} == {"stdout", "stderr"}
    [request] = [record for record in records if "GET / HTTP" in record["message"]]
    assert request["stream"] == "stdout"


def _wait_until_serving(vm: VMHandle) -> None:
    def serving() -> bool:
        page = vm.run(["curl", "--silent", "--fail", URL], check=False, hide=True)
        return page.ok and EXPECTED_BODY in page.stdout

    wait_until(serving, f"{APP_NAME} serves its page")


def _app_images(vm: VMHandle) -> list[str]:
    output = vm.run(
        ["docker", "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"], hide=True
    ).stdout
    return [image for image in output.split() if image.startswith(APP_IMAGE_PREFIX)]
