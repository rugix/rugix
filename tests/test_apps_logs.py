"""Rugix Ctrl reads the logs of binary and generic apps.

The workload of the ``binary-logs`` app writes a plain and a JSON log line to
the journal. The orchestrator script of the ``generic-logs`` app writes the same
kinds of lines to a file when it starts the workload, and its ``logs``
operation prints them. Both apps declare JSON logs.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from rugix_testkit import Bundler, VMHandle

from support import app_logs, install_app, wait_for_app_state, wait_until

BINARY_APP = "binary-logs"
GENERIC_APP = "generic-logs"


@pytest.fixture
def boot_system() -> str:
    return "customized-amd64-apps"


@pytest.fixture(scope="module")
def binary_app_bundle(bundler: Bundler, rugix_project: Path) -> Path:
    output = rugix_project / "apps" / "build" / "binary-logs_amd64.rugixb"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    return bundler.apps_pack(
        "binary",
        [
            *["--app", BINARY_APP, "--log-format", "json"],
            *["--service", "apps/binary-logs/log-writer.service"],
        ],
        rugix_project / "apps" / "binary-logs" / "log-writer",
        output,
    )


@pytest.fixture(scope="module")
def generic_app_bundle(bundler: Bundler, rugix_project: Path) -> Path:
    output = rugix_project / "apps" / "build" / "generic-logs_amd64.rugixb"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.unlink(missing_ok=True)
    return bundler.apps_pack(
        "generic",
        ["--app", GENERIC_APP, "--log-format", "json"],
        rugix_project / "apps" / "generic-logs" / "orchestrator",
        output,
    )


def test_binary_app_logs(
    vm: VMHandle, binary_app_bundle: Path, bundle_url: Callable[[Path], str]
) -> None:
    """The logs of a binary app contain the lines of its workload, with JSON
    lines as structured records, and systemd's messages about its unit. Records
    name the generation that produced them, and the line limit keeps the most
    recent records."""
    install_app(vm, bundle_url(binary_app_bundle))
    wait_for_app_state(vm, BINARY_APP, "running")
    wait_until(
        lambda: any(
            record["message"] == "structured hello"
            for record in app_logs(vm, BINARY_APP)
        ),
        "the structured line is in the logs",
    )

    records = app_logs(vm, BINARY_APP)
    workload = [record for record in records if record.get("source") == "log-writer"]
    assert [
        (record["message"], record["severity"], record.get("fields"))
        for record in workload
    ] == [
        ("plain hello", "info", None),
        ("structured hello", "warning", {"answer": 42}),
    ]
    assert all(record["generation"] == 1 for record in workload)
    assert any(
        record.get("source") == "systemd" and "Started" in record["message"]
        for record in records
    )
    assert app_logs(vm, BINARY_APP, "--lines", "1") == records[-1:]

    text = vm.run(["rugix-ctrl", "apps", "logs", BINARY_APP], hide=True).stdout
    assert "log-writer WARNING structured hello answer=42" in text


def test_generic_app_logs(
    vm: VMHandle, generic_app_bundle: Path, bundle_url: Callable[[Path], str]
) -> None:
    """The logs of a generic app are the records and lines that the `logs`
    operation of its orchestrator script prints. Rugix Ctrl interprets JSON
    lines and keeps no more records than requested, even if the script prints
    more."""
    install_app(vm, bundle_url(generic_app_bundle))
    wait_for_app_state(vm, GENERIC_APP, "running")

    assert [
        (record.get("source"), record["message"], record.get("severity"))
        for record in app_logs(vm, GENERIC_APP)
    ] == [
        ("script", "script record", None),
        (None, "plain line", None),
        (None, "json line", "error"),
    ]
    assert [
        record["message"] for record in app_logs(vm, GENERIC_APP, "--lines", "2")
    ] == [
        "plain line",
        "json line",
    ]
