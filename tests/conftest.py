"""Fixtures for the Rugix Ctrl and Rugix Bundler system tests."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tarfile
from collections.abc import Callable
from pathlib import Path

import pytest
from rugix_testkit import (
    BakeryBuilder,
    Bundler,
    Parameters,
    QemuVM,
    VMConfig,
    VMHandle,
)
from rugix_testkit.locks import exclusive_lock

OUTDATED_CTRL = "the VM runs an outdated Rugix Ctrl, delete `.rugix/` and retry"

REPOSITORY_DIR = Path(__file__).resolve().parent.parent


def pytest_configure(config: pytest.Config) -> None:
    # Bakery installs Rugix Ctrl from these binaries and the tests run Bundler
    # from them.
    binaries = REPOSITORY_DIR / "build" / "binaries"
    if binaries.is_dir():
        os.environ.setdefault("RUGIX_BINARIES_DIR", str(binaries))
    if not os.environ.get("RUGIX_BINARIES_DIR"):
        raise pytest.UsageError(
            "no Rugix build to test: build one with "
            "`mise run build x86_64-unknown-linux-musl` or set RUGIX_BINARIES_DIR"
        )


@pytest.fixture(scope="session")
def ctrl_build_digests() -> set[str]:
    """SHA-256 digests of the Rugix Ctrl builds under test."""
    binaries = Path(os.environ["RUGIX_BINARIES_DIR"])
    return {
        hashlib.sha256(path.read_bytes()).hexdigest()
        for path in binaries.glob("x86_64-*/rugix-ctrl")
    }


@pytest.fixture
def start_vm(
    start_vm: Callable[[VMConfig], VMHandle], ctrl_build_digests: set[str]
) -> Callable[[VMConfig], VMHandle]:
    """Starts VMs and checks that they run a Rugix Ctrl build under test.

    Bakery does not rebuild cached layers when the mounted binaries change.
    """

    def start(config: VMConfig) -> VMHandle:
        vm = start_vm(config)
        output = vm.run(["sha256sum", "/usr/bin/rugix-ctrl"], hide=True).stdout
        if output.split()[0] not in ctrl_build_digests:
            pytest.fail(OUTDATED_CTRL)
        return vm

    return start


@pytest.fixture
def start_qemu(
    start_qemu: Callable[[VMConfig], QemuVM],
    ctrl_build_digests: set[str],
    rugix_project: Path,
) -> Callable[[VMConfig], QemuVM]:
    """Starts VMs without SSH after checking the image's Rugix Ctrl build.

    Only use it for systems without bundles, because baking a bundle rewrites
    the inspected archive.
    """

    def start(config: VMConfig) -> QemuVM:
        system_archive = (
            rugix_project
            / "build"
            / config.drives[0].file.parent.name
            / "filesystems"
            / "partition-4.tar"
        )
        with tarfile.open(system_archive) as archive:
            binary = archive.extractfile("./usr/bin/rugix-ctrl")
            assert binary is not None
            if hashlib.sha256(binary.read()).hexdigest() not in ctrl_build_digests:
                pytest.fail(OUTDATED_CTRL)
        return start_qemu(config)

    return start


@pytest.fixture(scope="session")
def update_keys(rugix_project: Path) -> Path:
    """Directory with update certificates and the signer's key.

    ``root.crt`` issues ``signer.crt``. ``other-root.crt`` is an unrelated root.
    """
    keys = rugix_project / "keys"
    with exclusive_lock(keys / ".lock"):
        if not (keys / "signer.crt").exists():
            _generate_update_keys(keys)
    return keys


@pytest.fixture(scope="session")
def bakery_parameters(update_keys: Path) -> Parameters:
    return {
        # Install the Rugix Ctrl build under test in every layer.
        "core/rugix-ctrl": {"version": "container"},
        "install-root-certs": {
            "root_crt": (update_keys / "root.crt").read_text(),
            "other_root_crt": (update_keys / "other-root.crt").read_text(),
        },
    }


@pytest.fixture(scope="session")
def signed_bundle(
    bakery: BakeryBuilder,
    bundler: Bundler,
    rugix_project: Path,
    update_keys: Path,
    worker_id: str,
) -> Path:
    """The `customized-amd64` bundle signed by ``signer.crt``."""
    # Workers sign concurrently, so each writes its own file.
    output = rugix_project / "build" / f"signed-{worker_id}.rugixb"
    return bundler.sign(
        bakery.bake_bundle("customized-amd64"),
        update_keys / "signer.crt",
        update_keys / "signer.key",
        output,
    )


def _generate_update_keys(keys: Path) -> None:
    keys.mkdir(parents=True, exist_ok=True)
    ec_key = ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out"]
    for root in ("root", "other-root"):
        _openssl(keys, *ec_key, f"{root}.key")
        _openssl(
            keys,
            *["req", "-x509", "-new", "-key", f"{root}.key", "-out", f"{root}.crt"],
            *["-days", "3650", "-subj", "/CN=Update CA"],
        )
    _openssl(keys, *ec_key, "signer.key")
    _openssl(
        keys,
        *["req", "-new", "-key", "signer.key", "-out", "signer.csr"],
        *["-subj", "/CN=Update Signer"],
    )
    (keys / "signer.ext").write_text(
        "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n"
    )
    _openssl(
        keys,
        *["x509", "-req", "-in", "signer.csr", "-CA", "root.crt", "-CAkey", "root.key"],
        *["-CAcreateserial", "-out", "signer.crt", "-days", "3650"],
        *["-extfile", "signer.ext"],
    )


def _openssl(keys: Path, *args: str) -> None:
    subprocess.run(["openssl", *args], cwd=keys, check=True, capture_output=True)
