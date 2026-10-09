#!/usr/bin/env python3
"""Exercise grant issuance, streaming installation, daemon admission, and replay recovery.

Requires built debug binaries, OpenSSL, and Linux user and mount namespaces.
All device paths are replaced inside a private namespace. No host root access is used.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time


REPO = Path(__file__).resolve().parents[1]
BUNDLER = REPO / "target/debug/rugix-bundler"
CTRL = REPO / "target/debug/rugix-ctrl"


def run(*args, success=True):
    """Run a real CLI and assert its exit status, retaining diagnostics on failure.

    Pass `success=None` to accept either outcome and assert on the output instead.
    """
    result = subprocess.run(
        [str(arg) for arg in args], capture_output=True, text=True, timeout=30
    )
    if success is not None and (result.returncode == 0) != success:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def timestamp(seconds):
    """Format deterministic whole-second CLI timestamps with an explicit UTC offset."""
    return datetime.fromtimestamp(seconds, timezone.utc).isoformat()


class Device:
    """One isolated device with its certificates, configuration, and bundles."""

    def __init__(self, directory):
        self.directory = directory
        self.state_dir = Path("/var/lib/rugix/grants")
        self.config_path = Path("/etc/rugix/ctrl.toml")
        self.identity_file = directory / "identity.json"
        self.identity = {"device": "device-1", "groups": ["canary"]}
        self.identity_file.write_text(json.dumps(self.identity))
        self.identity_helper = Path("/etc/rugix/grant-identity")
        self.helper_script = f"#!/bin/sh\ncat '{self.identity_file}'\n"
        self.identity_helper.write_text(self.helper_script)
        self.identity_helper.chmod(0o755)
        self.grant_root, self.grant_root_key = self.root("grant")
        self.publisher_root, self.publisher_root_key = self.root("publisher")
        self.publisher_cert, self.publisher_key = self.code_signing_cert(
            "publisher-signer", self.publisher_root, self.publisher_root_key
        )
        self.signer, self.signer_key = self.authority_cert(
            "deployment-signer", self.grant_root, self.grant_root_key,
            ["--any-audience", "--permission", "apps", "--permission", "system"],
        )
        self.bundle = self.app_bundle("grant-test", "app")
        self.other_bundle = self.app_bundle("other-app", "other")

    def root(self, name):
        """Create a self-signed certificate authority."""
        cert, key = self.directory / f"{name}-root.pem", self.directory / f"{name}-root.key"
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-subj", f"/CN={name} root", "-days", "2",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign",
            "-keyout", key, "-out", cert)
        return cert, key

    def code_signing_cert(self, name, parent, parent_key):
        """Issue an ordinary code-signing certificate, which cannot sign grants."""
        extensions = self.directory / f"{name}.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=codeSigning\n"
        )
        return self.issue(name, parent, parent_key, extensions, days="2")

    def authority_cert(self, name, parent, parent_key, scope, intermediate=None,
                       alter_extensions=None, days="1"):
        """Issue a grant authority certificate using Bundler's extension generator."""
        extensions = self.directory / f"{name}.ext"
        run(BUNDLER, "grants", "authority-extensions", "--namespace", "test", *scope,
            *(["--intermediate", str(intermediate)] if intermediate is not None else []),
            extensions)
        if alter_extensions:
            extensions.write_text(alter_extensions(extensions.read_text()))
        return self.issue(name, parent, parent_key, extensions, days=days)

    def issue(self, name, parent, parent_key, extensions, days):
        """Issue one certificate with the prepared extension file."""
        cert, key = self.directory / f"{name}.pem", self.directory / f"{name}.key"
        csr = self.directory / f"{name}.csr"
        run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-subj", f"/CN={name}", "-keyout", key, "-out", csr)
        run("openssl", "x509", "-req", "-in", csr, "-CA", parent, "-CAkey", parent_key,
            "-CAcreateserial", "-days", days, "-extfile", extensions, "-out", cert)
        return cert, key

    def app_bundle(self, app, name):
        """Pack an app bundle whose orchestrator records its activations."""
        script = self.directory / f"{name}-orchestrator"
        script.write_text(
            '#!/bin/sh\nif [ "$1" = "activate" ]; then\n'
            '    echo activated >> "$RUGIX_APP_DATA_DIR/activations"\nfi\nexit 0\n'
        )
        script.chmod(0o755)
        bundle = self.directory / f"{name}.rugixb"
        run(BUNDLER, "apps", "pack", "generic", "--app", app, script, bundle)
        return bundle

    def configure(self, authorities=None, mode=None, max_lifetime=86400, signatures=True):
        """Write a complete Ctrl configuration with the requested grant policy."""
        if authorities is None:
            authorities = [(self.grant_root, ["apps", "system"])]
        sections = []
        if signatures:
            sections.append(f'[signatures]\nroots = ["{self.publisher_root}"]\n')
        policy = [
            "[grants]",
            'namespace = "test"',
            f'identity-helper = "{self.identity_helper}"',
        ]
        if mode:
            policy.append(f'mode = "{mode}"')
        if not authorities:
            policy.append("authorities = []")
        sections.append("\n".join(policy) + "\n")
        for root, permissions in authorities:
            entry = [
                "[[grants.authorities]]",
                f'root = "{root}"',
                "permissions = [" + ", ".join(f'"{name}"' for name in permissions) + "]",
            ]
            if max_lifetime is not None:
                entry.append(f"max-lifetime = {max_lifetime}")
            sections.append("\n".join(entry) + "\n")
        self.config_path.write_text("\n".join(sections))

    def set_identity(self, **changes):
        """Replace the identity the helper reports."""
        self.identity_file.write_text(json.dumps(dict(self.identity, **changes)))

    def grant(self, name, target="apps", device="device-1", group=None, bundle=None,
              bundle_hash=None, start=None, end=None, options=(), signer=None,
              intermediates=(), success=True):
        """Issue a grant with Bundler and return its CMS file."""
        output = self.directory / f"{name}.cms"
        cert, key = signer or (self.signer, self.signer_key)
        audience = ["--group", group] if group else ["--device", device]
        source = (["--bundle-hash", bundle_hash] if bundle_hash
                  else ["--bundle", bundle or self.bundle])
        run(BUNDLER, "grants", "sign", *source, "--id", name,
            "--namespace", "test", *audience,
            *(["--not-before", timestamp(start)] if start is not None else []),
            "--expires-at", timestamp(end) if end is not None else "5m",
            "--target", target, *options,
            "--cert", cert, "--key", key,
            *[arg for path in intermediates for arg in ("--intermediate-cert", path)],
            output, success=success)
        return output

    def install(self, signature, bundle=None, success=True, extra=()):
        """Install an app bundle through the CLI."""
        args = [CTRL, "apps", "install", bundle or self.bundle]
        if signature:
            args += ["--grant", signature]
        return run(*args, *extra, success=success)

    def state(self):
        """Current durable replay state."""
        return json.loads((self.state_dir / "state.json").read_text())

    def record(self, grant_id):
        """Admitted record belonging to one grant identifier, if any."""
        return next(
            (record for record in self.state()["admitted"] if record["id"] == grant_id),
            None,
        )

    def activations(self, app="grant-test"):
        """Recorded activations of an installed app."""
        path = Path(f"/var/lib/rugix/apps/{app}/data/activations")
        return path.read_text().splitlines() if path.exists() else []


def test_configuration_errors(device):
    """A policy that could never authorize an installation is rejected at load time."""
    signature = device.grant("configuration-probe")

    def rejected(expected):
        result = device.install(signature, success=False)
        assert expected in result.stderr, result.stderr
        assert not (device.state_dir / "state.json").exists()

    device.configure(mode="embedded-and-grant", signatures=False)
    rejected("signatures.roots")
    device.configure(authorities=[])
    rejected("grants.authorities")
    device.config_path.write_text(
        '[grants]\nnamespace = "test"\nidentity-helper = "relative/path"\n'
        '[[grants.authorities]]\nroot = "/x.pem"\npermissions = ["apps"]\n'
    )
    rejected("identity-helper")
    device.configure()
    print("PASS: unenforceable grant policies are rejected when the configuration loads",
          flush=True)


def test_lazy_state_initialization(device):
    """Replay state appears on first use, private to the privileged executor."""
    assert not (device.state_dir / "state.json").exists()
    first = device.grant("first-install")
    device.install(first)
    assert oct(device.state_dir.stat().st_mode & 0o777) == "0o700"
    assert oct((device.state_dir / "lock").stat().st_mode & 0o777) == "0o600"
    assert device.record("first-install")["consumed"] is True
    device.install(first, success=False)
    # Deleting the state resets history, which is why the directory is private.
    (device.state_dir / "state.json").unlink()
    device.install(first)
    print("PASS: replay state is created on first use and kept private", flush=True)


def test_window_parsing(device):
    """Validity windows accept RFC 3339 and durations, and reject empty ranges."""
    def prepare(end, start=None, success=True):
        output = device.directory / "window.raw"
        output.unlink(missing_ok=True)
        run(BUNDLER, "grants", "prepare", "--bundle", device.bundle, "--id", "window",
            "--namespace", "test", "--device", "device-1",
            *(["--not-before", start] if start is not None else []),
            "--expires-at", end, "--target", "apps", output, success=success)
        if not success:
            assert not output.exists()
            return None
        prefix, payload = output.read_bytes().split(b"\0", 1)
        assert prefix == b"rugix.operation-grant.v1"
        content = json.loads(payload)
        assert content["service"] == "rugix-ctrl"
        assert content["audience"]["target"] == {"recipient": "device-1"}
        return content

    for duration in ["5m", "PT5M"]:
        before = int(time.time())
        window = prepare(duration)
        assert before <= int(window["notBefore"]) <= int(time.time())
        assert int(window["expiresAt"]) - int(window["notBefore"]) == 300
    now = int(time.time())
    offset_start = datetime.fromtimestamp(now, timezone(timedelta(hours=5, minutes=30)))
    window = prepare(timestamp(now + 60), offset_start.isoformat())
    assert int(window["notBefore"]) == now
    assert int(window["expiresAt"]) == now + 60
    window = prepare(timestamp(now + 60).replace("+00:00", ".875Z"),
                     timestamp(now).replace("+00:00", ".125Z"))
    assert int(window["notBefore"]) == now
    assert int(window["expiresAt"]) == now + 60
    prepare(timestamp(now).replace("+00:00", ".875Z"),
            timestamp(now).replace("+00:00", ".125Z"), success=False)
    # Relative expiry is measured from now, even when the start is explicitly later.
    before = int(time.time())
    window = prepare("2m", timestamp(before + 60))
    assert before + 120 <= int(window["expiresAt"]) <= int(time.time()) + 120
    for end in ["not a time", "1700000000", "0s", "-1h", "999999999999999h"]:
        prepare(end, success=False)
    prepare("1h", "1969-12-31T23:59:59Z", success=False)
    prepare(timestamp(now), timestamp(now + 1), success=False)
    print("PASS: RFC 3339 offsets, relative expiry, default start, and invalid windows",
          flush=True)


def test_hash_only_issuance(device):
    """A trusted hash is enough to issue, verify, and install a grant."""
    digest = run(BUNDLER, "hash", device.bundle).stdout.strip()
    signature = device.grant("hash-only", bundle_hash=digest)
    run(BUNDLER, "grants", "verify", signature, "--root-cert", device.grant_root,
        "--namespace", "test", "--device", "device-1", "--bundle-hash", digest)
    output = run(BUNDLER, "grants", "verify", signature, "--root-cert", device.grant_root,
                 "--namespace", "test", "--device", "device-1",
                 "--bundle", device.bundle).stdout
    assert json.loads(output)["operation"]["bundleHash"] == digest
    run(BUNDLER, "grants", "sign", "--bundle", device.bundle, "--bundle-hash", digest,
        "--id", "both", "--namespace", "test", "--device", "device-1",
        "--expires-at", "5m", "--target", "apps", "--cert", device.signer,
        "--key", device.signer_key, device.directory / "both.cms", success=False)
    device.install(signature)
    wrong = device.grant("hash-mismatch", bundle_hash=run(
        BUNDLER, "hash", device.other_bundle).stdout.strip())
    device.install(wrong, success=False)
    # Verification needs a time inside the window, which --at supplies.
    scheduled = device.grant("scheduled-inspection", bundle_hash=digest,
                             start=int(time.time()) + 300, end=int(time.time()) + 600)
    run(BUNDLER, "grants", "verify", scheduled, "--root-cert", device.grant_root,
        "--namespace", "test", "--device", "device-1", "--bundle-hash", digest,
        success=False)
    run(BUNDLER, "grants", "verify", scheduled, "--root-cert", device.grant_root,
        "--namespace", "test", "--device", "device-1", "--bundle-hash", digest,
        "--at", timestamp(int(time.time()) + 450))
    print("PASS: grants can be issued, verified, and installed from a bundle hash",
          flush=True)


def test_grant_bindings(device):
    """A grant binds the bundle, the device audience, and its validity window."""
    good = device.grant("first")
    run(BUNDLER, "grants", "verify", good, "--root-cert", device.grant_root,
        "--namespace", "test", "--device", "device-1", "--bundle", device.bundle)
    device.install(None, success=False)
    device.install(device.grant("wrong-device", device="device-2"), success=False)
    device.install(device.grant("wrong-group", group="production"), success=False)
    device.install(good, device.other_bundle, success=False)
    now = int(time.time())
    device.install(device.grant("expired", start=now - 100, end=now - 1), success=False)
    device.install(device.grant("future", start=now + 100, end=now + 200), success=False)
    for flags in [
        ["--bundle-hash", run(BUNDLER, "hash", device.bundle).stdout.strip()],
        ["--root-cert", device.grant_root],
        ["--insecure-skip-bundle-verification"],
        ["--insecure-allow-missing-block-index"],
        ["--skip-compatibility-check"],
    ]:
        device.install(good, success=False, extra=flags)
    assert device.record("first") is None
    print("PASS: bundle, audience, window, and override bindings are enforced", flush=True)


def test_explicit_policy_bypass(device):
    """Grant policy can be skipped explicitly, and a grant excludes the overrides."""
    digest = run(BUNDLER, "hash", device.bundle).stdout.strip()
    device.install(None, success=False)
    # Skipping policy returns to the ordinary verification rules, which this
    # unsigned bundle does not satisfy on its own.
    device.install(None, extra=["--insecure-skip-grant-verification"], success=False)
    device.install(None, extra=["--insecure-skip-grant-verification",
                                "--bundle-hash", digest])
    # A grant decides its installation, so it excludes every local override.
    good = device.grant("exclusive")
    for flags in [
        ["--insecure-skip-grant-verification"],
        ["--bundle-hash", digest],
        ["--root-cert", device.grant_root],
        ["--insecure-skip-bundle-verification"],
        ["--insecure-allow-missing-block-index"],
        ["--skip-compatibility-check"],
    ]:
        device.install(good, success=False, extra=flags)
    device.install(good)
    print("PASS: policy can be skipped explicitly and a grant excludes overrides",
          flush=True)


def test_unprepared_certificates(device):
    """Only certificates prepared as grant authorities can sign grants."""
    unprepared = [
        ("code-signing", device.code_signing_cert(
            "unprepared-signer", device.grant_root, device.grant_root_key)),
        ("missing scope", device.authority_cert(
            "no-scope", device.grant_root, device.grant_root_key,
            ["--any-audience", "--permission", "apps"],
            alter_extensions=lambda text: "\n".join(
                line for line in text.splitlines() if "=DER:" not in line) + "\n")),
        ("missing purpose", device.authority_cert(
            "no-purpose", device.grant_root, device.grant_root_key,
            ["--any-audience", "--permission", "apps"],
            alter_extensions=lambda text: "\n".join(
                line for line in text.splitlines()
                if not line.startswith("extendedKeyUsage")) + "\n")),
        ("truncated scope", device.authority_cert(
            "bad-scope", device.grant_root, device.grant_root_key,
            ["--any-audience", "--permission", "apps"],
            alter_extensions=lambda text: text.replace("=DER:30", "=DER:31"))),
    ]
    for reason, signer in unprepared:
        name = f"unprepared-{reason.replace(' ', '-')}"
        signature = device.grant(name, signer=signer)
        device.install(signature, success=False)
        assert device.record(name) is None
    print("PASS: unprepared and malformed authority certificates cannot sign grants",
          flush=True)


def test_authority_scope(device):
    """Certificate scope and local policy both bound what an authority may authorize."""
    canary = device.authority_cert(
        "canary-signer", device.grant_root, device.grant_root_key,
        ["--group", "canary", "--permission", "apps"])
    device.install(device.grant("canary-ok", group="canary", signer=canary))
    device.install(device.grant("canary-device", signer=canary), success=False)
    apps_only = device.authority_cert(
        "apps-signer", device.grant_root, device.grant_root_key,
        ["--any-audience", "--permission", "apps"])
    system_grant = device.grant("apps-only-system", target="system", signer=apps_only)
    run(CTRL, "update", "install", device.bundle, "--grant", system_grant, success=False)
    device.configure(authorities=[(device.grant_root, ["apps"])])
    run(CTRL, "update", "install", device.bundle,
        "--grant", device.grant("local-policy-system", target="system"), success=False)
    device.configure()
    print("PASS: certificate scope and local permissions each bound an authority",
          flush=True)


def test_delegation(device):
    """Delegated authorities may narrow but never widen, and depth is bounded."""
    intermediate, intermediate_key = device.authority_cert(
        "delegation-authority", device.grant_root, device.grant_root_key,
        ["--group", "canary", "--permission", "apps"], intermediate=0, days="2")
    delegated = device.authority_cert(
        "delegated-signer", intermediate, intermediate_key,
        ["--group", "canary", "--permission", "apps"])
    device.install(device.grant("delegated", group="canary", signer=delegated,
                                intermediates=[intermediate]))
    wider = device.authority_cert(
        "escalated-signer", intermediate, intermediate_key,
        ["--any-audience", "--permission", "apps"])
    device.install(device.grant("escalated", group="canary", signer=wider,
                                intermediates=[intermediate]), success=False)
    sub_authority, sub_key = device.authority_cert(
        "sub-authority", intermediate, intermediate_key,
        ["--group", "canary", "--permission", "apps"], intermediate=0, days="2")
    too_deep = device.authority_cert(
        "too-deep-signer", sub_authority, sub_key,
        ["--group", "canary", "--permission", "apps"])
    device.install(device.grant("too-deep", group="canary", signer=too_deep,
                                intermediates=[intermediate, sub_authority]), success=False)
    print("PASS: delegation narrows scope and stops at the authorized depth", flush=True)


def test_replay(device):
    """An interrupted transfer retries, a consumed grant is final, and order is free."""
    truncated = device.directory / "truncated.rugixb"
    truncated.write_bytes(device.bundle.read_bytes()[:-50])
    first = device.grant("retry")
    device.install(first, truncated, success=False)
    assert device.record("retry")["consumed"] is False
    device.install(first)
    assert device.record("retry")["consumed"] is True
    device.install(first, success=False)
    before = len(device.activations())
    second = device.grant("second")
    third = device.grant("third")
    device.install(third)
    device.install(second)
    assert len(device.activations()) == before + 2
    device.install(second, success=False)
    # Activating software that is already installed is outside grant policy, so
    # these commands succeed or fail on their own merits, never on a missing grant.
    for command in [["apps", "activate", "grant-test"], ["apps", "rollback", "grant-test"]]:
        result = run(CTRL, *command, success=None)
        assert "requires a new installation" not in result.stderr, result.stderr
    print("PASS: admitted grants retry, consumed grants are final, and order is free",
          flush=True)


def test_time_watermark(device):
    """Verification never uses a time below the recorded watermark."""
    device.install(device.grant("watermark"))
    state = device.state()
    assert state["timeWatermark"] >= int(time.time()) - 60
    future = int(time.time()) + 3600
    state["timeWatermark"] = future
    (device.state_dir / "state.json").write_text(json.dumps(state))
    device.install(device.grant("behind-watermark"), success=False)
    state["timeWatermark"] = 0
    (device.state_dir / "state.json").write_text(json.dumps(state))
    device.install(device.grant("after-reset", end=future + 600))
    print("PASS: the durable watermark floors verification time", flush=True)


def test_expiry_during_transfer(device):
    """A stream that outlives its grant cannot reach activation."""
    expires = int(time.time()) + 3
    expiring = device.grant("expiring", end=expires)
    before = len(device.activations())
    process = subprocess.Popen([CTRL, "apps", "install", "-", "--grant", expiring],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    payload = device.bundle.read_bytes()
    process.stdin.write(payload[:-50])
    process.stdin.flush()
    time.sleep(max(0, expires - time.time() + 0.1))
    stdout, stderr = process.communicate(payload[-50:], timeout=15)
    assert process.returncode != 0, (stdout, stderr)
    assert len(device.activations()) == before
    device.install(device.grant("renewed"))
    print("PASS: expiry during streaming prevents activation; a new grant recovers",
          flush=True)


def test_identity_revalidation(device):
    """Identity, membership, and helper health are rechecked before activation."""
    updated = device.app_bundle("grant-test", "identity-update")
    for name, change in [
        ("membership", lambda: device.set_identity(groups=[])),
        ("identity", lambda: device.set_identity(device="device-2")),
        ("helper", lambda: device.identity_helper.write_text(
            device.helper_script + "exit 1\n")),
    ]:
        signature = device.grant(f"changed-{name}", group="canary", bundle=updated)
        before = len(device.activations())
        process = subprocess.Popen([CTRL, "apps", "install", "-", "--grant", signature],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        try:
            process.stdin.write(updated.read_bytes()[:-50])
            process.stdin.flush()
            deadline = time.monotonic() + 10
            while not any(record["id"] == f"changed-{name}"
                          for record in device.state()["admitted"]):
                assert time.monotonic() < deadline, "installation did not admit the grant"
                assert process.poll() is None, "installation exited before admission"
                time.sleep(0.02)
            change()
            stdout, stderr = process.communicate(updated.read_bytes()[-50:], timeout=15)
            assert process.returncode != 0, (stdout, stderr)
            assert not any(record["consumed"] for record in device.state()["admitted"]
                           if record["id"] == f"changed-{name}")
            assert len(device.activations()) == before
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            device.set_identity()
            device.identity_helper.write_text(device.helper_script)
    print("PASS: identity, membership, and helper failures are caught before activation",
          flush=True)


def test_daemon(device):
    """The daemon enforces grant policy even with its override switch enabled."""
    Path("/etc/rugix/daemon.toml").write_text("dangerously-insecure = true\n")
    log = device.directory / "daemon.log"
    with log.open("w") as handle:
        daemon = subprocess.Popen([CTRL, "daemon"], stdout=handle, stderr=handle)
        try:
            deadline = time.monotonic() + 10
            while not Path("/run/rugix/ctrl.sock").exists():
                assert daemon.poll() is None, log.read_text()
                assert time.monotonic() < deadline
                time.sleep(0.02)
            signature = device.grant("daemon", group="canary")
            daemon_install(device.bundle, None, success=False)
            daemon_install(device.bundle, signature,
                           {"insecure_skip_bundle_verification": True}, success=False)
            daemon_install(device.bundle, signature,
                           {"insecure_skip_grant_verification": True}, success=False)
            device.set_identity(groups=[])
            daemon_install(device.bundle, signature, success=False)
            device.set_identity()
            daemon_install(device.bundle, signature)
            daemon_install(device.bundle, signature, success=False)
        finally:
            # SIGKILL makes cleanup independent of inherited signal masks.
            daemon.kill()
            daemon.wait(timeout=10)
    print("PASS: daemon transport, group grant, and override rejection", flush=True)


def test_independent_publisher(device):
    """Publisher and deployment authorities can be required independently."""
    device.configure(mode="embedded-and-grant")
    signed_bundle = device.directory / "signed.rugixb"
    run(BUNDLER, "signatures", "sign", device.bundle, device.publisher_cert,
        device.publisher_key, signed_bundle)
    dual = device.grant("dual")
    device.install(dual, success=False)
    device.install(None, signed_bundle, success=False)
    device.install(dual, signed_bundle)
    saved = (device.state_dir / "state.json").read_bytes()
    (device.state_dir / "state.json").write_text("invalid")
    device.install(device.grant("corrupt-state"), signed_bundle, success=False)
    (device.state_dir / "state.json").write_bytes(saved)
    device.configure()
    print("PASS: independent publisher approval and corrupt state failing closed",
          flush=True)


def test_external_signing(device):
    """External CMS signing uses the exact prepared bytes."""
    prepared = device.directory / "prepared.raw"
    external = device.directory / "external.cms"
    now = int(time.time())
    run(BUNDLER, "grants", "prepare", "--bundle", device.bundle, "--id", "external",
        "--namespace", "test", "--device", "device-1", "--not-before", timestamp(now - 1),
        "--expires-at", timestamp(now + 300), "--target", "apps", prepared)
    run("openssl", "cms", "-sign", "-binary", "-nodetach", "-in", prepared,
        "-signer", device.signer, "-inkey", device.signer_key,
        "-outform", "DER", "-out", external)
    device.install(external)
    print("PASS: external OpenSSL signing is accepted", flush=True)


def test_system_installation(device):
    """System installation binds its options and consumes before boot selection."""
    slot_a, slot_b = device.directory / "slot-a", device.directory / "slot-b"
    slot_a.write_bytes(b"active system")
    slot_b.write_bytes(b"old inactive system")
    boot_log = device.directory / "boot.log"
    controller = device.directory / "boot-controller"
    controller.write_text(f"""#!{sys.executable}
import json
from pathlib import Path
import sys

operation = sys.argv[1]
if operation in ["get_active", "get_default"]:
    print(json.dumps({{"group": "A"}}))
else:
    state = json.loads(Path({str(device.state_dir / "state.json")!r}).read_text())
    consumed = sum(1 for record in state["admitted"] if record["consumed"])
    with Path({str(boot_log)!r}).open("a") as log:
        log.write(" ".join(sys.argv[1:]) + f" consumed={{consumed}}\\n")
    print("{{}}")
""")
    controller.chmod(0o755)
    Path("/etc/rugix/system.toml").write_text(f"""
[config-partition]
disabled = true
[boot-flow]
type = "custom"
controller = "{controller}"
[slots.a]
type = "file"
path = "{slot_a}"
[slots.b]
type = "file"
path = "{slot_b}"
[boot-groups.A.slots]
system = "a"
[boot-groups.B.slots]
system = "b"
""")
    bundle_dir = device.directory / "system-bundle"
    (bundle_dir / "payloads").mkdir(parents=True)
    payload = b"replacement system" * 4096
    (bundle_dir / "payloads/system").write_bytes(payload)
    (bundle_dir / "rugix-bundle.toml").write_text("""
update-type = "full"
[[payloads]]
filename = "system"
delivery = { type = "slot", slot = "system" }
[payloads.block-encoding]
chunker = "casync-64"
hash-algorithm = "sha256"
""")
    system_bundle = device.directory / "system.rugixb"
    run(BUNDLER, "bundle", bundle_dir, system_bundle)
    exact = device.grant("system-exact", target="system", bundle=system_bundle,
                         options=["--boot-group", "B", "--keep-overlay", "false",
                                  "--reboot", "set"])
    base = [CTRL, "update", "install", system_bundle, "--grant", exact]
    for flags in [
        ["--boot-group", "A", "--reboot", "set"],
        ["--boot-group", "B", "--reboot", "no"],
        ["--boot-group", "B", "--reboot", "set", "--keep-overlay"],
    ]:
        run(*base, *flags, success=False)
    assert slot_b.read_bytes() == b"old inactive system"
    assert not boot_log.exists()
    before = sum(1 for record in device.state()["admitted"] if record["consumed"])
    run(*base, "--boot-group", "B", "--reboot", "set")
    assert slot_a.read_bytes() == b"active system"
    assert slot_b.read_bytes() == payload
    # The grant is consumed after installation and before boot selection.
    assert boot_log.read_text().splitlines() == [
        f"pre_install B consumed={before}",
        f"post_install B consumed={before}",
        f"set_try_next B consumed={before + 1}",
    ]
    run(*base, "--boot-group", "B", "--reboot", "set", success=False)
    selections = boot_log.read_text().count("set_try_next")
    permissive = device.grant("system-permissive", target="system", bundle=system_bundle)
    run(CTRL, "update", "install", system_bundle, "--grant", permissive,
        "--boot-group", "B", "--reboot", "no")
    assert boot_log.read_text().count("set_try_next") == selections
    # Selecting a staged system is outside grant policy, because installing it
    # needed a grant. A deployment script can therefore reboot when it chooses.
    result = run(CTRL, "system", "reboot", "--spare", success=None)
    assert "requires an installation granted" not in result.stderr, result.stderr
    assert boot_log.read_text().count("set_try_next") == selections + 1
    print("PASS: system installation binds options and consumes before boot selection",
          flush=True)


def test_managed_state_location(device):
    """Replay history lives outside resettable state profiles."""
    standalone = (device.state_dir / "state.json").read_bytes()
    profile = Path("/run/rugix/mounts/data/state/default")
    profile.mkdir(parents=True)
    state_mount = Path("/run/rugix/state")
    state_mount.mkdir()
    run("mount", "--bind", profile, state_mount)
    managed = device.grant("managed", group="canary")
    device.state_dir = Path("/run/rugix/mounts/data/.rugix/grants")
    assert not (device.state_dir / "state.json").exists()
    device.install(managed)
    after_install = (device.state_dir / "state.json").read_bytes()
    run("umount", state_mount)
    shutil.rmtree(profile)
    profile.mkdir()
    run("mount", "--bind", profile, state_mount)
    device.install(managed, success=False)
    assert (device.state_dir / "state.json").read_bytes() == after_install
    assert Path("/var/lib/rugix/grants/state.json").read_bytes() == standalone
    print("PASS: managed and standalone state locations both resist resets", flush=True)


def recv_exact(stream, size):
    """Read one complete private-protocol field from the daemon."""
    data = b""
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise AssertionError("daemon closed before returning a response")
        data += chunk
    return data


def daemon_install(bundle, grant, overrides=None, success=True):
    """Send an untrusted install request through the real daemon socket and stream."""
    options = {
        "grant": list(grant.read_bytes()) if grant else None,
        "bundle_hash": None, "root_cert": None,
        "insecure_skip_bundle_verification": False,
        "insecure_allow_missing_block_index": False, "skip_compatibility_check": False,
    }
    options.update(overrides or {})
    request = json.dumps({
        "operation": "install-bundle",
        "parameters": {"source": "Stream", "target": "Apps", "options": options},
    }).encode()
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(15)
        stream.connect("/run/rugix/ctrl.sock")
        stream.sendall(b"RGXD" + struct.pack(">HI", 1, len(request)) + request)
        try:
            stream.sendall(bundle.read_bytes())
            stream.shutdown(socket.SHUT_WR)
        except BrokenPipeError:
            pass
        while True:
            kind, length = struct.unpack(">BI", recv_exact(stream, 5))
            payload = json.loads(recv_exact(stream, length))
            if kind == 1:
                continue
            assert (kind == 2) == success, (kind, payload)
            return payload


SECTIONS = [
    test_configuration_errors,
    test_lazy_state_initialization,
    test_window_parsing,
    test_hash_only_issuance,
    test_grant_bindings,
    test_explicit_policy_bypass,
    test_unprepared_certificates,
    test_authority_scope,
    test_delegation,
    test_replay,
    test_time_watermark,
    test_expiry_during_transfer,
    test_identity_revalidation,
    test_daemon,
    test_independent_publisher,
    test_external_signing,
    test_system_installation,
    test_managed_state_location,
]


def suite(directory):
    """Test the public commands and installed app behavior on an isolated device."""
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/user") != sys.argv[3]
    assert os.readlink("/proc/self/ns/mnt") != sys.argv[4]
    for name in ["etc", "var", "run"]:
        replacement = directory / name
        replacement.mkdir()
        run("mount", "--bind", replacement, f"/{name}")
    Path("/etc/rugix").mkdir()
    Path("/var/lib").mkdir()
    os.environ["OPENSSL_CONF"] = "/dev/null"
    Path("/etc/rugix/apps.toml").write_text('service-manager = "none"\n')
    device = Device(directory)
    for section in SECTIONS:
        section(device)


def main():
    """Launch tests in new user and mount namespaces with disposable device paths."""
    if len(sys.argv) == 5 and sys.argv[1] == "--inside":
        suite(Path(sys.argv[2]))
        return
    for executable in [CTRL, BUNDLER]:
        if not executable.is_file():
            raise SystemExit("Build rugix-ctrl and rugix-bundler before running this test.")
    with tempfile.TemporaryDirectory(prefix="rugix-grant-e2e-") as directory:
        subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--fork",
             sys.executable, str(Path(__file__).resolve()), "--inside", directory,
             os.readlink("/proc/self/ns/user"), os.readlink("/proc/self/ns/mnt")],
            check=True,
        )


if __name__ == "__main__":
    main()
