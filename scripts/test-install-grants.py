#!/usr/bin/env python3
"""Exercise grant issuance, streaming installation, daemon admission, and replay recovery.

Requires built debug binaries, OpenSSL, and Linux user and mount namespaces.
All device paths are replaced inside a private namespace. No host root access is used.
"""

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
    """Run a real CLI and assert its exit status, retaining diagnostics on failure."""
    result = subprocess.run(
        [str(arg) for arg in args], capture_output=True, text=True, timeout=30
    )
    if (result.returncode == 0) != success:
        raise AssertionError(f"{args}: exit {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def certificate(directory, name):
    """Create an independent CA and a leaf signing certificate for the test."""
    root = directory / f"{name}-root.pem"
    root_key = directory / f"{name}-root.key"
    cert = directory / f"{name}.pem"
    key = directory / f"{name}.key"
    csr = directory / f"{name}.csr"
    extensions = directory / f"{name}.ext"
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\n")
    run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-subj", f"/CN={name} root", "-days", "2",
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign",
        "-keyout", root_key, "-out", root)
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-subj", f"/CN={name}", "-keyout", key, "-out", csr)
    run("openssl", "x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key,
        "-CAcreateserial", "-days", "2", "-extfile", extensions, "-out", cert)
    return root, cert, key


def authority_certificate(directory, name, parent, parent_key, policy, intermediate=False,
                          alter_extensions=None):
    """Issue real constrained certificates using Bundler's policy encoder and OpenSSL."""
    cert, key = directory / f"{name}.pem", directory / f"{name}.key"
    csr, extensions = directory / f"{name}.csr", directory / f"{name}.ext"
    policy_file = directory / f"{name}.json"
    policy_file.write_text(json.dumps(policy))
    run(BUNDLER, "grants", "authority-extensions", policy_file, extensions,
        *(["--intermediate"] if intermediate else []))
    if alter_extensions:
        extensions.write_text(alter_extensions(extensions.read_text()))
    run("openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
        "-nodes", "-subj", f"/CN={name}", "-keyout", key, "-out", csr)
    run("openssl", "x509", "-req", "-in", csr, "-CA", parent, "-CAkey", parent_key,
        "-CAcreateserial", "-days", "2" if intermediate else "1",
        "-extfile", extensions, "-out", cert)
    return cert, key


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
    root, cert, key = certificate(directory, "grant")
    publisher_root, publisher_cert, publisher_key = certificate(directory, "publisher")
    state_dir = Path("/var/lib/rugix/grants")
    config = Path("/etc/rugix/ctrl.toml")
    Path("/etc/rugix/apps.toml").write_text('service-manager = "none"\n')

    def configure(mode="GrantOnly", trusted=True, state_override=None):
        location = f'state-directory = "{state_override}"' if state_override else ""
        config.write_text(f"""
[signatures]
roots = ["{publisher_root}"]
[grants]
roots = ["{publisher_root}", "{root}"]
namespace = "test"
device = "device-1"
groups = ["canary"]
{location}
trusted-system-clock = {str(trusted).lower()}
mode = {{ tag = "{mode}" }}
""")

    configure()
    run(CTRL, "initialize-grant-state")
    initial_state = (state_dir / "state.json").read_bytes()
    run(CTRL, "initialize-grant-state", success=False)
    assert (state_dir / "state.json").read_bytes() == initial_state

    script = directory / "orchestrator"
    script.write_text("""#!/bin/sh
if [ "$1" = "activate" ]; then
    echo activated >> "$RUGIX_APP_DATA_DIR/activations"
fi
exit 0
""")
    script.chmod(0o755)
    bundle = directory / "app.rugixb"
    run(BUNDLER, "apps", "pack", "generic", "--app", "grant-test", script, bundle)
    other_bundle = directory / "other.rugixb"
    run(BUNDLER, "apps", "pack", "generic", "--app", "other-app", script, other_bundle)
    bundle_hash = run(BUNDLER, "hash", bundle).stdout.strip()

    def grant(name, sequence, device="device-1", group=None, start=None, end=None, target="apps",
              payload=bundle, extra=(), signer=None):
        now = int(time.time())
        signing_cert, signing_key = signer or (cert, key)
        output = directory / f"{name}.cms"
        audience = ["--group", group] if group else ["--device", device]
        run(BUNDLER, "grants", "sign", "--bundle", payload, "--id", name,
            "--namespace", "test", *audience, "--not-before", start if start is not None else now,
            "--expires-at", end if end is not None else now + 300, "--sequence", sequence,
            "--target", target, "--cert", signing_cert, "--key", signing_key, *extra, output)
        return output

    def install(signature, payload=bundle, success=True, extra=()):
        args = [CTRL, "apps", "install", payload]
        if signature:
            args += ["--grant", signature]
        return run(*args, *extra, success=success)

    def state():
        return json.loads((state_dir / "state.json").read_text())

    good = grant("first", 10)
    run(BUNDLER, "grants", "verify", good, "--root-cert", root,
        "--namespace", "test", "--device", "device-1", "--bundle", bundle)
    install(None, success=False)
    install(grant("wrong-device", 10, device="device-2"), success=False)
    install(grant("wrong-group", 10, group="production"), success=False)
    install(grant("wrong-operation", 10, target="system"), success=False)
    now = int(time.time())
    install(grant("expired", 10, start=now-100, end=now-1), success=False)
    install(grant("future", 10, start=now+100, end=now+200), success=False)
    install(good, other_bundle, success=False)
    for flags in [
        ["--bundle-hash", bundle_hash], ["--root-cert", root],
        ["--insecure-skip-bundle-verification"], ["--insecure-allow-missing-block-index"],
        ["--skip-compatibility-check"],
    ]:
        install(good, success=False, extra=flags)
    assert state().get("apps") is None
    configure(trusted=False)
    install(good, success=False)
    configure()

    # A truncated transfer reserves a transaction; a fresh process can retry it.
    truncated = directory / "truncated.rugixb"
    truncated.write_bytes(bundle.read_bytes()[:-50])
    install(good, truncated, success=False)
    assert state()["apps"]["consumed"] is False
    install(good)
    assert state()["apps"]["consumed"] is True
    assert Path("/var/lib/rugix/apps/grant-test/data/activations").read_text() == "activated\n"
    install(good, success=False)
    install(grant("older", 9), success=False)
    install(grant("same-sequence", 10), success=False)
    run(CTRL, "apps", "activate", "grant-test", success=False)
    run(CTRL, "apps", "rollback", "grant-test", success=False)
    print("PASS: CLI grant constraints, interrupted transfer retry, activation, and replay", flush=True)


    # Certificate authority policy must hold before any reservation or installation.
    authority_policy = {
        "version": 1, "namespace": "test", "audiences": "Any",
        "permissions": [{"verifier": "rugix-ctrl", "operation": "rugix.install.apps.v1"}],
        "maxGrantLifetime": 600,
    }
    intermediate_cert, intermediate_key = authority_certificate(
        directory, "deployment-authority", root, root.with_suffix(".key"),
        authority_policy, intermediate=True)
    signer_policy = dict(authority_policy, audiences={"Targets": [{"Group": "canary"}]},
                         maxGrantLifetime=300)
    scoped_signer = authority_certificate(
        directory, "scoped-signer", intermediate_cert, intermediate_key, signer_policy)
    chain_args = ["--intermediate-cert", intermediate_cert]
    scoped_args = {"signer": scoped_signer, "extra": chain_args}
    install(grant("authority-wrong-audience", 11, **scoped_args), success=False)
    install(grant("authority-long-grant", 11, group="canary",
                  end=int(time.time()) + 500, **scoped_args), success=False)

    wider_policy = dict(signer_policy, audiences="Any")
    # This broadens the child relative to a narrower parent, even for an allowed request.
    narrow_ca_policy = dict(authority_policy, audiences={"Targets": [{"Group": "canary"}]})
    narrow_ca, narrow_key = authority_certificate(
        directory, "narrow-authority", root, root.with_suffix(".key"), narrow_ca_policy,
        intermediate=True)
    wider_signer = authority_certificate(
        directory, "escalated-signer", narrow_ca, narrow_key, wider_policy)
    install(grant("authority-escalation", 11, group="canary", signer=wider_signer,
                  extra=["--intermediate-cert", narrow_ca]), success=False)

    missing_policy_signer = authority_certificate(
        directory, "missing-policy", intermediate_cert, intermediate_key, signer_policy,
        alter_extensions=lambda text: "\n".join(line for line in text.splitlines()
                                                if "=DER:" not in line) + "\n")
    install(grant("authority-missing-policy", 11, group="canary", signer=missing_policy_signer,
                  extra=chain_args), success=False)
    mixed_purpose_signer = authority_certificate(
        directory, "mixed-purpose", intermediate_cert, intermediate_key, signer_policy,
        alter_extensions=lambda text: text.replace("extendedKeyUsage=critical,",
                                                   "extendedKeyUsage=critical,codeSigning,"))
    install(grant("authority-mixed-purpose", 11, group="canary", signer=mixed_purpose_signer,
                  extra=chain_args), success=False)
    assert int(state()["apps"]["sequence"]) == 10
    print("PASS: constrained certificate issuance, scope, lifetime, escalation, and required policy", flush=True)

    # The daemon must enforce grants even when its legacy override switch is enabled.
    Path("/etc/rugix/daemon.toml").write_text("dangerously-insecure = true\n")
    daemon_log = directory / "daemon.log"
    with daemon_log.open("w") as log:
        daemon = subprocess.Popen([CTRL, "daemon"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while not Path("/run/rugix/ctrl.sock").exists():
                assert daemon.poll() is None, daemon_log.read_text()
                assert time.monotonic() < deadline
                time.sleep(0.02)
            daemon_install(bundle, None, success=False)
            daemon_install(bundle, good, success=False)
            group_grant = grant("group", 11, group="canary", **scoped_args)
            daemon_install(bundle, group_grant, {"insecure_skip_bundle_verification": True}, success=False)
            daemon_install(bundle, group_grant)
            daemon_install(bundle, group_grant, success=False)
        finally:
            # SIGKILL makes cleanup independent of inherited signal masks.
            daemon.kill()
            daemon.wait(timeout=10)
    print("PASS: daemon transport, group grant, and override rejection", flush=True)

    # Admission must be checked again after a stream outlives its grant.
    expires = int(time.time()) + 3
    expiring = grant("expiring", 12, end=expires)
    proc = subprocess.Popen([CTRL, "apps", "install", "-", "--grant", expiring],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    payload = bundle.read_bytes()
    proc.stdin.write(payload[:-50])
    proc.stdin.flush()
    time.sleep(max(0, expires - time.time() + 0.1))
    stdout, stderr = proc.communicate(payload[-50:], timeout=15)
    assert proc.returncode != 0, (stdout, stderr)
    assert state()["apps"]["consumed"] is False
    assert len(Path("/var/lib/rugix/apps/grant-test/data/activations").read_text().splitlines()) == 2
    install(grant("renewed", 13))
    print("PASS: expiry during streaming prevents activation; a new grant permits recovery", flush=True)

    configure(mode="EmbeddedAndGrant")
    signed_bundle = directory / "signed.rugixb"
    run(BUNDLER, "signatures", "sign", bundle, publisher_cert, publisher_key, signed_bundle)
    dual = grant("dual", 14)
    install(dual, success=False)
    install(None, signed_bundle, success=False)
    install(dual, signed_bundle)
    assert int(state()["apps"]["sequence"]) == 14

    saved = (state_dir / "state.json").read_bytes()
    (state_dir / "state.json").unlink()
    install(grant("missing-state", 15), signed_bundle, success=False)
    (state_dir / "state.json").write_text("invalid")
    install(grant("corrupt-state", 15), signed_bundle, success=False)
    (state_dir / "state.json").write_bytes(saved)
    assert int(state()["apps"]["sequence"]) == 14
    print("PASS: independent publisher and deployment signatures; missing/corrupt state fails closed", flush=True)

    # External CMS signing uses the exact prepared bytes and preserves the grant.
    prepared = directory / "prepared.raw"
    external = directory / "external.cms"
    now = int(time.time())
    run(BUNDLER, "grants", "prepare", "--bundle", bundle, "--id", "external",
        "--namespace", "test", "--device", "device-1", "--not-before", now-1,
        "--expires-at", now+300, "--sequence", 15, "--target", "apps", prepared)
    run("openssl", "cms", "-sign", "-binary", "-nodetach", "-in", prepared,
        "-signer", cert, "-inkey", key, "-outform", "DER", "-out", external)
    install(external, signed_bundle)
    print("PASS: external OpenSSL signing and unchanged bundle identity", flush=True)

    # File slots and a recording boot controller exercise the system installer
    # without block devices or a real reboot.
    configure()
    slot_a, slot_b = directory / "slot-a", directory / "slot-b"
    slot_a.write_bytes(b"active system")
    slot_b.write_bytes(b"old inactive system")
    boot_log = directory / "boot.log"
    controller = directory / "boot-controller"
    controller.write_text(f"""#!{sys.executable}
import json
from pathlib import Path
import sys

operation = sys.argv[1]
if operation in ["get_active", "get_default"]:
    print(json.dumps({{"group": "A"}}))
else:
    if operation in ["pre_install", "set_try_next"]:
        state = json.loads(Path({str(state_dir / "state.json")!r}).read_text())
        assert state["system"]["consumed"] == (operation == "set_try_next")
    with Path({str(boot_log)!r}).open("a") as log:
        log.write(" ".join(sys.argv[1:]) + "\\n")
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
    bundle_dir = directory / "system-bundle"
    (bundle_dir / "payloads").mkdir(parents=True)
    system_payload = b"replacement system" * 4096
    (bundle_dir / "payloads/system").write_bytes(system_payload)
    (bundle_dir / "rugix-bundle.toml").write_text("""
update-type = "full"
[[payloads]]
filename = "system"
delivery = { type = "slot", slot = "system" }
[payloads.block-encoding]
chunker = "casync-64"
hash-algorithm = "sha256"
""")
    system_bundle = directory / "system.rugixb"
    run(BUNDLER, "bundle", bundle_dir, system_bundle)
    scoped_system = grant("authority-system-denied", 1, target="system", payload=system_bundle,
                          group="canary", signer=scoped_signer,
                          extra=[*chain_args, "--boot-group", "B", "--reboot", "set"])
    run(CTRL, "update", "install", system_bundle, "--grant", scoped_system,
        "--boot-group", "B", "--reboot", "set", success=False)
    assert slot_b.read_bytes() == b"old inactive system"
    assert state().get("system") is None
    system_policy = dict(authority_policy, audiences={"Targets": [{"Device": "device-1"}]},
                         permissions=[{"verifier": "rugix-ctrl", "operation": "rugix.install.system.v1"}])
    system_signer = authority_certificate(
        directory, "system-authority", root, root.with_suffix(".key"), system_policy)
    system_grant = grant("system", 1, target="system", payload=system_bundle,
                         signer=system_signer,
                         extra=["--boot-group", "B", "--reboot", "set"])
    base = [CTRL, "update", "install", system_bundle, "--grant", system_grant]
    for flags in [
        ["--boot-group", "A", "--reboot", "set"],
        ["--boot-group", "B", "--reboot", "no"],
        ["--boot-group", "B", "--reboot", "set", "--keep-overlay"],
    ]:
        run(*base, *flags, success=False)
    assert slot_b.read_bytes() == b"old inactive system"
    assert not boot_log.exists()
    run(*base, "--boot-group", "B", "--reboot", "set")
    assert slot_a.read_bytes() == b"active system"
    assert slot_b.read_bytes() == system_payload
    assert boot_log.read_text().splitlines() == ["pre_install B", "post_install B", "set_try_next B"]
    assert state()["system"]["consumed"] is True
    assert int(state()["apps"]["sequence"]) == 15
    run(*base, "--boot-group", "B", "--reboot", "set", success=False)
    run(CTRL, "system", "reboot", "--spare", success=False)
    assert boot_log.read_text().splitlines() == ["pre_install B", "post_install B", "set_try_next B"]
    print("PASS: system slot installation, option binding, consumption before boot selection, and replay", flush=True)

    # A reset replaces the managed profile but must preserve authorization history.
    standalone_state = (state_dir / "state.json").read_bytes()
    profile = Path("/run/rugix/mounts/data/state/default")
    profile.mkdir(parents=True)
    state_mount = Path("/run/rugix/state")
    state_mount.mkdir()
    run("mount", "--bind", profile, state_mount)
    managed_grant = grant("managed", 16, group="canary", **scoped_args)
    install(managed_grant, success=False)
    state_dir = Path("/run/rugix/mounts/data/.rugix/grants")
    run(CTRL, "initialize-grant-state")
    install(managed_grant)
    managed_state = (state_dir / "state.json").read_bytes()
    run("umount", state_mount)
    shutil.rmtree(profile)
    profile.mkdir()
    run("mount", "--bind", profile, state_mount)
    install(managed_grant, success=False)
    assert (state_dir / "state.json").read_bytes() == managed_state
    assert Path("/var/lib/rugix/grants/state.json").read_bytes() == standalone_state

    configure(state_override="/var/lib/rugix/grants")
    install(external, success=False)
    install(grant("explicit-location", 17))
    assert (state_dir / "state.json").read_bytes() == managed_state
    print("PASS: standard state paths, reset-resistant replay history, and explicit override", flush=True)


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
