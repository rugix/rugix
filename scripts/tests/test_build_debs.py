"""Exercise Debian packaging and service enablement without root or systemd."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
UNITS = ("rugix-apps-restore-units.service", "rugix-apps-recover.service")
TARGETS = {
    "x86_64-unknown-linux-gnu": ("amd64", "gnu"),
    "x86_64-unknown-linux-musl": ("amd64", "musl"),
    "aarch64-unknown-linux-gnu": ("arm64", "gnu"),
    "aarch64-unknown-linux-musl": ("arm64", "musl"),
}


def run(*args, **kwargs):
    return subprocess.run(
        args, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, **kwargs,
    ).stdout


class DebianPackagingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.project = Path(cls.temporary.name)
        for directory in ("scripts", "packaging", "crates/apps/rugix-ctrl/assets"):
            shutil.copytree(PROJECT / directory, cls.project / directory)
        run("git", "init", "-q", str(cls.project))
        run(
            "git", "-C", str(cls.project), "-c", "user.name=Packaging Test",
            "-c", "user.email=test@example.com", "commit", "-q",
            "--allow-empty", "-m", "Packaging fixture",
        )
        run("git", "-C", str(cls.project), "tag", "v1.0.0")
        for target in TARGETS:
            directory = cls.project / "build/binaries" / target
            directory.mkdir(parents=True)
            for binary in ("rugix-ctrl", "rugix-bundler"):
                (directory / binary).write_text("#!/bin/sh\nexit 0\n")
        run("bash", str(cls.project / "scripts/build-debs.sh"))

    def package(self, binary, architecture, libc):
        return self.project / "build/debs" / (
            f"{binary}-{libc}_1.0.0_{architecture}.deb"
        )

    def test_package_contents(self):
        """Both libc variants ship boot services only in Rugix Ctrl packages."""
        with tempfile.TemporaryDirectory() as temporary:
            for architecture, libc in TARGETS.values():
                for binary in ("rugix-ctrl", "rugix-bundler"):
                    with self.subTest(architecture=architecture, libc=libc, binary=binary):
                        package = self.package(binary, architecture, libc)
                        root = Path(temporary) / f"{binary}-{libc}-{architecture}"
                        run("dpkg-deb", "--raw-extract", str(package), str(root))
                        self.assertTrue(os.access(root / "usr/bin" / binary, os.X_OK))
                        dependencies = run("dpkg-deb", "-f", str(package), "Depends")
                        if binary == "rugix-ctrl":
                            self.assertIn("init-system-helpers (>= 1.63)", dependencies)
                            self.assertIn("ca-certificates", dependencies)
                            for unit in UNITS:
                                self.assertEqual(
                                    (root / "usr/lib/systemd/system" / unit).read_bytes(),
                                    (PROJECT / "crates/apps/rugix-ctrl/assets" / unit).read_bytes(),
                                )
                            for script in ("postinst", "prerm", "postrm"):
                                self.assertTrue(os.access(root / "DEBIAN" / script, os.X_OK))
                        else:
                            self.assertFalse((root / "usr/lib/systemd").exists())
                            self.assertFalse((root / "DEBIAN/postinst").exists())
                            self.assertNotIn("init-system-helpers", dependencies)

    def test_offline_service_lifecycle(self):
        """Install and upgrade preserve service choices; purge clears helper state."""
        for libc in ("gnu", "musl"):
            with self.subTest(libc=libc), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                run(
                    "dpkg-deb", "--raw-extract",
                    str(self.package("rugix-ctrl", "amd64", libc)), str(root),
                )
                environment = dict(
                    os.environ, DPKG_ROOT=str(root),
                    DPKG_MAINTSCRIPT_PACKAGE=f"rugix-ctrl-{libc}",
                )

                def maintscript(name, *args):
                    run("sh", str(root / "DEBIAN" / name), *args, env=environment)

                def boot_link(unit):
                    return root / "etc/systemd/system/multi-user.target.wants" / unit

                maintscript("postinst", "configure")
                for unit in UNITS:
                    self.assertTrue(boot_link(unit).is_symlink())
                    self.assertEqual(
                        os.readlink(boot_link(unit)),
                        f"/usr/lib/systemd/system/{unit}",
                    )

                maintscript("prerm", "upgrade", "1.0.1")
                maintscript("postinst", "configure", "1.0.0")
                for unit in UNITS:
                    self.assertTrue(boot_link(unit).is_symlink())

                boot_link(UNITS[0]).unlink()
                mask = root / "etc/systemd/system" / UNITS[1]
                mask.symlink_to("/dev/null")
                maintscript("postinst", "configure", "1.0.0")
                self.assertFalse(boot_link(UNITS[0]).is_symlink())
                self.assertEqual(os.readlink(mask), "/dev/null")

                maintscript("prerm", "remove")
                for unit in UNITS:
                    (root / "usr/lib/systemd/system" / unit).unlink()
                maintscript("postrm", "remove")
                maintscript("postrm", "purge")
                for unit in UNITS:
                    self.assertFalse(boot_link(unit).is_symlink())
                state = root / "var/lib/systemd/deb-systemd-helper-enabled"
                self.assertFalse(state.exists() and any(state.rglob("*")))
                self.assertEqual(os.readlink(mask), "/dev/null")


if __name__ == "__main__":
    unittest.main(verbosity=2)
