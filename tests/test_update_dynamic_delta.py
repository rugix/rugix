"""Dynamic delta updates download only the blocks missing from the local slots.

The bundle is served by nginx on the VM, which supports HTTP range requests,
unlike the host's HTTP server used by other tests.
"""

from __future__ import annotations

import re

from rugix_testkit import BakeryBuilder, CmdResult, RugixCtrl, VMHandle

from support import UPDATE_PAGE, web_page

REMOTE_BUNDLE = "/var/www/html/system.rugixb"
BUNDLE_URL = "http://localhost/system.rugixb"
INDEX_FILE = (
    "/run/rugix/mounts/data/rugix/slots/{slot}/casync-64_sha512-256.rugix-block-index"
)


def test_dynamic_delta_downloads_changed_blocks(
    vm: VMHandle,
    rugix: RugixCtrl,
    bakery: BakeryBuilder,
) -> None:
    """Indexing active slots cuts download bytes by at least half, and the
    updated system boots with the changed web page."""
    vm.upload(bakery.bake_bundle("customized-amd64-delta"), REMOTE_BUNDLE)
    vm.run(["chmod", "644", REMOTE_BUNDLE], hide=True)
    full_download = _downloaded_percent(rugix.update_install(BUNDLE_URL, timeout=600))

    # The control install retains target indices. Remove them so only active
    # slots can supply blocks in the indexed install.
    for slot in ("boot-b", "system-b"):
        vm.run(["rm", INDEX_FILE.format(slot=slot)], hide=True)

    for slot in ("boot-a", "system-a"):
        vm.run(
            ["rugix-ctrl", "slots", "create-index", slot, "casync-64", "sha512-256"],
            hide=True,
        )
    result = rugix.update_install(BUNDLE_URL, timeout=600)
    delta_download = _downloaded_percent(result)
    assert delta_download < full_download / 2, (delta_download, full_download)

    vm.run_disconnecting(["rugix-ctrl", "system", "reboot", "--spare"])
    vm.wait_for_reboot()
    rugix.assert_boot(default="a", active="b")
    assert UPDATE_PAGE in web_page(vm)


def _downloaded_percent(result: CmdResult) -> float:
    """Read the transfer ratio reported by Rugix Ctrl after installation."""
    downloaded = re.search(r"downloaded ([\d.]+)% .* of the full bundle", result.stderr)
    assert downloaded is not None, result.stderr
    return float(downloaded.group(1))
