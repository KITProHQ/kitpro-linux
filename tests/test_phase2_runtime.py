from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from tools import kitpro_phase2


class Phase2RuntimeTests(unittest.TestCase):
    @mock.patch("tools.kitpro_phase2.run")
    @mock.patch("tools.kitpro_phase2.Path.is_file", return_value=True)
    @mock.patch("tools.kitpro_phase2.os.geteuid", return_value=0)
    @mock.patch("tools.kitpro_phase2.shutil.which", return_value="/usr/bin/arch-chroot")
    def test_root_uses_plain_arch_chroot(
        self, _which: mock.Mock, _geteuid: mock.Mock, _is_file: mock.Mock, run: mock.Mock
    ) -> None:
        kitpro_phase2.run_in_root_namespace(Path("/target"), ["true"], Path("/state"))
        run.assert_called_once_with(["/usr/bin/arch-chroot", "/target", "true"])

    @mock.patch("tools.kitpro_phase2.run")
    @mock.patch("tools.kitpro_phase2.Path.is_file", return_value=True)
    @mock.patch("tools.kitpro_phase2.os.geteuid", return_value=1000)
    @mock.patch("tools.kitpro_phase2.shutil.which", return_value="/usr/bin/arch-chroot")
    def test_unprivileged_uses_arch_chroot_namespace(
        self, _which: mock.Mock, _geteuid: mock.Mock, _is_file: mock.Mock, run: mock.Mock
    ) -> None:
        kitpro_phase2.run_in_root_namespace(Path("/target"), ["true"], Path("/state"))
        run.assert_called_once_with(["/usr/bin/arch-chroot", "-N", "/target", "true"])


if __name__ == "__main__":
    unittest.main()
