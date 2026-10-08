from pathlib import Path
import unittest
from unittest.mock import patch
from tools.install.rootfs import _firewall_check_command


class RootlessFirewallValidationTests(unittest.TestCase):
    def test_mapped_root_retains_network_isolation_without_nested_user_mapping(self):
        with patch('os.geteuid', return_value=0), patch.object(Path, 'read_text', return_value='0 1000 1\n1 100000 65536\n'):
            command = _firewall_check_command(Path('/guest/etc/nftables.conf'))
        self.assertEqual(command, ['unshare', '--net', 'nft', '-c', '-f', '/guest/etc/nftables.conf'])

    def test_host_root_and_regular_users_require_new_user_and_network_namespaces(self):
        for uid in (0, 1000):
            with self.subTest(uid=uid), patch('os.geteuid', return_value=uid), patch.object(Path, 'read_text', return_value='0 0 4294967295\n'):
                command = _firewall_check_command(Path('/guest/etc/nftables.conf'))
            self.assertEqual(command[:4], ['unshare', '--user', '--map-root-user', '--net'])
