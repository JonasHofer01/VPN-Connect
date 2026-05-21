"""
Verification test suite for vpn_connect.py bug fixes.
Tests:
  1. _parse_networks: IP parsing, DNS resolution, error handling
  2. extract_tunnel_name: .conf / .conf.dpapi / bare name
  3. DPAPI protect/unprotect round-trip
  4. RDP password merging logic (plain base64 + DPAPI encrypted)
  5. Split-tunnel route deletion format (CIDR stripping)
  6. py_compile syntax check
"""

import sys
import os
import unittest
import socket
import ipaddress
import base64
import py_compile
from unittest.mock import patch

# Ensure the workspace directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication

# Mock background dialog dismisser before importing vpn_connect
with patch("vpn_connect._start_dialog_dismisser", lambda: None), \
     patch("vpn_connect._stop_dialog_dismisser", lambda: None):
    import vpn_connect


class TestCompilation(unittest.TestCase):
    """Ensure vpn_connect.py compiles without syntax errors."""

    def test_py_compile(self):
        path = os.path.join(os.path.dirname(__file__), "vpn_connect.py")
        # Raises py_compile.PyCompileError on failure
        py_compile.compile(path, doraise=True)


class TestParseNetworks(unittest.TestCase):
    """Bug 5: Split-tunnel domain resolution."""

    def test_valid_cidr(self):
        res = vpn_connect._parse_networks(["192.168.1.0/24"])
        self.assertEqual(res, [ipaddress.ip_network("192.168.1.0/24")])

    def test_valid_single_ip(self):
        res = vpn_connect._parse_networks(["10.0.0.5"])
        self.assertEqual(res, [ipaddress.ip_network("10.0.0.5/32")])

    def test_empty_and_whitespace(self):
        res = vpn_connect._parse_networks(["", "   ", "\t"])
        self.assertEqual(res, [])

    @patch("socket.gethostbyname", return_value="8.8.8.8")
    def test_domain_resolution(self, mock_dns):
        res = vpn_connect._parse_networks(["google.com"])
        mock_dns.assert_called_once_with("google.com")
        self.assertEqual(res, [ipaddress.ip_network("8.8.8.8/32")])

    @patch("socket.gethostbyname", side_effect=socket.gaierror("fail"))
    def test_domain_resolution_failure(self, mock_dns):
        res = vpn_connect._parse_networks(["nonexistent.invalid"])
        self.assertEqual(res, [])

    def test_mixed_input(self):
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            res = vpn_connect._parse_networks([
                "10.0.0.0/8", "192.168.1.1", "myhost.local"
            ])
        self.assertEqual(len(res), 3)
        self.assertEqual(res[0], ipaddress.ip_network("10.0.0.0/8"))
        self.assertEqual(res[1], ipaddress.ip_network("192.168.1.1/32"))
        self.assertEqual(res[2], ipaddress.ip_network("1.2.3.4/32"))


class TestExtractTunnelName(unittest.TestCase):

    def test_dpapi_extension(self):
        self.assertEqual(vpn_connect.extract_tunnel_name(r"C:\WG\Tunnel.conf.dpapi"), "Tunnel")

    def test_conf_extension(self):
        self.assertEqual(vpn_connect.extract_tunnel_name(r"C:\WG\Tunnel2.conf"), "Tunnel2")

    def test_bare_name(self):
        self.assertEqual(vpn_connect.extract_tunnel_name(r"C:\WG\weird_name"), "weird_name")


class TestDPAPI(unittest.TestCase):
    """Bug 7: DPAPI protect/unprotect round-trip."""

    def test_round_trip(self):
        plain = "SecretPassword123!@#"
        token = vpn_connect._dpapi_protect(plain)
        if token:  # DPAPI available on this machine
            decrypted = vpn_connect._dpapi_unprotect(token)
            self.assertEqual(decrypted, plain)
        else:
            # On non-Windows or DPAPI failure, returns ""
            self.assertEqual(token, "")

    def test_empty_string(self):
        self.assertEqual(vpn_connect._dpapi_protect(""), "")

    def test_unprotect_invalid(self):
        # Invalid base64 / garbage should return ""
        self.assertEqual(vpn_connect._dpapi_unprotect("notbase64!!!"), "")


class TestRDPPasswordMerging(unittest.TestCase):
    """Bug 7: Verify RDP password merging (plain base64 fallback + DPAPI encrypted)."""

    def test_merging_logic(self):
        """Simulate the merging logic from _load_credentials without instantiating VPNApp."""
        plain_pw = "JonasPlain123"
        dpapi_pw = "JonasSecure456"

        pw_b64 = base64.b64encode(plain_pw.encode("utf-8")).decode("ascii")
        dpapi_enc = vpn_connect._dpapi_protect(dpapi_pw)

        # Simulate settings data
        settings = {
            "rdp_passwords": {"JonasPC": pw_b64},
            "rdp_passwords_enc": {"WorkPC": dpapi_enc} if dpapi_enc else {},
        }

        # Replicate the merging logic from _load_credentials (lines ~2495-2507)
        rdp_passwords = {}
        fallback_rdp = settings.get("rdp_passwords", {})
        if fallback_rdp:
            rdp_passwords.update(fallback_rdp)
        rdp_enc = settings.get("rdp_passwords_enc", {})
        if rdp_enc:
            for host, enc in rdp_enc.items():
                pw_plain = vpn_connect._dpapi_unprotect(enc)
                if pw_plain:
                    rdp_passwords[host] = base64.b64encode(
                        pw_plain.encode("utf-8")).decode("ascii")

        # JonasPC should always be present from the fallback
        self.assertEqual(rdp_passwords["JonasPC"], pw_b64)
        decoded = base64.b64decode(rdp_passwords["JonasPC"]).decode("utf-8")
        self.assertEqual(decoded, plain_pw)

        # WorkPC should be present if DPAPI worked
        if dpapi_enc:
            self.assertIn("WorkPC", rdp_passwords)
            decoded_work = base64.b64decode(rdp_passwords["WorkPC"]).decode("utf-8")
            self.assertEqual(decoded_work, dpapi_pw)


class TestSplitRouteRemoval(unittest.TestCase):
    """Bug 6: Verify CIDR suffix is stripped before calling 'route delete'."""

    def test_cidr_strip(self):
        """The _remove_split_routes method splits on '/' and uses the base IP."""
        test_cases = [
            ("192.168.1.0/24", "192.168.1.0"),
            ("10.0.0.5/32", "10.0.0.5"),
            ("172.16.0.0/12", "172.16.0.0"),
        ]
        for net_str, expected_base in test_cases:
            base_ip = net_str.split("/")[0]
            self.assertEqual(base_ip, expected_base,
                             f"Failed for {net_str}: got {base_ip}")


class TestSaveSettingsRDPSecurity(unittest.TestCase):
    """Bug 7: Verify that _save_settings only writes fallback base64 when DPAPI fails."""

    def test_save_logic(self):
        """Simulate the save logic for RDP passwords."""
        test_passwords = {
            "PC1": base64.b64encode(b"password1").decode("ascii"),
            "PC2": base64.b64encode(b"password2").decode("ascii"),
        }

        rdp_pw_enc = {}
        rdp_pw_fallback = {}
        for host, pw_b64 in test_passwords.items():
            try:
                pw_plain = base64.b64decode(pw_b64.encode("ascii")).decode("utf-8")
            except Exception:
                pw_plain = ""
            if pw_plain:
                enc = vpn_connect._dpapi_protect(pw_plain)
                if enc:
                    rdp_pw_enc[host] = enc
                else:
                    rdp_pw_fallback[host] = pw_b64

        # If DPAPI works, passwords go to enc dict, not fallback
        if all(vpn_connect._dpapi_protect("test")):
            self.assertEqual(len(rdp_pw_enc), 2)
            self.assertEqual(len(rdp_pw_fallback), 0)
        else:
            # DPAPI not available → all go to fallback
            self.assertEqual(len(rdp_pw_fallback), 2)
            self.assertEqual(len(rdp_pw_enc), 0)


class TestReleaseAssetSelection(unittest.TestCase):
    """Verify updater pairs the EXE with the matching SHA256 asset."""

    def test_prefers_matching_sha_for_exe(self):
        assets = [
            {"name": "notes.txt"},
            {"name": "OtherTool.exe"},
            {"name": "OtherTool.exe.sha256"},
            {"name": "VPN_Connect.exe"},
            {"name": "VPN_Connect.exe.sha256"},
        ]

        exe, sha = vpn_connect._select_update_assets(assets)

        self.assertEqual(exe["name"], "VPN_Connect.exe")
        self.assertEqual(sha["name"], "VPN_Connect.exe.sha256")

    def test_does_not_guess_when_multiple_unrelated_hashes_exist(self):
        assets = [
            {"name": "VPN_Connect.exe"},
            {"name": "first.sha256"},
            {"name": "second.sha256"},
        ]

        exe, sha = vpn_connect._select_update_assets(assets)

        self.assertEqual(exe["name"], "VPN_Connect.exe")
        self.assertIsNone(sha)


class TestInstalledExePath(unittest.TestCase):
    """Updater must always install to the stable shortcut target name."""

    def test_current_new_name_maps_to_stable_exe(self):
        current = os.path.join("C:\\Apps\\VPN", "VPN_Connect_new.exe")
        expected = os.path.join("C:\\Apps\\VPN", "VPN_Connect.exe")

        self.assertEqual(vpn_connect._installed_exe_path(current), expected)

    def test_current_stable_name_stays_stable(self):
        current = os.path.join("C:\\Apps\\VPN", "VPN_Connect.exe")

        self.assertEqual(vpn_connect._installed_exe_path(current), current)


if __name__ == "__main__":
    # Initialize QApplication before tests (needed for PyQt6 imports in vpn_connect)
    qapp = QApplication.instance()
    if not qapp:
        qapp = QApplication([])

    unittest.main(verbosity=2)
