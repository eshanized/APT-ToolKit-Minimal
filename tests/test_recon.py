import unittest
from unittest.mock import patch, MagicMock
from modules import recon
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from modules import recon


class TestReconModule(unittest.TestCase):

    @patch("modules.recon.resolve_hostname", return_value="93.184.216.34")
    @patch("modules.recon.socket.gethostbyaddr", return_value=("example.com", [], ["93.184.216.34"]))
    @patch("modules.recon.whois.whois")
    @patch("modules.recon.socket.gethostbyname_ex", return_value=("example.com", [], ["93.184.216.34"]))
    @patch("modules.recon.requests.get")
    def test_run_successful_recon(
        self,
        mock_requests_get,
        mock_gethostbyname_ex,
        mock_whois,
        mock_gethostbyaddr,
        mock_resolve_hostname
    ):
        # Setup fake whois response
        mock_whois.return_value = MagicMock(
            domain_name="example.com",
            registrar="FakeRegistrar",
            creation_date="2020-01-01",
            expiration_date="2030-01-01",
            name_servers=["ns1.fake.com", "ns2.fake.com"]
        )

        # Setup fake HTTP response
        mock_response = MagicMock()
        mock_response.headers = {"Server": "FakeServer"}
        mock_response.text = "Welcome!"
        mock_response.status_code = 200
        mock_requests_get.return_value = mock_response

        # Run recon
        result = recon.run("example.com")

        # Assertions
        self.assertEqual(result["target"], "example.com")
        self.assertEqual(result["ip_address"], "93.184.216.34")
        self.assertEqual(result["reverse_dns"], "example.com")
        self.assertEqual(result["dns"]["hostname"], "example.com")
        self.assertEqual(result["whois"]["registrar"], "FakeRegistrar")
        self.assertEqual(result["http_headers"]["Server"], "FakeServer")
        self.assertIsNone(result["error"])

    def test_run_with_invalid_target(self):
        result = recon.run("invalid@target")
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
