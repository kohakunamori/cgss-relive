from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID


SCRIPT = pathlib.Path(__file__).parents[1] / "scripts" / "make-test-tls-cert.py"
SPEC = importlib.util.spec_from_file_location("make_test_tls_cert", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class TestTLSCertificateGenerator(unittest.TestCase):
    def test_generates_ca_and_hostname_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = MODULE.generate(pathlib.Path(directory), "apis.game.starlight-stage.jp", days=2)
            for path in paths.values():
                self.assertTrue(path.exists())

            ca = x509.load_pem_x509_certificate(paths["ca_cert"].read_bytes())
            leaf = x509.load_pem_x509_certificate(paths["server_cert"].read_bytes())
            self.assertTrue(ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
            self.assertEqual(leaf.issuer, ca.subject)
            sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertIn("apis.game.starlight-stage.jp", sans.get_values_for_type(x509.DNSName))
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            self.assertIn(ExtendedKeyUsageOID.SERVER_AUTH, eku)

            chain = paths["server_chain"].read_bytes()
            self.assertGreaterEqual(chain.count(b"BEGIN CERTIFICATE"), 2)


if __name__ == "__main__":
    unittest.main()
