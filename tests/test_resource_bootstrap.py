import importlib.util
import struct
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "fetch-resource-bootstrap.py"

spec = importlib.util.spec_from_file_location("resource_bootstrap", SCRIPT)
resource_bootstrap = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(resource_bootstrap)


class ResourceBootstrapTests(unittest.TestCase):
    def wrap_lz4(self, raw_block: bytes, decoded_size: int) -> bytes:
        # The first 4 and last 8 wrapper bytes are not used by the current decoder;
        # offset 4 stores the little-endian uncompressed size.
        return b"CGSS" + struct.pack("<I", decoded_size) + b"\x00" * 8 + raw_block

    def literal_only_block(self, payload: bytes) -> bytes:
        length = len(payload)
        if length < 15:
            return bytes([length << 4]) + payload

        extra = length - 15
        extensions = bytearray()
        while extra >= 255:
            extensions.append(255)
            extra -= 255
        extensions.append(extra)
        return b"\xF0" + bytes(extensions) + payload

    def test_parse_android_manifest_md5(self):
        md5 = "0123456789abcdef0123456789abcdef"
        index = (
            "SomeOtherManifest,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,123\n"
            f"Android_AHigh_SHigh,{md5},456\n"
        ).encode()
        self.assertEqual(resource_bootstrap.parse_android_manifest_md5(index), md5)

    def test_parse_android_manifest_md5_is_case_normalized(self):
        md5 = "ABCDEF0123456789ABCDEF0123456789"
        index = f"Android_AHigh_SHigh,{md5},1\r\n".encode()
        self.assertEqual(
            resource_bootstrap.parse_android_manifest_md5(index), md5.lower()
        )

    def test_parse_android_manifest_md5_rejects_missing_entry(self):
        with self.assertRaises(resource_bootstrap.BootstrapError):
            resource_bootstrap.parse_android_manifest_md5(
                b"Android_ALow_SLow,0123456789abcdef0123456789abcdef,1\n"
            )

    def test_lz4_literal_only_sequence(self):
        payload = b"SQLite format 3\x00synthetic-manifest"
        raw = self.literal_only_block(payload)
        wrapped = self.wrap_lz4(raw, len(payload))
        self.assertEqual(resource_bootstrap.cgss_lz4_decompress(wrapped), payload)

    def test_lz4_overlapping_match_copy(self):
        # token 0x44: 4 literal bytes + (4 + 4) match bytes.
        # offset 4 causes the match to repeat "abcd" twice using overlapping copy.
        expected = b"abcdabcdabcd"
        raw = bytes([0x44]) + b"abcd" + b"\x04\x00"
        wrapped = self.wrap_lz4(raw, len(expected))
        self.assertEqual(resource_bootstrap.cgss_lz4_decompress(wrapped), expected)

    def test_lz4_rejects_declared_size_mismatch(self):
        payload = b"abc"
        raw = self.literal_only_block(payload)
        wrapped = self.wrap_lz4(raw, len(payload) + 1)
        with self.assertRaises(resource_bootstrap.BootstrapError):
            resource_bootstrap.cgss_lz4_decompress(wrapped)

    def test_lz4_rejects_invalid_offset(self):
        # One literal byte, then a match offset larger than produced output.
        raw = bytes([0x10]) + b"a" + b"\x02\x00"
        wrapped = self.wrap_lz4(raw, 5)
        with self.assertRaises(resource_bootstrap.BootstrapError):
            resource_bootstrap.cgss_lz4_decompress(wrapped)


if __name__ == "__main__":
    unittest.main()
