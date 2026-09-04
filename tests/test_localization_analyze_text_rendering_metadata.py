from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest

MODULE_PATH = (
    pathlib.Path(__file__).parents[1]
    / "localization"
    / "tools"
    / "analyze_text_rendering_metadata.py"
)
SPEC = importlib.util.spec_from_file_location("analyze_text_rendering_metadata", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


IL2CPP_DUMPER_STYLE = """
// Namespace: UnityEngine.UI
public class Text : MaskableGraphic
{
    // RVA: 0x1234 Offset: 0x1234 VA: 0x1234
    public string get_text() { }
    // RVA: 0x1250 Offset: 0x1250 VA: 0x1250
    public void set_text(string value) { }
    // RVA: 0x1270 Offset: 0x1270 VA: 0x1270
    public void Unrelated() { }
}

// Namespace: TMPro
public abstract class TMP_Text : MaskableGraphic
{
    // RVA: 0x2200 Offset: 0x2200 VA: 0x2200
    public virtual string get_text() { }
    // RVA: 0x2210 Offset: 0x2210 VA: 0x2210
    public virtual void set_text(string value) { }
    // RVA: 0x2220 Offset: 0x2220 VA: 0x2220
    public void SetText(string sourceText) { }
}

public class TMP_FontAsset : TMP_Asset
{
    // RVA: 0x3300 Offset: 0x3300 VA: 0x3300
    public List<TMP_FontAsset> get_fallbackFontAssetTable() { }
}
"""

STANDARD_CS_STYLE = """
namespace UnityEngine
{
    public class Font
    {
        // RVA: 0x4400 Offset: 0x4400 VA: 0x4400
        public int get_fontSize() { }
    }
}
"""


class AnalyzeTextRenderingMetadataTests(unittest.TestCase):
    def analyze(self, content: str):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "dump.cs"
            path.write_text(content, encoding="utf-8")
            return MODULE.analyze_dump_cs(path)

    def test_extracts_il2cppdumper_namespace_comment_format(self) -> None:
        report = self.analyze(IL2CPP_DUMPER_STYLE)
        self.assertEqual(report["schema_version"], 2)

        text = report["targets"]["UnityEngine.UI.Text"]
        self.assertTrue(text["present"])
        self.assertEqual(
            text["interesting_methods"],
            [
                {"name": "get_text", "rva": "0x1234"},
                {"name": "set_text", "rva": "0x1250"},
            ],
        )

        tmp = report["targets"]["TMPro.TMP_Text"]
        self.assertTrue(tmp["present"])
        self.assertEqual(
            [item["name"] for item in tmp["interesting_methods"]],
            ["get_text", "set_text", "SetText"],
        )

        font = report["targets"]["TMPro.TMP_FontAsset"]
        self.assertTrue(font["present"])
        self.assertEqual(
            font["interesting_methods"],
            [{"name": "get_fallbackFontAssetTable", "rva": "0x3300"}],
        )
        self.assertFalse(report["targets"]["TMPro.TextMeshProUGUI"]["present"])

    def test_also_accepts_standard_csharp_namespace_blocks(self) -> None:
        report = self.analyze(STANDARD_CS_STYLE)
        font = report["targets"]["UnityEngine.Font"]
        self.assertTrue(font["present"])
        self.assertEqual(
            font["interesting_methods"],
            [{"name": "get_fontSize", "rva": "0x4400"}],
        )


if __name__ == "__main__":
    unittest.main()
