from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import tempfile
import unittest
from pathlib import Path

from PIL import Image, PngImagePlugin

from pixelveil.cli import _diff, _expand_paths
from pixelveil.core import clean_file


class FolderExpansionTests(unittest.TestCase):
    def test_recursive_expansion_finds_supported_images_and_skips_cleaned_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "top.png").write_bytes(b"x")
            (root / "top.cleaned.png").write_bytes(b"x")
            nested = root / "nested"
            nested.mkdir()
            (nested / "inside.webp").write_bytes(b"x")
            (nested / "notes.txt").write_text("not an image")

            shallow = _expand_paths([root], recursive=False)
            recursive = _expand_paths([root], recursive=True)

            self.assertEqual([p.name for p in shallow], ["top.png"])
            self.assertEqual({p.name for p in recursive}, {"top.png", "inside.webp"})

    def test_diff_reports_payload_and_metadata_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "photo.png"
            info = PngImagePlugin.PngInfo()
            info.add_text("Description", "private note")
            Image.new("RGB", (2, 2), (20, 40, 60)).save(source, pnginfo=info)
            cleaned, _ = clean_file(source)
            output = StringIO()
            with redirect_stdout(output):
                code = _diff(source, cleaned, as_json=True)
            report = json.loads(output.getvalue())
            self.assertEqual(code, 0)
            self.assertTrue(report["image_payload_unchanged"])
            self.assertIn("PNG text metadata", report["removed_categories"])


if __name__ == "__main__":
    unittest.main()
