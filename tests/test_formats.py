from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from io import BytesIO

from PIL import Image, PngImagePlugin
from pixelveil.core import PixelVeilError, clean_bytes, clean_file, inspect_bytes


def jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xff" + bytes([marker]) + (len(payload) + 2).to_bytes(2, "big") + payload


def png_chunk(kind: bytes, payload: bytes) -> bytes:
    import zlib

    crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return len(payload).to_bytes(4, "big") + kind + payload + crc.to_bytes(4, "big")


def riff_chunk(kind: bytes, payload: bytes) -> bytes:
    return kind + len(payload).to_bytes(4, "little") + payload + (b"\0" if len(payload) & 1 else b"")


def jpeg_fixture() -> bytes:
    return (
        b"\xff\xd8"
        + jpeg_segment(0xE1, b"Exif\0\0private-gps")
        + jpeg_segment(0xED, b"Photoshop 3.0\0private-iptc")
        + jpeg_segment(0xE2, b"ICC_PROFILE\0\x01\x01color-profile")
        + jpeg_segment(0xEB, b"C2PA-test-manifest")
        + jpeg_segment(0xDA, b"\x01\x01\0\0?\0")
        + b"\x12\xff\x00\x34\xff\xd0\x56"
        + b"\xff\xd9"
        + b"trailing-data"
    )


def png_fixture() -> bytes:
    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"\x08\x02\0\0\0"
    return (
        signature
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"tEXt", b"Author\0private-name")
        + png_chunk(b"eXIf", b"private-exif")
        + png_chunk(b"iCCP", b"color-profile")
        + png_chunk(b"caBX", b"c2pa-manifest")
        + png_chunk(b"IDAT", b"compressed-pixels")
        + png_chunk(b"IEND", b"")
        + b"trailing-data"
    )


def webp_fixture() -> bytes:
    vp8x = bytes([0x0C]) + b"\0" * 9  # EXIF and XMP feature bits.
    body = b"WEBP" + b"".join(
        [
            riff_chunk(b"VP8X", vp8x),
            riff_chunk(b"EXIF", b"private-exif"),
            riff_chunk(b"XMP ", b"private-xmp"),
            riff_chunk(b"ICCP", b"color-profile"),
            riff_chunk(b"C2PA", b"c2pa-manifest"),
            riff_chunk(b"VP8 ", b"encoded-image-payload"),
        ]
    )
    return b"RIFF" + len(body).to_bytes(4, "little") + body + b"tail"


def gif_fixture() -> bytes:
    header = b"GIF89a" + b"\x01\0\x01\0\0\0\0"
    comment = b"\x21\xfe\x0ccomment-only\0"
    xmp = b"\x21\xff\x0bXMP DataXMP\x09xmp-only!\0"
    c2pa = b"\x21\xff\x0bC2PA_GIF   \x09c2pa-only\0"
    image = b"\x2c\0\0\0\0\x01\0\x01\0\0\x02\x02\x44\x01\0"
    return header + comment + xmp + c2pa + image + b"\x3b" + b"tail"


class FormatCleaningTests(unittest.TestCase):
    def test_jpeg_removes_metadata_and_trailer_but_keeps_color_and_scan(self) -> None:
        original = jpeg_fixture()
        cleaned, report = clean_bytes(original)
        self.assertTrue(report.image_payload_unchanged)
        self.assertIn(b"ICC_PROFILE", cleaned)
        self.assertIn(b"C2PA-test-manifest", cleaned)
        self.assertNotIn(b"private-gps", cleaned)
        self.assertNotIn(b"private-iptc", cleaned)
        self.assertNotIn(b"trailing-data", cleaned)
        self.assertEqual([item["kind"] for item in report.removed], [
            "EXIF metadata", "Photoshop/IPTC metadata", "trailing bytes after JPEG EOI"
        ])

    def test_jpeg_c2pa_removal_is_explicit(self) -> None:
        cleaned, report = clean_bytes(jpeg_fixture(), remove_provenance=True)
        self.assertNotIn(b"C2PA-test-manifest", cleaned)
        self.assertTrue(any("APP11" in warning for warning in report.warnings))

    def test_png_strips_text_and_exif_keeps_color_and_provenance_by_default(self) -> None:
        cleaned, report = clean_bytes(png_fixture())
        self.assertTrue(report.image_payload_unchanged)
        self.assertIn(b"iCCP", cleaned)
        self.assertIn(b"caBX", cleaned)
        self.assertNotIn(b"private-name", cleaned)
        self.assertNotIn(b"private-exif", cleaned)
        self.assertNotIn(b"trailing-data", cleaned)

    def test_png_optional_provenance_removal(self) -> None:
        cleaned, report = clean_bytes(png_fixture(), remove_provenance=True)
        self.assertNotIn(b"caBX", cleaned)
        self.assertTrue(any(item["kind"] == "C2PA manifest" for item in report.removed))

    def test_png_rejects_bad_crc(self) -> None:
        data = bytearray(png_fixture())
        data[41] ^= 0x01
        with self.assertRaisesRegex(ValueError, "invalid CRC"):
            inspect_bytes(bytes(data))

    def test_webp_metadata_removal_updates_sizes_and_feature_bits(self) -> None:
        cleaned, report = clean_bytes(webp_fixture())
        self.assertTrue(report.image_payload_unchanged)
        self.assertNotIn(b"private-exif", cleaned)
        self.assertNotIn(b"private-xmp", cleaned)
        self.assertIn(b"color-profile", cleaned)
        self.assertIn(b"c2pa-manifest", cleaned)
        self.assertEqual(int.from_bytes(cleaned[4:8], "little") + 8, len(cleaned))
        self.assertEqual(cleaned[20] & 0x0C, 0)

    def test_webp_optional_c2pa_removal(self) -> None:
        cleaned, report = clean_bytes(webp_fixture(), remove_provenance=True)
        self.assertNotIn(b"c2pa-manifest", cleaned)
        self.assertTrue(any(item["kind"] == "C2PA manifest" for item in report.removed))

    def test_gif_removes_comment_and_xmp_preserving_animation_payload(self) -> None:
        cleaned, report = clean_bytes(gif_fixture())
        self.assertTrue(report.image_payload_unchanged)
        self.assertNotIn(b"comment-only", cleaned)
        self.assertNotIn(b"xmp-only!", cleaned)
        self.assertIn(b"c2pa-only", cleaned)
        self.assertIn(b"C2PA_GIF", cleaned)
        self.assertEqual(cleaned[-1:], b";")

    def test_gif_optional_c2pa_removal(self) -> None:
        cleaned, _ = clean_bytes(gif_fixture(), remove_provenance=True)
        self.assertNotIn(b"C2PA_GIF", cleaned)

    def test_inspection_reports_categories_without_raw_values(self) -> None:
        scan = inspect_bytes(jpeg_fixture())
        rendered = repr(scan.to_dict())
        self.assertIn("EXIF metadata", rendered)
        self.assertNotIn("private-gps", rendered)

    def test_png_reports_ai_prompt_and_iptc_indicators_without_values(self) -> None:
        signature = b"\x89PNG\r\n\x1a\n"
        ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + b"\x08\x02\0\0\0"
        payload = b"parameters\0secret prompt text trainedAlgorithmicMedia"
        sample = signature + png_chunk(b"IHDR", ihdr) + png_chunk(b"tEXt", payload) + png_chunk(b"IDAT", b"pixels") + png_chunk(b"IEND", b"")
        scan = inspect_bytes(sample)
        rendered = repr(scan.to_dict())
        kinds = [row["kind"] for row in scan.findings]
        self.assertIn("AI-generation or provenance metadata indicator", kinds)
        self.assertIn("IPTC digital-source declaration", kinds)
        self.assertNotIn("secret prompt text", rendered)

    def test_unknown_jpeg_app11_is_preserved_even_with_provenance_option(self) -> None:
        data = b"\xff\xd8" + jpeg_segment(0xEB, b"unrelated JPEG extension") + jpeg_segment(0xDA, b"\x01\x01\0\0?\0") + b"pixels\xff\xd9"
        cleaned, report = clean_bytes(data, remove_provenance=True)
        self.assertIn(b"unrelated JPEG extension", cleaned)
        self.assertFalse(any(item["container"] == "APP11" for item in report.removed))

    def test_unknown_format_is_rejected(self) -> None:
        with self.assertRaisesRegex(PixelVeilError, "unsupported image format"):
            inspect_bytes(b"not an image")

    def test_real_images_still_decode_to_identical_pixels_after_cleaning(self) -> None:
        image = Image.new("RGB", (3, 2), (40, 100, 180))
        exif = Image.Exif()
        exif[0x010E] = "private description"
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text("Description", "private description")
        samples = [
            ("JPEG", {"exif": exif}),
            ("PNG", {"pnginfo": png_info}),
            ("WEBP", {"exif": exif.tobytes(), "xmp": b"<x:xmpmeta>private</x:xmpmeta>"}),
            ("GIF", {"comment": b"private comment"}),
        ]
        for format_name, options in samples:
            with self.subTest(format=format_name):
                source = BytesIO()
                image.save(source, format=format_name, **options)
                original = source.getvalue()
                cleaned, report = clean_bytes(original)
                with Image.open(BytesIO(original)) as before, Image.open(BytesIO(cleaned)) as after:
                    before.load()
                    after.load()
                    self.assertEqual(before.size, after.size)
                    self.assertEqual(before.convert("RGB").tobytes(), after.convert("RGB").tobytes())
                self.assertTrue(report.image_payload_unchanged)

    def test_output_is_new_file_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            source = folder / "photo.jpg"
            source.write_bytes(jpeg_fixture())
            target, _ = clean_file(source)
            self.assertTrue(target.exists())
            self.assertEqual(source.read_bytes(), jpeg_fixture())
            with self.assertRaisesRegex(PixelVeilError, "refusing to overwrite"):
                clean_file(source)


if __name__ == "__main__":
    unittest.main()
