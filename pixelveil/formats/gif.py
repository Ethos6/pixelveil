from __future__ import annotations

from .common import Finding, FormatError, ParseResult, metadata_signals, result


def _subblocks(data: bytes, pos: int, limit: int) -> tuple[int, bytes]:
    start = pos
    body = bytearray()
    while True:
        if pos >= limit:
            raise FormatError("truncated GIF data sub-block")
        size = data[pos]
        pos += 1
        if size == 0:
            return pos, bytes(body)
        if pos + size > limit:
            raise FormatError("GIF data sub-block exceeds file size")
        body.extend(data[pos : pos + size])
        pos += size


def _table_bytes(packed: int) -> int:
    return 3 * (1 << ((packed & 0x07) + 1))


def parse(data: bytes, *, clean: bool, remove_provenance: bool) -> ParseResult:
    if len(data) < 13 or data[:6] not in (b"GIF87a", b"GIF89a"):
        raise FormatError("invalid GIF header")
    packed = data[10]
    pos = 13
    if packed & 0x80:
        pos += _table_bytes(packed)
    if pos > len(data):
        raise FormatError("truncated GIF global color table")
    out = bytearray(data[:pos])
    image_payload = bytearray()
    findings: list[Finding] = []
    removed: list[Finding] = []
    warnings: list[str] = []
    saw_trailer = False
    while pos < len(data):
        start = pos
        tag = data[pos]
        pos += 1
        if tag == 0x3B:
            out.append(tag)
            saw_trailer = True
            break
        if tag == 0x2C:  # Image descriptor and LZW data.
            if pos + 9 > len(data):
                raise FormatError("truncated GIF image descriptor")
            descriptor = data[pos : pos + 9]
            pos += 9
            out.append(tag)
            out.extend(descriptor)
            if descriptor[8] & 0x80:
                table_size = _table_bytes(descriptor[8])
                if pos + table_size > len(data):
                    raise FormatError("truncated GIF local color table")
                out.extend(data[pos : pos + table_size])
                pos += table_size
            if pos >= len(data):
                raise FormatError("missing GIF LZW code size")
            out.append(data[pos])
            pos += 1
            block_start = pos
            pos, _ = _subblocks(data, pos, len(data))
            out.extend(data[block_start:pos])
            image_payload.extend(data[start:pos])
            continue
        if tag != 0x21:
            raise FormatError(f"unexpected GIF block 0x{tag:02X} at byte {start}")
        if pos >= len(data):
            raise FormatError("truncated GIF extension")
        label = data[pos]
        pos += 1
        if label == 0xF9:  # Graphic Control Extension: fixed-size block.
            if pos + 6 > len(data) or data[pos] != 4 or data[pos + 5] != 0:
                raise FormatError("invalid GIF graphic control extension")
            block_end = pos + 6
            out.extend(data[start:block_end])
            pos = block_end
            continue
        if label == 0x01:  # Plain-text extension has a fixed 12-byte header.
            if pos >= len(data) or data[pos] != 12 or pos + 13 > len(data):
                raise FormatError("invalid GIF plain-text extension")
            pos += 13
            pos, _ = _subblocks(data, pos, len(data))
            out.extend(data[start:pos])
            continue
        if label == 0xFE:
            pos, contents = _subblocks(data, pos, len(data))
            finding = Finding("GIF comment", "comment extension", start, pos - start, "remove")
            findings.append(finding)
            if clean:
                removed.append(Finding(finding.kind, finding.container, finding.offset, finding.byte_count, "removed"))
            else:
                out.extend(data[start:pos])
                if contents:
                    warnings.append("GIF contains a comment extension")
            continue
        if label == 0xFF:
            if pos >= len(data):
                raise FormatError("truncated GIF application extension")
            app_len = data[pos]
            pos += 1
            if app_len != 11 or pos + app_len > len(data):
                raise FormatError("invalid GIF application identifier")
            app_id = data[pos : pos + app_len]
            pos += app_len
            pos, app_data = _subblocks(data, pos, len(data))
            app_name = app_id.rstrip(b"\0 ").decode("ascii", "replace")
            is_xmp = app_id.startswith(b"XMP DataXMP")
            is_c2pa = app_id.startswith(b"C2PA_GIF")
            if is_xmp or is_c2pa:
                label_name = "GIF XMP metadata" if is_xmp else "C2PA GIF manifest"
                findings.append(Finding(label_name, app_name, start, pos - start, "remove" if is_xmp else "preserve; optional provenance removal"))
                if clean and (is_xmp or (is_c2pa and remove_provenance)):
                    removed.append(Finding(label_name, app_name, start, pos - start, "removed"))
                else:
                    out.extend(data[start:pos])
                    if is_c2pa:
                        warnings.append("C2PA provenance is preserved unless --remove-provenance is selected.")
                    if is_xmp:
                        warnings.append("GIF XMP application data remains in the output.")
            else:
                out.extend(data[start:pos])
            for signal in metadata_signals(app_data):
                findings.append(Finding(signal, app_name, start, pos - start, "remove with the containing GIF extension"))
            continue
        # Unknown extensions are preserved; deleting an unknown block could break playback.
        pos, _ = _subblocks(data, pos, len(data))
        out.extend(data[start:pos])
        warnings.append(f"unknown GIF extension 0x{label:02X} was preserved")
    if not saw_trailer:
        raise FormatError("GIF has no trailer byte")
    if pos < len(data):
        finding = Finding("trailing bytes after GIF trailer", "trailing payload", pos, len(data) - pos, "remove")
        findings.append(finding)
        if clean:
            removed.append(Finding(finding.kind, finding.container, finding.offset, finding.byte_count, "removed"))
        else:
            out.extend(data[pos:])
            warnings.append("bytes follow the GIF trailer")
    return result(data, bytes(out), image_payload, findings, removed, warnings)
