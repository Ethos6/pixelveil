from __future__ import annotations

from .common import Finding, FormatError, ParseResult, metadata_signals, result

SOI = b"\xff\xd8"
STANDALONE = {0x01, *range(0xD0, 0xD8), 0xD8, 0xD9}


def _scan_end(data: bytes, start: int) -> tuple[int, int]:
    """Return the next marker start while ignoring entropy stuffing and restarts."""
    i = start
    while i < len(data) - 1:
        if data[i] != 0xFF:
            i += 1
            continue
        j = i + 1
        while j < len(data) and data[j] == 0xFF:
            j += 1
        if j >= len(data):
            break
        marker = data[j]
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            i = j + 1
            continue
        return i, j
    raise FormatError("JPEG scan has no terminating marker")


def parse(data: bytes, *, clean: bool, remove_provenance: bool) -> ParseResult:
    if not data.startswith(SOI):
        raise FormatError("invalid JPEG start marker")
    out = bytearray(SOI)
    payload = bytearray()
    findings: list[Finding] = []
    removed: list[Finding] = []
    warnings: list[str] = []
    i = 2
    saw_eoi = False

    while i < len(data):
        start = i
        if data[i] != 0xFF:
            raise FormatError(f"expected JPEG marker at byte {i}")
        while i < len(data) and data[i] == 0xFF:
            i += 1
        if i >= len(data):
            raise FormatError("truncated JPEG marker")
        marker = data[i]
        i += 1
        if marker == 0x00:
            raise FormatError("unexpected stuffed byte outside JPEG scan")
        marker_bytes = data[start:i]
        if marker in STANDALONE:
            out.extend(marker_bytes)
            if marker == 0xD9:
                saw_eoi = True
                break
            continue
        if i + 2 > len(data):
            raise FormatError("truncated JPEG segment length")
        length = int.from_bytes(data[i : i + 2], "big")
        if length < 2 or i + length > len(data):
            raise FormatError(f"invalid JPEG segment length at byte {start}")
        segment = data[start : i + length]
        content = data[i + 2 : i + length]
        container = f"APP{marker - 0xE0}" if 0xE0 <= marker <= 0xEF else ("COM" if marker == 0xFE else f"marker 0xFF{marker:02X}")
        kind = None
        lowered = content[:1_048_576].lower()
        if marker == 0xE1:
            if content.startswith(b"Exif\0\0"):
                kind = "EXIF metadata"
            elif content.startswith(b"http://ns.adobe.com/xap/1.0/\0") or content.startswith(b"http://ns.adobe.com/xmp/extension/\0"):
                kind = "XMP metadata"
            else:
                kind = "APP1 application data (preserved)"
        elif marker == 0xED:
            kind = "Photoshop/IPTC metadata"
        elif marker == 0xFE:
            kind = "JPEG comment"
        elif marker == 0xEB:
            kind = "C2PA/JUMBF provenance" if b"c2pa" in lowered or b"jumbf" in lowered else "APP11 application data"
        elif marker == 0xE2 and content.startswith(b"ICC_PROFILE\0"):
            kind = "ICC color profile (preserved)"
        elif marker == 0xEE and content.startswith(b"Adobe"):
            kind = "Adobe APP14 encoder marker (preserved)"
        elif marker == 0xE0 and content.startswith(b"JFIF\0"):
            kind = "JFIF encoder marker (preserved)"
        elif 0xE0 <= marker <= 0xEF:
            kind = f"{container} application data (unclassified; preserved)"
        elif marker == 0xDB:
            kind = "JPEG quantization tables (encoder characteristic; preserved)"
        if kind:
            removable = marker in (0xED, 0xFE) or (marker == 0xE1 and kind in ("EXIF metadata", "XMP metadata"))
            is_provenance = kind == "C2PA/JUMBF provenance"
            action = "remove" if removable else ("preserve; explicit provenance removal requested separately" if is_provenance else "preserve")
            finding = Finding(kind, container, start, len(segment), action)
            findings.append(finding)
            drop = clean and (removable or (is_provenance and remove_provenance))
            if drop:
                removed.append(Finding(kind, container, start, len(segment), "removed"))
                if is_provenance:
                    warnings.append("C2PA/JUMBF APP11 data was removed on request; APP11 also carries unrelated JPEG extensions, which were preserved when not recognized as C2PA/JUMBF.")
            else:
                out.extend(segment)
        else:
            out.extend(segment)

        if marker in (0xE1, 0xED):
            for signal in metadata_signals(content):
                findings.append(Finding(signal, container, start, len(segment), "remove with the containing metadata segment"))

        i += length
        if marker == 0xDA:  # Start of Scan: preserve compressed bytes verbatim.
            end, _ = _scan_end(data, i)
            payload.extend(data[i:end])
            out.extend(data[i:end])
            i = end

    if not saw_eoi:
        raise FormatError("JPEG has no end-of-image marker")
    if i < len(data):
        finding = Finding("trailing bytes after JPEG EOI", "trailing payload", i, len(data) - i, "remove")
        findings.append(finding)
        if clean:
            removed.append(Finding(finding.kind, finding.container, finding.offset, finding.byte_count, "removed"))
        else:
            out.extend(data[i:])
            warnings.append("bytes follow the JPEG end marker")
    return result(data, bytes(out), payload, findings, removed, warnings)
