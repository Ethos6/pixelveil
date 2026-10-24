from __future__ import annotations

import zlib

from .common import Finding, FormatError, ParseResult, result


def _png_crc(kind: bytes, payload: bytes) -> int:
    return zlib.crc32(kind + payload) & 0xFFFFFFFF

SIGNATURE = b"\x89PNG\r\n\x1a\n"
PRIVATE_METADATA = {b"eXIf": "EXIF metadata", b"tEXt": "PNG text metadata", b"zTXt": "compressed PNG text metadata", b"iTXt": "international PNG text/XMP metadata", b"tIME": "PNG modification timestamp"}


def parse(data: bytes, *, clean: bool, remove_provenance: bool) -> ParseResult:
    if not data.startswith(SIGNATURE):
        raise FormatError("invalid PNG signature")
    out = bytearray(SIGNATURE)
    image_payload = bytearray()
    findings: list[Finding] = []
    removed: list[Finding] = []
    warnings: list[str] = []
    i = len(SIGNATURE)
    saw_ihdr = False
    saw_iend = False
    chunk_count = 0
    while i < len(data):
        start = i
        if i + 12 > len(data):
            raise FormatError("truncated PNG chunk header")
        length = int.from_bytes(data[i : i + 4], "big")
        kind = data[i + 4 : i + 8]
        end = i + 12 + length
        if end > len(data):
            raise FormatError(f"PNG chunk {kind!r} exceeds file size")
        payload = data[i + 8 : i + 8 + length]
        stored_crc = int.from_bytes(data[i + 8 + length : end], "big")
        if _png_crc(kind, payload) != stored_crc:
            raise FormatError(f"PNG chunk {kind.decode('ascii', 'replace')} has an invalid CRC")
        chunk = data[start:end]
        chunk_count += 1
        if kind == b"IHDR":
            if saw_ihdr or chunk_count != 1 or length != 13:
                raise FormatError("PNG must begin with one 13-byte IHDR chunk")
            saw_ihdr = True
        elif not saw_ihdr:
            raise FormatError("PNG chunk appears before IHDR")

        label = PRIVATE_METADATA.get(kind)
        if kind == b"caBX":
            label = "C2PA manifest"
        if label:
            finding = Finding(label, kind.decode("ascii"), start, len(chunk), "remove" if kind != b"caBX" else "preserve; optional provenance removal")
            findings.append(finding)
            drop = clean and (kind in PRIVATE_METADATA or (kind == b"caBX" and remove_provenance))
            if drop:
                removed.append(Finding(label, kind.decode("ascii"), start, len(chunk), "removed"))
            else:
                out.extend(chunk)
        else:
            out.extend(chunk)

        if kind in (b"IDAT", b"fdAT"):
            image_payload.extend(payload)
        if kind == b"IEND":
            if length != 0:
                raise FormatError("PNG IEND chunk must be empty")
            saw_iend = True
            i = end
            break
        i = end
    if not saw_iend:
        raise FormatError("PNG has no IEND chunk")
    if i < len(data):
        finding = Finding("trailing bytes after PNG IEND", "trailing payload", i, len(data) - i, "remove")
        findings.append(finding)
        if clean:
            removed.append(Finding(finding.kind, finding.container, finding.offset, finding.byte_count, "removed"))
        else:
            out.extend(data[i:])
            warnings.append("bytes follow the PNG IEND chunk")
    return result(data, bytes(out), image_payload, findings, removed, warnings)
