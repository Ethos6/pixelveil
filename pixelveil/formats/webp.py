from __future__ import annotations

from .common import Finding, FormatError, ParseResult, result


def parse(data: bytes, *, clean: bool, remove_provenance: bool) -> ParseResult:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        raise FormatError("invalid WebP RIFF header")
    declared = int.from_bytes(data[4:8], "little") + 8
    if declared < 12 or declared > len(data):
        raise FormatError("WebP RIFF size exceeds file size")
    if declared < len(data):
        trailing = len(data) - declared
    else:
        trailing = 0
    chunks: list[tuple[bytes, bytes, int, int]] = []
    findings: list[Finding] = []
    removed: list[Finding] = []
    warnings: list[str] = []
    i = 12
    image_payload = bytearray()
    while i < declared:
        start = i
        if i + 8 > declared:
            raise FormatError("truncated WebP chunk header")
        kind = data[i : i + 4]
        length = int.from_bytes(data[i + 4 : i + 8], "little")
        end = i + 8 + length + (length & 1)
        if end > declared:
            raise FormatError(f"WebP chunk {kind!r} exceeds RIFF size")
        payload = data[i + 8 : i + 8 + length]
        chunks.append((kind, data[start:end], start, length))
        if kind == b"VP8 " or kind == b"VP8L" or kind == b"ALPH" or kind == b"ANMF":
            image_payload.extend(data[start:end])
        label = {b"EXIF": "EXIF metadata", b"XMP ": "XMP metadata", b"C2PA": "C2PA manifest"}.get(kind)
        if label:
            action = "remove" if kind != b"C2PA" else "preserve; optional provenance removal"
            findings.append(Finding(label, kind.decode("ascii"), start, len(data[start:end]), action))
            if clean and (kind in (b"EXIF", b"XMP ") or (kind == b"C2PA" and remove_provenance)):
                removed.append(Finding(label, kind.decode("ascii"), start, len(data[start:end]), "removed"))
                chunks.pop()
            elif kind == b"C2PA":
                warnings.append("C2PA provenance is preserved unless --remove-provenance is selected.")
        i = end

    out_chunks = [chunk for _, chunk, _, _ in chunks]
    # The VP8X feature byte must agree with metadata chunks still present.
    kinds = {kind for kind, _, _, _ in chunks}
    if clean and b"VP8X" in kinds:
        updated: list[bytes] = []
        for kind, chunk, _, length in chunks:
            if kind == b"VP8X":
                if length != 10:
                    raise FormatError("WebP VP8X chunk must have a 10-byte payload")
                payload = bytearray(chunk[8:18])
                if b"EXIF" not in kinds:
                    payload[0] &= ~0x08
                if b"XMP " not in kinds:
                    payload[0] &= ~0x04
                chunk = kind + length.to_bytes(4, "little") + bytes(payload) + (b"\0" if length & 1 else b"")
            updated.append(chunk)
        out_chunks = updated
    body = b"WEBP" + b"".join(out_chunks)
    output = b"RIFF" + len(body).to_bytes(4, "little") + body
    if trailing:
        finding = Finding("trailing bytes after WebP RIFF container", "trailing payload", declared, trailing, "remove")
        findings.append(finding)
        if clean:
            removed.append(Finding(finding.kind, finding.container, finding.offset, finding.byte_count, "removed"))
        else:
            output += data[declared:]
            warnings.append("bytes follow the WebP RIFF container")
    return result(data, output, image_payload, findings, removed, warnings)
