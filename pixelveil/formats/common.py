from __future__ import annotations

from dataclasses import dataclass


AI_METADATA_MARKERS = (
    b"parameters", b"workflow", b"comfyui", b"stable diffusion", b"invokeai",
    b"novelai", b"midjourney", b"trainedalgorithmicmedia",
    b"compositewithtrainedalgorithmicmedia",
)


def metadata_signals(payload: bytes) -> tuple[str, ...]:
    """Identify known metadata labels without returning embedded values."""
    lowered = payload[:1_048_576].lower()
    signals: list[str] = []
    if any(marker in lowered for marker in AI_METADATA_MARKERS):
        signals.append("AI-generation or provenance metadata indicator")
    if b"trainedalgorithmicmedia" in lowered or b"compositewithtrainedalgorithmicmedia" in lowered:
        signals.append("IPTC digital-source declaration")
    if b"c2pa" in lowered or b"jumbf" in lowered:
        signals.append("C2PA/JUMBF provenance indicator")
    return tuple(signals)


class FormatError(ValueError):
    pass


@dataclass(frozen=True)
class Finding:
    kind: str
    container: str
    offset: int
    byte_count: int
    action: str

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "container": self.container,
            "offset": self.offset,
            "byte_count": self.byte_count,
            "action": self.action,
        }


@dataclass(frozen=True)
class ParseResult:
    output: bytes
    image_payload: bytes
    findings: tuple[Finding, ...]
    removed: tuple[Finding, ...]
    warnings: tuple[str, ...]


def result(data: bytes, output: bytes, image_payload: bytearray, findings: list[Finding], removed: list[Finding], warnings: list[str]) -> ParseResult:
    return ParseResult(output, bytes(image_payload), tuple(findings), tuple(removed), tuple(warnings))
