from __future__ import annotations

from dataclasses import dataclass


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
