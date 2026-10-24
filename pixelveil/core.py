from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from pathlib import Path
import os
import tempfile

from .formats import gif, jpeg, png, webp

MAX_INPUT_BYTES = 512 * 1024 * 1024
PARSERS = {
    "JPEG": jpeg.parse,
    "PNG": png.parse,
    "WebP": webp.parse,
    "GIF": gif.parse,
}


class PixelVeilError(Exception):
    """Expected input or output error suitable for a concise CLI message."""


@dataclass(frozen=True)
class Scan:
    format: str
    byte_count: int
    sha256: str
    image_payload_sha256: str
    findings: tuple[dict[str, object], ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class CleanResult:
    format: str
    input_bytes: int
    output_bytes: int
    input_sha256: str
    output_sha256: str
    image_payload_unchanged: bool
    removed: tuple[dict[str, object], ...]
    remaining: tuple[dict[str, object], ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _format(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WebP"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    raise PixelVeilError("unsupported image format; supported formats are JPEG, PNG, WebP, and GIF")


def _read(path: Path) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise PixelVeilError(f"cannot read {path.name}: {exc.strerror or exc}") from exc
    if size > MAX_INPUT_BYTES:
        raise PixelVeilError(f"{path.name}: exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB input limit")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PixelVeilError(f"cannot read {path.name}: {exc.strerror or exc}") from exc
    if len(data) != size:
        raise PixelVeilError(f"{path.name}: file changed while it was being read")
    return data


def inspect_bytes(data: bytes) -> Scan:
    if len(data) > MAX_INPUT_BYTES:
        raise PixelVeilError(f"input exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit")
    fmt = _format(data)
    result = PARSERS[fmt](data, clean=False, remove_provenance=False)
    return Scan(
        format=fmt,
        byte_count=len(data),
        sha256=_sha(data),
        image_payload_sha256=_sha(result.image_payload),
        findings=tuple(f.to_dict() for f in result.findings),
        warnings=tuple(result.warnings),
    )


def inspect_file(path: Path) -> Scan:
    return inspect_bytes(_read(path))


def clean_bytes(data: bytes, *, remove_provenance: bool = False) -> tuple[bytes, CleanResult]:
    if len(data) > MAX_INPUT_BYTES:
        raise PixelVeilError(f"input exceeds the {MAX_INPUT_BYTES // (1024 * 1024)} MiB limit")
    fmt = _format(data)
    before = PARSERS[fmt](data, clean=False, remove_provenance=False)
    cleaned = PARSERS[fmt](data, clean=True, remove_provenance=remove_provenance)
    after = PARSERS[fmt](cleaned.output, clean=False, remove_provenance=False)
    payload_same = _sha(before.image_payload) == _sha(after.image_payload)
    if not payload_same:
        raise PixelVeilError("verification failed: encoded image payload changed")
    result = CleanResult(
        format=fmt,
        input_bytes=len(data),
        output_bytes=len(cleaned.output),
        input_sha256=_sha(data),
        output_sha256=_sha(cleaned.output),
        image_payload_unchanged=payload_same,
        removed=tuple(f.to_dict() for f in cleaned.removed),
        remaining=tuple(f.to_dict() for f in after.findings),
        warnings=tuple(dict.fromkeys(before.warnings + cleaned.warnings + after.warnings)),
    )
    return cleaned.output, result


def clean_file(path: Path, output_dir: Path | None = None, *, remove_provenance: bool = False) -> tuple[Path, CleanResult]:
    data = _read(path)
    cleaned, result = clean_bytes(data, remove_provenance=remove_provenance)
    folder = output_dir if output_dir is not None else path.parent
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PixelVeilError(f"cannot create output directory {folder}: {exc.strerror or exc}") from exc
    target = folder / f"{path.stem}.cleaned{path.suffix}"
    if path.resolve() == target.resolve():
        raise PixelVeilError("refusing to replace the input file")
    try:
        fd, temp_name = tempfile.mkstemp(prefix=".pixelveil-", suffix=".tmp", dir=folder)
        temp_path = Path(temp_name)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(cleaned)
                stream.flush()
                os.fsync(stream.fileno())
            # Hard-link creation is atomic and fails if the destination already exists.
            os.link(temp_path, target)
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    except FileExistsError as exc:
        raise PixelVeilError(f"refusing to overwrite existing output: {target.name}") from exc
    except OSError as exc:
        raise PixelVeilError(f"cannot write {target}: {exc.strerror or exc}") from exc
    return target, result
