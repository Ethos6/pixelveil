# Format support and limits

PixelVeil edits container structure and leaves supported encoded image payloads untouched. The table describes known behavior; it is not a claim that every private datum in a file can be found.

| Format | Removed by default | Preserved by default | Optional provenance behavior |
|---|---|---|---|
| JPEG | Recognized EXIF/XMP APP1 segments, APP13 Photoshop/IPTC, COM comments, bytes after EOI | ICC APP2, unknown APPn segments, unknown markers, scan bytes, quantization tables | Removes APP11 only when the segment has recognizable C2PA/JUMBF indicators. Other APP11 data is preserved. |
| PNG | `eXIf`, `tEXt`, `zTXt`, `iTXt`, `tIME`, bytes after IEND | Image data, ICC/color chunks, structural chunks, unknown chunks | Removes `caBX` C2PA chunk. |
| WebP | `EXIF`, `XMP ` chunks, bytes outside the declared RIFF container | ICC, image chunks, unknown chunks; clears corresponding EXIF/XMP bits in VP8X | Removes a `C2PA` chunk. |
| GIF | Comment extensions, recognized XMP application extension, bytes after trailer | Image and animation blocks, unknown extensions | Removes the recognized `C2PA_GIF` application extension. |

PixelVeil follows the relevant container identifiers and structures: PNG defines text and EXIF chunks; WebP stores EXIF and XMP in RIFF chunks; and C2PA identifies format-specific manifest containers, including JPEG APP11 and PNG `caBX`. JPEG APP11 is not exclusive to C2PA, so PixelVeil does not remove it unless asked. Sources: [PNG specification](https://www.w3.org/TR/png-3/), [WebP container specification](https://developers.google.com/speed/webp/docs/riff_container), and [C2PA specification 2.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html).

Inspection also checks common metadata text for known AI prompt/workflow field names and IPTC Digital Source Type values. These are heuristic indicators, not proof of image origin. For JPEG, APP segments and quantization tables can reveal encoder characteristics; PixelVeil reports and preserves them rather than claiming they uniquely identify a device.

## Important boundaries

- **Color data stays.** ICC profiles and recognized color information are retained to avoid changing color appearance. Profiles can themselves contain descriptive data.
- **Unknown data stays.** Unknown and vendor-specific chunks are retained because dropping them can damage display, animation, or editing behavior. This means PixelVeil cannot promise that all metadata has been removed.
- **C2PA stays by default.** Provenance may contain authenticity and editing history. Removing it makes that history unavailable and can invalidate provenance claims. JPEG's APP11 marker can carry non-C2PA data too.
- **The image itself stays byte-for-byte encoded.** PixelVeil checks a SHA-256 digest of compressed image payloads before and after. This does not establish that the whole file is metadata-free or anonymous.
- **Only four formats are parsed.** Other formats, embedded images, vendor-specific conventions, steganography, and visible or robust watermarks are out of scope.
- **Provenance is not validated.** PixelVeil recognizes container indicators but does not cryptographically validate C2PA manifests or detect robust pixel-domain watermarks.
- **Input size is capped at 512 MiB.** The tool validates container bounds and PNG CRCs before writing output.
- **Output does not replace input.** PixelVeil creates a new sibling or selected-folder file and refuses if that name already exists.

## Research notes

PNG metadata identifiers and the WebP EXIF/XMP RIFF chunk names come from their published format specifications. The C2PA technical specification documents the relevant manifest containers. Marker detection intentionally reports categories, offsets, and sizes, not raw field values. PixelVeil does not interpret EXIF content or verify C2PA signatures; it only recognizes and edits known container locations.
