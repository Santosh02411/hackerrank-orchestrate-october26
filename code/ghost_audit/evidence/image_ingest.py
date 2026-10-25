"""Screenshots (PNG/JPEG) -> observations, by offline OCR (Stage 1C).

Pipeline: validate -> OCR twice with independent configurations (default ``psm 11`` and ``psm 6``, both
at 2x) -> regroup the first pass into visual rows/cells -> label every identifier as uncertain when its
word confidence is below ``OCR_CONFIDENCE_THRESHOLD`` or when the second pass did not reproduce it
exactly. Failures are explicit: a missing Tesseract is ``DEPENDENCY_MISSING`` (never a silent skip), an
unreadable/unsupported picture is ``OCR_FAILED`` / ``IMAGE_UNSUPPORTED_FORMAT``, and an image with no
recognised text is ``OCR_NO_TEXT``.
"""
from __future__ import annotations

import os
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .builders import FileContext
from .document_rows import DocRow, OCR_CONFIDENCE_THRESHOLD, find_anchors, finalize_document, rows_from_words
from .manifest import resolve_inside
from .model import EvidenceFileRef, ParsedFile, ParseStatus, SourceFormat
from .ocr import INSTALL_HINT, OcrError, OcrPass, find_tesseract, pillow_available, run_pass, tesseract_version

MAX_IMAGE_BYTES = 25 * 1024 * 1024
PASSES: Tuple[Tuple[int, int], ...] = ((11, 2), (6, 2))   # (psm, upscale); the first is the primary reading
_PNG, _JPEG = b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff"


def image_size(head: bytes) -> Optional[Tuple[int, int]]:
    if head.startswith(_PNG) and len(head) >= 24:
        return struct.unpack(">II", head[16:24])
    return None


def pass_summary(p: OcrPass) -> Dict[str, Any]:
    confs = [w.conf for w in p.words]
    return {"psm": p.psm, "upscale": p.scale, "words": len(p.words),
            "mean_confidence": round(sum(confs) / len(confs), 1) if confs else None,
            "words_below_threshold": sum(1 for c in confs if c < OCR_CONFIDENCE_THRESHOLD)}


def ocr_rows(cmd: str, image_path: Path, width: Optional[int]) -> Tuple[List[DocRow], Set[Tuple[str, str]], List[Tuple[str, str]], Dict[str, Any]]:
    """Two independent OCR passes -> (primary rows, anchors of the other pass(es), anchors only they found, diagnostics)."""
    scale = 1 if not pillow_available() else None
    configs = [(psm, scale or sc) for psm, sc in PASSES]
    with ThreadPoolExecutor(max_workers=len(configs)) as pool:
        passes = list(pool.map(lambda c: run_pass(cmd, image_path, c[0], c[1]), configs))
    primary = passes[0]
    w = width or max((x.left + x.width for x in primary.words), default=1)
    rows = rows_from_words(primary.words, w)
    seen = {(a.kind, a.value) for r in rows for a in find_anchors(r)[0]}
    other: Set[Tuple[str, str]] = set()
    for p in passes[1:]:
        other |= {(a.kind, a.value) for r in rows_from_words(p.words, w) for a in find_anchors(r)[0]}
    diag = {"backend": "tesseract", "version": tesseract_version(cmd), "language": "eng",
            "confidence_threshold": OCR_CONFIDENCE_THRESHOLD, "upscale_applied": configs[0][1] != 1,
            "passes": [pass_summary(p) for p in passes], "image_width": width}
    return rows, other, sorted(other - seen), diag


def parse_image_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.IMAGE, status=ParseStatus.PARSED, layout="image:screenshot_ocr", ref=ref)
    ctx = FileContext(ref, ref.file_path, SourceFormat.IMAGE)

    def fail(code: str, message: str) -> ParsedFile:
        ctx.warn(code, message)
        parsed.status = ParseStatus.FAILED
        parsed.warnings = ctx.warnings
        parsed.coverage.containers_seen = 1
        return parsed.finalize()

    try:
        path = resolve_inside(dataset_dir, ref.file_path)
        size = os.path.getsize(str(path))
        with open(str(path), "rb") as handle:
            head = handle.read(32)
    except (OSError, ValueError) as exc:
        return fail("FILE_UNREADABLE", "cannot read %s: %s" % (ref.file_path, exc))
    if size > MAX_IMAGE_BYTES:
        return fail("FILE_TOO_LARGE", "%d bytes exceeds the %d byte limit for screenshots" % (size, MAX_IMAGE_BYTES))
    if not (head.startswith(_PNG) or head.startswith(_JPEG)):
        return fail("IMAGE_UNSUPPORTED_FORMAT", "file does not start with a PNG or JPEG signature")
    cmd = find_tesseract()
    if cmd is None:
        return fail("DEPENDENCY_MISSING", "Tesseract OCR was not found: " + INSTALL_HINT)
    if not pillow_available():
        ctx.warn("OCR_UPSCALE_UNAVAILABLE", "Pillow is not installed: OCR runs at native resolution, which misreads small identifiers "
                 "(e.g. areed1433 -> areedi433). `pip install Pillow` for the 2x upscale.")
    try:
        rows, other, only_other, diag = ocr_rows(cmd, path, (image_size(head) or (None, None))[0])
    except OcrError as exc:
        return fail("OCR_FAILED", str(exc))
    diag["image"] = {"bytes": size, "width": (image_size(head) or (None, None))[0], "height": (image_size(head) or (None, None))[1]}
    if not rows:
        parsed.metadata["extraction"] = diag
        return fail("OCR_NO_TEXT", "OCR recognised no text in the image")
    parsed.metadata.update({"passes": [p["psm"] for p in diag["passes"]]})
    return finalize_document(ctx, parsed, rows, diag, collection="screenshot_row", secondary_values=other, ocr=True, secondary_only=only_other)
