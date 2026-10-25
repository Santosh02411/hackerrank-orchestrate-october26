
"""Screenshots (PNG/JPEG) -> observations, by offline OCR (Stage 1C).

Pipeline: validate -> OCR twice with independent configurations (default
psm 11 and psm 6, both at 2x when Pillow is available) -> regroup the first
pass into visual rows/cells -> label identifiers uncertain when confidence
is low or the second standard pass did not reproduce them exactly.

A native-resolution recovery pass may recover identifiers missed by both
standard passes. Recovery never corrects a standard reading and recovered
identifiers remain uncertain.
"""
from __future__ import annotations

import os
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .builders import FileContext
from .document_rows import (
    DocRow,
    OCR_CONFIDENCE_THRESHOLD,
    find_anchors,
    finalize_document,
    rows_from_words,
)
from .manifest import resolve_inside
from .model import EvidenceFileRef, ParsedFile, ParseStatus, SourceFormat
from .ocr import (
    INSTALL_HINT,
    OcrError,
    OcrPass,
    OcrWord,
    find_tesseract,
    pillow_available,
    run_pass,
    tesseract_version,
)

MAX_IMAGE_BYTES = 25 * 1024 * 1024
PASSES: Tuple[Tuple[int, int], ...] = ((11, 2), (6, 2))
_PNG, _JPEG = b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff"


def image_size(head: bytes) -> Optional[Tuple[int, int]]:
    if head.startswith(_PNG) and len(head) >= 24:
        return struct.unpack(">II", head[16:24])
    return None


def pass_summary(p: OcrPass) -> Dict[str, Any]:
    confs = [word.conf for word in p.words]
    return {
        "psm": p.psm,
        "upscale": p.scale,
        "words": len(p.words),
        "mean_confidence": (
            round(sum(confs) / len(confs), 1) if confs else None
        ),
        "words_below_threshold": sum(
            1 for confidence in confs
            if confidence < OCR_CONFIDENCE_THRESHOLD
        ),
    }


def ocr_rows(
    cmd: str,
    image_path: Path,
    width: Optional[int],
) -> Tuple[
    List[DocRow],
    Set[Tuple[str, str]],
    List[Tuple[str, str]],
    Dict[str, Any],
]:
    """Run standard OCR passes and recover only identifiers both passes missed."""
    has_pillow = pillow_available()

    configs = [
        (psm, scale if has_pillow else 1)
        for psm, scale in PASSES
    ]

    with ThreadPoolExecutor(max_workers=len(configs)) as pool:
        passes = list(
            pool.map(
                lambda config: run_pass(
                    cmd, image_path, config[0], config[1]
                ),
                configs,
            )
        )

    primary = passes[0]
    image_width = width or max(
        (word.left + word.width for word in primary.words),
        default=1,
    )

    rows = rows_from_words(primary.words, image_width)

    def anchors_in(words: Tuple[OcrWord, ...]) -> Set[Tuple[str, str]]:
        found: Set[Tuple[str, str]] = set()
        for row in rows_from_words(words, image_width):
            anchors, _ = find_anchors(row)
            found.update(
                (anchor.kind, anchor.value)
                for anchor in anchors
            )
        return found

    # Standard pass 1 supplies observations; pass 2 checks reproducibility.
    seen = anchors_in(primary.words)
    other: Set[Tuple[str, str]] = set()

    for result in passes[1:]:
        other.update(anchors_in(result.words))

    secondary_only = sorted(other - seen)

    recovery: Optional[OcrPass] = None
    recovery_used = False

    # Do not run recovery when Pillow is absent: standard OCR already uses
    # native resolution in that case, and tests rely on that fallback.
    if has_pillow:
        recovery = run_pass(cmd, image_path, 11, 1)
        recovery_rows = rows_from_words(
            recovery.words, image_width
        )

        standard_values = seen | other
        recovered_rows: List[DocRow] = []

        for recovery_row in recovery_rows:
            anchors, _ = find_anchors(recovery_row)
            missing_values = {
                (anchor.kind, anchor.value)
                for anchor in anchors
                if (anchor.kind, anchor.value) not in standard_values
            }

            if not missing_values:
                continue

            # Keep only original OCR words that themselves contain a
            # complete, valid missing identifier. Preserve their coordinates
            # and confidence instead of rebuilding them from cell geometry.
            selected_words = []

            for word in recovery.words:
                word_rows = rows_from_words([word], image_width)
                word_anchors: Set[Tuple[str, str]] = set()

                for word_row in word_rows:
                    word_found, _ = find_anchors(word_row)
                    word_anchors.update(
                        (anchor.kind, anchor.value)
                        for anchor in word_found
                    )

                if word_anchors & missing_values:
                    selected_words.append(word)

            if not selected_words:
                continue

            # A recovered row contains only identifiers missing from BOTH
            # standard passes, so unrelated primary observations aren't
            # duplicated. Recovery-only values remain uncertain because they
            # are absent from `other`.
            selected_rows = rows_from_words(
                selected_words, image_width
            )

            for selected_row in selected_rows:
                recovered_rows.append(
                    DocRow(
                        page=selected_row.page,
                        index=0,  # assigned uniquely below
                        cells=selected_row.cells,
                        multi_region=selected_row.multi_region,
                        ocr=True,
                    )
                )

        next_index = max(
            (row.index for row in rows),
            default=0,
        ) + 1

        for recovered_row in recovered_rows:
            rows.append(
                DocRow(
                    page=recovered_row.page,
                    index=next_index,
                    cells=recovered_row.cells,
                    multi_region=recovered_row.multi_region,
                    ocr=True,
                )
            )
            next_index += 1

        recovery_used = bool(recovered_rows)

    diag: Dict[str, Any] = {
        "backend": "tesseract",
        "version": tesseract_version(cmd),
        "language": "eng",
        "confidence_threshold": OCR_CONFIDENCE_THRESHOLD,
        "upscale_applied": any(
            result.scale != 1 for result in passes
        ),
        "passes": [pass_summary(result) for result in passes],
        "image_width": width,
    }

    if recovery is not None:
        diag["recovery_pass"] = pass_summary(recovery)
        diag["recovery_used"] = recovery_used

    return rows, other, secondary_only, diag


def parse_image_file(
    ref: EvidenceFileRef,
    dataset_dir: Union[str, Path],
) -> ParsedFile:
    parsed = ParsedFile(
        source=ref.file_path,
        source_format=SourceFormat.IMAGE,
        status=ParseStatus.PARSED,
        layout="image:screenshot_ocr",
        ref=ref,
    )
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
        return fail(
            "FILE_UNREADABLE",
            "cannot read %s: %s" % (ref.file_path, exc),
        )

    if size > MAX_IMAGE_BYTES:
        return fail(
            "FILE_TOO_LARGE",
            "%d bytes exceeds the %d byte limit for screenshots"
            % (size, MAX_IMAGE_BYTES),
        )

    if not (head.startswith(_PNG) or head.startswith(_JPEG)):
        return fail(
            "IMAGE_UNSUPPORTED_FORMAT",
            "file does not start with a PNG or JPEG signature",
        )

    cmd = find_tesseract()
    if cmd is None:
        return fail(
            "DEPENDENCY_MISSING",
            "Tesseract OCR was not found: " + INSTALL_HINT,
        )

    if not pillow_available():
        ctx.warn(
            "OCR_UPSCALE_UNAVAILABLE",
            "Pillow is not installed: OCR runs at native resolution, "
            "which can misread small identifiers. Install Pillow with "
            "`pip install Pillow` to enable 2x upscaling.",
        )

    try:
        rows, other, only_other, diag = ocr_rows(
            cmd,
            path,
            (image_size(head) or (None, None))[0],
        )
    except OcrError as exc:
        return fail("OCR_FAILED", str(exc))

    dimensions = image_size(head)
    diag["image"] = {
        "bytes": size,
        "width": dimensions[0] if dimensions else None,
        "height": dimensions[1] if dimensions else None,
    }

    if not rows:
        parsed.metadata["extraction"] = diag
        return fail(
            "OCR_NO_TEXT",
            "OCR recognised no text in the image",
        )

    parsed.metadata["passes"] = [
        result["psm"] for result in diag["passes"]
    ]

    return finalize_document(
        ctx,
        parsed,
        rows,
        diag,
        collection="screenshot_row",
        secondary_values=other,
        ocr=True,
        secondary_only=only_other,
    )
