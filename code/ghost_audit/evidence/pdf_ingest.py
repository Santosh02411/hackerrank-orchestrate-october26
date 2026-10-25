"""PDF evidence -> observations (Stage 1C).

Text comes from the PDF's own text layer through ``pypdf`` (pure Python; ``pip install pypdf``), in
``layout`` mode so table rows stay on one line. Nothing in a PDF is executed. Pages that have no text
layer but do carry embedded pictures (scans) are OCR'd through the same two-pass pipeline as
screenshots; if OCR is unavailable that is reported (``DEPENDENCY_MISSING`` / ``PDF_PAGE_NO_TEXT``).

All four supplied PDFs have text layers. They contain one detail worth knowing: times such as
``10:24 UTC`` are rendered as two table cells, ``... 10`` and ``24 UTC``, because the generator used the
colon as its key/value separator. The cells are preserved and flagged ``time_split_across_cells``; the
time is not reconstructed.
"""
from __future__ import annotations

import io
import logging
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Union

from .builders import FileContext
from .document_rows import DocRow, finalize_document, rows_from_text_lines
from .manifest import resolve_inside
from .model import EvidenceFileRef, ParsedFile, ParseStatus, SourceFormat
from .ocr import INSTALL_HINT, OcrError, find_tesseract

MAX_PDF_BYTES = 50 * 1024 * 1024
MAX_PAGES = 200
MAX_IMAGES_PER_PAGE = 10


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage()[:200])


@contextmanager
def _captured_reader_log():
    """pypdf reports damage through the `pypdf` logger (stderr by default); route it into our diagnostics instead."""
    lg = logging.getLogger("pypdf")
    handler, old = _Collect(), (lg.propagate, lg.level)
    lg.addHandler(handler)
    lg.propagate = False
    lg.setLevel(logging.WARNING)
    try:
        yield handler.messages
    finally:
        lg.removeHandler(handler)
        lg.propagate, level = old
        lg.setLevel(level)


def parse_pdf_bytes(ref: EvidenceFileRef, data: bytes) -> ParsedFile:
    parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.PDF, status=ParseStatus.PARSED, layout="pdf:text_layer", ref=ref)
    ctx = FileContext(ref, ref.file_path, SourceFormat.PDF)
    parsed.coverage.containers_seen = 1

    def fail(code: str, message: str) -> ParsedFile:
        ctx.warn(code, message)
        parsed.status = ParseStatus.FAILED
        parsed.warnings = ctx.warnings
        return parsed.finalize()

    if b"%PDF-" not in data[:1024]:
        return fail("PDF_NOT_A_PDF", "file has no %PDF- header")
    try:
        import pypdf
    except ImportError:
        return fail("DEPENDENCY_MISSING", "the `pypdf` package is required to read PDFs: pip install pypdf")
    with _captured_reader_log() as reader_messages:
        try:
            reader = pypdf.PdfReader(io.BytesIO(data))
            if reader.is_encrypted and not reader.decrypt(""):
                return fail("PDF_ENCRYPTED", "the PDF is encrypted and needs a password; none is tried")
            page_count = len(reader.pages)
        except Exception as exc:  # pypdf raises many unrelated types for damaged files
            detail = "; reader said: " + " | ".join(reader_messages[:3]) if reader_messages else ""
            return fail("PDF_UNREADABLE", "cannot parse the PDF: %s: %s%s" % (type(exc).__name__, str(exc)[:200], detail))
        return _parse_pages(ctx, parsed, reader, page_count, fail, reader_messages, pypdf)


def _parse_pages(ctx: FileContext, parsed: ParsedFile, reader: Any, page_count: int, fail: Any, reader_messages: List[str], pypdf: Any) -> ParsedFile:

    rows: List[DocRow] = []
    empty_pages: List[int] = []
    scanned_pages: List[int] = []
    ocr_diag: Dict[str, Any] = {}
    secondary: Set[Tuple[str, str]] = set()
    secondary_only: List[Tuple[str, str]] = []
    if page_count > MAX_PAGES:
        ctx.warn("PDF_PAGE_LIMIT", "the PDF has %d pages; only the first %d are read" % (page_count, MAX_PAGES))
    for pno in range(min(page_count, MAX_PAGES)):
        loc = "page=%d" % (pno + 1)
        try:
            page = reader.pages[pno]
            try:
                text = page.extract_text(extraction_mode="layout")
            except TypeError:  # pypdf < 3.17 has no layout mode
                text = page.extract_text()
        except Exception as exc:
            ctx.warn("PDF_PAGE_UNREADABLE", "page %d could not be extracted: %s: %s" % (pno + 1, type(exc).__name__, str(exc)[:160]), loc)
            parsed.status = ParseStatus.PARTIAL
            continue
        page_rows = rows_from_text_lines(text.splitlines(), pno + 1)
        if page_rows:
            rows.extend(DocRow(r.page, len(rows) + i + 1, r.cells) for i, r in enumerate(page_rows))
            continue
        empty_pages.append(pno + 1)
        scanned = _ocr_page_images(ctx, reader.pages[pno], pno + 1, rows, ocr_diag, secondary, secondary_only)
        if scanned:
            scanned_pages.append(pno + 1)
        else:
            ctx.warn("PDF_PAGE_NO_TEXT", "page %d has no text layer and no readable embedded picture" % (pno + 1), loc)
            parsed.status = ParseStatus.PARTIAL
    info = {}
    try:
        info = {str(k): str(v)[:120] for k, v in (reader.metadata or {}).items()}
    except Exception:
        pass
    parsed.metadata["pdf_metadata"] = info  # informational only: generator time is never used as an observation time
    diag: Dict[str, Any] = {"backend": "pypdf", "version": getattr(pypdf, "__version__", None), "mode": "layout", "pages": page_count,
                            "pages_without_text_layer": empty_pages, "pages_read_by_ocr": scanned_pages}
    if ocr_diag:
        diag["ocr"] = ocr_diag
    if reader_messages:
        diag["reader_messages"] = reader_messages[:20]
        ctx.warn("PDF_READER_MESSAGES", "pypdf reported %d problem(s) while reading (e.g. %s); text was still extracted" % (len(reader_messages), reader_messages[0]), level="info")
    if not rows:
        parsed.metadata["extraction"] = diag
        return fail("PDF_NO_TEXT", "no text could be extracted from any page")
    if parsed.status is ParseStatus.PARTIAL and not any(w.code in ("PDF_PAGE_UNREADABLE", "PDF_PAGE_NO_TEXT") for w in ctx.warnings):
        parsed.status = ParseStatus.PARSED
    status = parsed.status
    parsed = finalize_document(ctx, parsed, rows, diag, collection="pdf_row", secondary_values=secondary if scanned_pages else None,
                               secondary_only=secondary_only)
    if parsed.status is not ParseStatus.FAILED:
        parsed.status = status
    return parsed


def _ocr_page_images(ctx: FileContext, page: Any, page_no: int, rows: List[DocRow], ocr_diag: Dict[str, Any],
                     secondary: Set[Tuple[str, str]], secondary_only: List[Tuple[str, str]]) -> bool:
    """OCR the pictures embedded in a page that has no text layer. Returns True if text was recovered."""
    try:
        images = list(page.images)[:MAX_IMAGES_PER_PAGE]
    except Exception:
        return False
    if not images:
        return False
    cmd = find_tesseract()
    if cmd is None:
        ctx.warn("DEPENDENCY_MISSING", "page %d is a scan; reading it needs OCR. %s" % (page_no, INSTALL_HINT), "page=%d" % page_no)
        return False
    from .image_ingest import ocr_rows
    got = False
    for img in images:
        try:
            with tempfile.TemporaryDirectory() as tmp:
                suffix = os.path.splitext(getattr(img, "name", "") or "")[1].lower()
                path = Path(tmp) / ("embedded" + (suffix if suffix in (".png", ".jpg", ".jpeg") else ".png"))
                path.write_bytes(img.data)
                page_rows, other, only, diag = ocr_rows(cmd, path.resolve(), None)
        except (OcrError, Exception) as exc:  # a broken picture must not abort the document
            ctx.warn("PDF_PAGE_IMAGE_UNREADABLE", "an embedded picture on page %d could not be OCR'd: %s" % (page_no, str(exc)[:160]), "page=%d" % page_no)
            continue
        ocr_diag.setdefault("pictures", []).append({"page": page_no, "passes": diag["passes"]})
        ocr_diag.setdefault("backend", diag["backend"])
        ocr_diag.setdefault("version", diag["version"])
        secondary |= other
        secondary_only.extend(only)
        rows.extend(DocRow(page_no, len(rows) + i + 1, r.cells, r.multi_region, True) for i, r in enumerate(page_rows))
        got = got or bool(page_rows)
    return got


def parse_pdf_file(ref: EvidenceFileRef, dataset_dir: Union[str, Path]) -> ParsedFile:
    try:
        path = resolve_inside(dataset_dir, ref.file_path)
        size = os.path.getsize(str(path))
        if size > MAX_PDF_BYTES:
            raise ValueError("%d bytes exceeds the %d byte limit for PDFs" % (size, MAX_PDF_BYTES))
        data = path.read_bytes()
    except (OSError, ValueError) as exc:
        parsed = ParsedFile(source=ref.file_path, source_format=SourceFormat.PDF, status=ParseStatus.FAILED, ref=ref)
        ctx = FileContext(ref, ref.file_path, SourceFormat.PDF)
        ctx.warn("FILE_TOO_LARGE" if "limit" in str(exc) else "FILE_UNREADABLE", "cannot read %s: %s" % (ref.file_path, exc))
        parsed.warnings = ctx.warnings
        return parsed.finalize()
    return parse_pdf_bytes(ref, data)
