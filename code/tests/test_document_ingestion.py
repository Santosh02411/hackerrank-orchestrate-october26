"""Stage 1C tests: PDF and screenshot (OCR) ingestion.

Dependencies for the real-extraction tests (the rest run anywhere):

    pip install pypdf Pillow          # PDF text layer; image upscaling for OCR
    Tesseract OCR on PATH (or $TESSERACT_CMD)   # Windows: https://github.com/UB-Mannheim/tesseract/wiki

Tests that need a missing dependency are SKIPPED with the reason shown, never silently passed; the
missing-dependency behaviour itself is tested unconditionally with monkeypatching.

Principles: real-evidence tests reconcile against independent signals (a second extraction mode, raw
bytes, verified-by-eye values for one screenshot) and never hard-code deletion labels; OCR-derived
totals are NOT pinned because they can vary with the Tesseract build. The dataset is hashed before and
after the module; any write fails it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
DATASET = REPO_ROOT / "dataset"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

from ghost_audit import contracts as C  # noqa: E402
from ghost_audit.evidence import (  # noqa: E402
    EXTENDED_FORMATS,
    FULL_FORMATS,
    EvidenceFileRef,
    ObservationKind,
    ParseStatus,
    SourceFormat,
    TimestampSource,
    ingest_dataset,
    load_manifest,
    parse_evidence_file,
)
from ghost_audit.evidence import document_rows as D  # noqa: E402
from ghost_audit.evidence import image_ingest as IMG  # noqa: E402
from ghost_audit.evidence import ocr as OCR  # noqa: E402
from ghost_audit.evidence import pdf_ingest as PDF  # noqa: E402
from ghost_audit.evidence.builders import FileContext  # noqa: E402
from ghost_audit.evidence.model import ParsedFile, ScopeKind  # noqa: E402

HAVE_DATASET = (DATASET / "evidence_files.csv").exists() and (DATASET / "evidence").is_dir()
HAVE_PYPDF = importlib.util.find_spec("pypdf") is not None
HAVE_PILLOW = importlib.util.find_spec("PIL") is not None
HAVE_TESS = OCR.find_tesseract() is not None
needs_dataset = unittest.skipUnless(HAVE_DATASET, "dataset/ not present (e.g. unpacked code.zip)")
needs_pypdf = unittest.skipUnless(HAVE_PYPDF, "pypdf not installed: pip install pypdf")
needs_ocr = unittest.skipUnless(HAVE_TESS and HAVE_PILLOW, "Tesseract and/or Pillow not available: see README")

_BEFORE: Dict[str, str] = {}


def _tree_hash() -> Dict[str, str]:
    out: Dict[str, str] = {}
    if DATASET.is_dir():
        for dirpath, _d, names in os.walk(str(DATASET)):
            for n in names:
                p = os.path.join(dirpath, n)
                with open(p, "rb") as h:
                    out[os.path.relpath(p, str(DATASET))] = hashlib.sha256(h.read()).hexdigest()
    return out


def setUpModule() -> None:
    _BEFORE.update(_tree_hash())


def tearDownModule() -> None:
    if _tree_hash() != _BEFORE:
        raise AssertionError("document ingestion modified the dataset")


def refs(fmt: SourceFormat) -> List[EvidenceFileRef]:
    return [r for r in load_manifest(DATASET)[0] if r.source_format is fmt]


@lru_cache(maxsize=1)
def real_pdfs() -> Dict[str, ParsedFile]:
    return {r.file_id: parse_evidence_file(r, DATASET, FULL_FORMATS) for r in refs(SourceFormat.PDF)}


@lru_cache(maxsize=1)
def real_images() -> Dict[str, ParsedFile]:  # ~35 s once per process: the OCR run is shared by every test
    return {r.file_id: parse_evidence_file(r, DATASET, FULL_FORMATS) for r in refs(SourceFormat.IMAGE)}


def mkref(fmt: SourceFormat, rel: str, file_id: str = "evidence_980", captured: str = "2026-09-01T12:00:00Z") -> EvidenceFileRef:
    return EvidenceFileRef(file_id, rel, "test_origin", captured, fmt)


# --------------------------------------------------------------------------- #
# Synthetic fixtures
# --------------------------------------------------------------------------- #
def _esc(text: str) -> bytes:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("latin-1")


def make_pdf(pages: List[List[Tuple[str, ...]]]) -> bytes:
    """A valid minimal text-layer PDF. Each row is a tuple of cells placed at x = 50, 250, 400."""
    objects: Dict[int, bytes] = {3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
    kids, nxt = [], 4
    for rows in pages:
        parts = []
        for i, cells in enumerate(rows):
            for j, cell in enumerate(cells):
                parts.append(b"BT /F1 11 Tf %d %d Td (%s) Tj ET" % ((50, 250, 400)[j], 740 - 18 * i, _esc(cell)))
        content = b"\n".join(parts)
        objects[nxt] = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content)
        objects[nxt + 1] = (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
                            b"/Resources << /Font << /F1 3 0 R >> >> >>" % nxt)
        kids.append(nxt + 1)
        nxt += 2
    objects[2] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (b" ".join(b"%d 0 R" % k for k in kids), len(kids))
    objects[1] = b"<< /Type /Catalog /Pages 2 0 R >>"
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for i in sorted(objects):
        offsets[i] = len(out)
        out += b"%d 0 obj\n" % i + objects[i] + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for i in sorted(objects):
        out += b"%010d 00000 n \n" % offsets[i]
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objects) + 1, xref)
    return bytes(out)


def find_font() -> Optional[str]:
    for p in ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\segoeui.ttf",
              "/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial.ttf"):
        if os.path.isfile(p):
            return p
    return None


def render_text_png(path: Path, lines: List[str], size: int = 34) -> None:
    from PIL import Image, ImageDraw, ImageFont
    font = ImageFont.truetype(find_font(), size)
    im = Image.new("RGB", (1500, 80 + 70 * len(lines)), "white")
    d = ImageDraw.Draw(im)
    for i, line in enumerate(lines):
        d.text((40, 40 + 70 * i), line, fill="black", font=font)
    im.save(str(path))


needs_font = unittest.skipUnless(find_font() is not None, "no TrueType font found to render test images")


def pdf_ref() -> EvidenceFileRef:
    return mkref(SourceFormat.PDF, "evidence/test/x.pdf")


# =========================================================================== #
class TestAnchorsAndRows(unittest.TestCase):
    def row(self, *cells: str, conf: Optional[float] = None) -> D.DocRow:
        return D.DocRow(1, 1, tuple(D.Cell(c, conf) for c in cells))

    def test_anchor_kinds(self):
        r = self.row("Detail", "mail Ana@Example.com or user_18 about backup_9287; call +91 98765 73142", "a" * 64)
        kinds = {(a.kind, a.value) for a in D.find_anchors(r)[0]}
        self.assertEqual(kinds, {("email", "Ana@Example.com"), ("user_id", "user_18"), ("resource_ref", "backup_9287"),
                                 ("phone", "+91 98765 73142"), ("email_hash", "a" * 64)})

    def test_boundaries_do_not_match_inside_longer_tokens(self):
        r = self.row("xbackup_9287 backup_9287x preuser_5 user_5x account_")
        self.assertEqual(D.find_anchors(r)[0], [])

    def test_malformed_identifier_like_tokens_are_reported_not_corrected(self):
        anchors, malformed = D.find_anchors(self.row("data_flow.1121 and backup-9287 and search_428"))
        self.assertEqual([a.value for a in anchors], ["search_428"])
        self.assertEqual([t for _c, t in malformed], ["data_flow.1121", "backup-9287"])

    def test_text_lines_split_into_cells_on_runs_of_spaces(self):
        rows = D.rows_from_text_lines(["Detail      user_18", "", "  1   a | b   c  "], page=2)
        self.assertEqual([[c.text for c in r.cells] for r in rows], [["Detail", "user_18"], ["1", "a | b", "c"]])
        self.assertEqual([(r.page, r.index) for r in rows], [(2, 1), (2, 2)])

    def test_ocr_words_are_regrouped_into_rows_and_cells_by_position(self):
        W = lambda t, l, top, c=90.0: OCR.OcrWord(t, c, l, top, 10 * len(t), 12)  # noqa: E731
        words = [W("backup_9287", 100, 50), W("areed1433@gmail.com", 400, 52), W("eu-west-1", 700, 49),
                 W("next", 100, 90), W("row", 150, 91), W("Account", 1500, 51)]
        rows = D.rows_from_words(words, image_width=1800)
        self.assertEqual([[c.text for c in r.cells] for r in rows], [["backup_9287", "areed1433@gmail.com", "eu-west-1", "Account"], ["next row"]])
        self.assertTrue(rows[0].multi_region, "a gap wider than 12% of the image width marks unrelated panels")
        self.assertFalse(rows[1].multi_region)
        self.assertEqual(rows[0].cells[1].box, (400, 52, 190, 12))

    def test_split_time_cells_are_detected_and_not_reconstructed(self):
        r = self.row("submitted 18 Jun 2026 10", "24 UTC")
        flag = D.split_time_flag(r)
        self.assertEqual((flag["key_cell"], flag["value_cell"]), ("submitted 18 Jun 2026 10", "24 UTC"))
        self.assertNotRegex(flag["key_cell"] + " " + flag["value_cell"], r"\d:\d")  # no hh:mm was synthesised
        self.assertIsNone(D.split_time_flag(self.row("received 18 Jun 2026", "ok")))


class TestUncertaintyLabelling(unittest.TestCase):
    """OCR uncertainty is only ever labelled; values are never changed."""

    def run_rows(self, cells, conf, secondary):
        parsed = ParsedFile(source="x", source_format=SourceFormat.IMAGE, status=ParseStatus.PARSED)
        ctx = FileContext(mkref(SourceFormat.IMAGE, "evidence/test/x.png"), "x", SourceFormat.IMAGE)
        word_spans = tuple((0, len(cells[0]), conf) for _ in [0])
        row = D.DocRow(1, 1, (D.Cell(cells[0], conf, (0, 0, 10, 10), word_spans),))
        counts = D.rows_to_observations(ctx, parsed, [row], collection="screenshot_row", extraction={"x": 1}, secondary_values=secondary, ocr=True)
        return parsed, counts

    def test_low_confidence_identifier_is_flagged_and_kept_verbatim(self):
        parsed, counts = self.run_rows(["areedi433@gmail.com"], 41.0, {("email", "areedi433@gmail.com")})
        (o,) = parsed.observations
        (item,) = o.identifiers.items
        self.assertEqual((item.value, item.confidence, item.uncertain), ("areedi433@gmail.com", 41.0, True))
        self.assertIn("ocr_uncertain_identifier", o.flags)
        self.assertEqual((counts["low_confidence"], counts["unstable"], counts["uncertain"]), (1, 0, 1))

    def test_identifier_not_reproduced_by_the_second_pass_is_flagged_even_with_high_confidence(self):
        parsed, counts = self.run_rows(["ingrid.dahl@outlook.com"], 96.0, {("email", "ingrid.dahi@outlook.com")})
        item = parsed.observations[0].identifiers.items[0]
        self.assertEqual((item.value, item.uncertain), ("ingrid.dahl@outlook.com", True))
        self.assertEqual((counts["low_confidence"], counts["unstable"]), (0, 1))

    def test_confident_and_reproduced_identifier_is_not_flagged(self):
        parsed, counts = self.run_rows(["backup_9287"], 93.0, {("resource_ref", "backup_9287")})
        self.assertFalse(parsed.observations[0].identifiers.items[0].uncertain)
        self.assertNotIn("ocr_uncertain_identifier", parsed.observations[0].flags)
        self.assertEqual(counts["uncertain"], 0)

    def test_threshold_boundary(self):
        for conf, expected in ((79.99, True), (80.0, False)):
            parsed, _ = self.run_rows(["user_18"], conf, {("user_id", "user_18")})
            self.assertEqual(parsed.observations[0].identifiers.items[0].uncertain, expected, conf)

    def test_malformed_token_makes_the_row_visible_without_creating_an_identifier(self):
        parsed, counts = self.run_rows(["data_flow.1121"], 90.0, set())
        (o,) = parsed.observations
        self.assertEqual((o.identifiers.items, counts["malformed"], o.resource_id), ((), 1, None))
        self.assertIn("malformed_identifier_token", o.flags)
        self.assertEqual(o.fields["malformed_identifier_tokens"], [{"cell": 0, "token": "data_flow.1121"}])

    def test_unanchored_rows_are_kept_not_dropped(self):
        parsed = ParsedFile(source="x", source_format=SourceFormat.PDF, status=ParseStatus.PARSED)
        ctx = FileContext(pdf_ref(), "x", SourceFormat.PDF)
        rows = [D.DocRow(1, 1, (D.Cell("Delivery address", None), D.Cell("24 Fjordgata, 7010 Trondheim", None))), D.DocRow(1, 2, (D.Cell("Detail user_5"),))]
        D.rows_to_observations(ctx, parsed, rows, collection="pdf_row", extraction={})
        self.assertEqual((parsed.coverage.records_seen, len(parsed.observations)), (2, 1))
        self.assertEqual(parsed.metadata["unanchored_rows"][0]["text"], "Delivery address 24 Fjordgata, 7010 Trondheim")


# =========================================================================== #
@needs_pypdf
@needs_dataset
class TestRealPdfs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parsed = real_pdfs()
        cls.refs = {r.file_id: r for r in refs(SourceFormat.PDF)}

    def plain_text(self, ref) -> str:  # independent path: pypdf's default extraction mode, not layout mode
        import pypdf
        return "\n".join(p.extract_text() for p in pypdf.PdfReader(str(DATASET / ref.file_path)).pages)

    def test_all_four_pdfs_parse_with_only_the_informational_time_notice(self):
        self.assertEqual(len(self.parsed), 4)
        for fid, p in self.parsed.items():
            self.assertEqual((p.status, p.layout, p.coverage.records_unrecognized), (ParseStatus.PARSED, "pdf:text_layer", 0), fid)
            self.assertEqual([(w.code, w.level) for w in p.warnings], [("DOCUMENT_TIME_UNSTRUCTURED", "info")], fid)

    def test_every_identifier_found_by_an_independent_extraction_is_an_observation_and_vice_versa(self):
        for fid, p in self.parsed.items():
            plain = self.plain_text(self.refs[fid])
            expected = {(k, v) for k, rx in (("email", D.EMAIL_SEARCH), ("user_id", D.USER_SEARCH), ("resource_ref", D.RESOURCE_SEARCH), ("phone", D.PHONE_SEARCH))
                        for v in rx.findall(plain) if isinstance(v, str)}
            got = {(i.kind, i.value) for o in p.observations for i in o.identifiers.items}
            self.assertEqual(got, expected, fid)

    def test_expected_documents_contents(self):
        by_name = {self.refs[f].file_path.split("/")[-1]: p for f, p in self.parsed.items()}
        ids = lambda name: {(i.kind, i.value) for o in by_name[name].observations for i in o.identifiers.items}  # noqa: E731
        self.assertEqual(ids("legal_retention_register_20260529.pdf"), {("user_id", "user_%02d" % n) for n in (8, 12, 17, 21, 24, 29)})
        self.assertIn(("email", "priya.raman@gmail.com"), ids("delivery_correction_attachment.pdf"))
        self.assertIn(("phone", "+91 98765 73142"), ids("delivery_correction_attachment.pdf"))
        self.assertIn(("resource_ref", "support_001"), ids("delivery_correction_attachment.pdf"))
        self.assertEqual(ids("security_retention_extract.pdf"), {("resource_ref", "audit_record_003"), ("user_id", "user_03")})
        self.assertEqual(ids("account_history_report_20260718.pdf"), {("user_id", "user_18"), ("email", "ingrid.dahl@outlook.com")})

    def test_register_rows_keep_their_full_row_text_and_cells(self):
        p = next(p for f, p in self.parsed.items() if "legal_retention" in self.refs[f].file_path)
        for o in p.observations:
            self.assertRegex(o.fields["text"], r"ORD-\d+ \| user_\d+ \| .+ \| Retain until \d{2} \w{3} 2033 \| [A-Z]{2}")
            self.assertEqual(len(o.fields["cells"]), 2)

    def test_split_times_are_flagged_and_never_reconstructed(self):
        p = next(p for f, p in self.parsed.items() if "delivery_correction" in self.refs[f].file_path)
        split = [e for e in p.metadata["unanchored_rows"] if "time_split" in e]
        self.assertEqual([e["cells"] for e in split], [["submitted 18 Jun 2026 10", "24 UTC"], ["captured 12 Sep 2026 07", "30 UTC"]])
        blob = json.dumps(p.metadata["unanchored_rows"]) + json.dumps([o.to_dict() for o in p.observations], default=str)
        self.assertNotRegex(blob, r"10:24|2026 07:30|07:30 UTC")  # the manifest's own "07:30:00Z" capture time is legitimately present

    def test_no_row_is_lost_rows_equal_anchored_plus_unanchored(self):
        for fid, p in self.parsed.items():
            ex = p.metadata["extraction"]
            self.assertEqual(ex["rows"], ex["row_anchored"] + ex["row_unanchored"], fid)
            self.assertEqual((p.coverage.records_seen, p.coverage.records_recognized), (ex["rows"], ex["rows"]), fid)
            self.assertEqual(len(p.observations), ex["row_anchored"])
            self.assertEqual(len(p.metadata["unanchored_rows"]), ex["row_unanchored"])

    def test_provenance_and_time_labelling(self):
        for fid, p in self.parsed.items():
            ref = self.refs[fid]
            self.assertEqual(p.scopes[0].kind, ScopeKind.DOCUMENT)
            self.assertEqual((p.metadata["extraction"]["backend"], p.metadata["extraction"]["mode"]), ("pypdf", "layout"))
            for i, o in enumerate(p.observations):
                pv = o.provenance
                self.assertEqual((o.kind, pv.file_id, pv.citable_id, pv.file_path, pv.file_captured_at, pv.source_format, pv.ordinal),
                                 (ObservationKind.RECORD, fid, fid, ref.file_path, ref.captured_at, SourceFormat.PDF, i))
                self.assertRegex(pv.locator, r"^page=\d+;row=\d+$")
                eff = o.effective_time()
                self.assertEqual((eff.value, eff.source), (ref.captured_at, TimestampSource.MANIFEST_CAPTURED))  # labelled, not disguised
                self.assertIsNone(o.record_observed_at)
                self.assertTrue(C.DEFAULT_EVIDENCE_ID_PATTERN.fullmatch(pv.citable_id))
            self.assertIn("pdf_metadata", p.metadata)  # generator metadata is recorded, never used as a time

    def test_extraction_is_deterministic(self):
        again = parse_evidence_file(self.refs[next(iter(self.parsed))], DATASET, FULL_FORMATS)
        first = self.parsed[next(iter(self.parsed))]
        self.assertEqual(json.dumps([o.to_dict() for o in again.observations], sort_keys=True, default=str),
                         json.dumps([o.to_dict() for o in first.observations], sort_keys=True, default=str))


@needs_pypdf
class TestSyntheticPdfs(unittest.TestCase):
    def parse(self, data: bytes) -> ParsedFile:
        return PDF.parse_pdf_bytes(pdf_ref(), data)

    def codes(self, p):
        return Counter(w.code for w in p.warnings)

    def test_text_pdf_with_cells_and_identifiers(self):
        p = self.parse(make_pdf([[("Record", "Customer Ana"), ("Detail", "ana@example.com"), ("Detail", "user_7", "backup_9287")]]))
        self.assertEqual((p.status, p.coverage.records_seen, len(p.observations)), (ParseStatus.PARSED, 3, 2))
        self.assertEqual([[c["text"] for c in o.fields["cells"]] for o in p.observations], [["Detail", "ana@example.com"], ["Detail", "user_7", "backup_9287"]])
        self.assertEqual([i.kind for i in p.observations[1].identifiers.items], ["user_id", "resource_ref"])
        self.assertNotIn("ocr", p.observations[1].flags)  # a text-layer row is never labelled as OCR
        self.assertEqual(p.observations[1].resource_id, "backup_9287")

    def test_two_pages_keep_page_numbers_in_locators(self):
        p = self.parse(make_pdf([[("a", "user_1")], [("b", "user_2")]]))
        self.assertEqual([o.provenance.locator for o in p.observations], ["page=1;row=1", "page=2;row=2"])

    def test_malformed_pdfs_fail_with_explicit_codes(self):
        cases = {"empty": (b"", "PDF_NOT_A_PDF"), "text": (b"hello world", "PDF_NOT_A_PDF"), "png": (b"\x89PNG\r\n\x1a\n" + b"0" * 50, "PDF_NOT_A_PDF"),
                 "header only": (b"%PDF-1.4\n", "PDF_UNREADABLE"), "garbage body": (b"%PDF-1.4\n" + os.urandom(64) * 4, "PDF_UNREADABLE"),
                 "truncated": (make_pdf([[("a", "user_1")]])[:140], "PDF_UNREADABLE")}
        for label, (data, code) in cases.items():
            with self.subTest(label):
                p = self.parse(data)
                self.assertEqual((p.status, p.observations), (ParseStatus.FAILED, []))
                self.assertIn(code, self.codes(p))

    def test_pdf_without_any_text_is_failed_not_silently_empty(self):
        p = self.parse(make_pdf([[]]))
        self.assertEqual((p.status, p.observations), (ParseStatus.FAILED, []))
        self.assertEqual(self.codes(p)["PDF_NO_TEXT"], 1)
        self.assertEqual(self.codes(p)["PDF_PAGE_NO_TEXT"], 1)

    def test_one_empty_page_makes_the_document_partial_and_is_reported(self):
        p = self.parse(make_pdf([[("a", "user_1")], []]))
        self.assertEqual(p.status, ParseStatus.PARTIAL)
        self.assertIn("PDF_PAGE_NO_TEXT", self.codes(p))
        self.assertEqual(p.metadata["extraction"]["pages_without_text_layer"], [2])
        self.assertEqual(len(p.observations), 1)

    def test_encrypted_pdf_is_reported_and_no_password_is_tried(self):
        import pypdf
        w = pypdf.PdfWriter()
        w.add_blank_page(200, 200)
        try:
            w.encrypt("secret", algorithm="RC4-128")
        except Exception as exc:  # pragma: no cover - depends on the installed crypto backend
            self.skipTest("cannot create an encrypted PDF here: %s" % exc)
        buf = io.BytesIO()
        w.write(buf)
        p = self.parse(buf.getvalue())
        self.assertEqual((p.status, [c for c in self.codes(p)]), (ParseStatus.FAILED, ["PDF_ENCRYPTED"]))

    def test_missing_pypdf_is_an_explicit_dependency_failure(self):
        with mock.patch.dict(sys.modules, {"pypdf": None}):
            p = self.parse(make_pdf([[("a", "user_1")]]))
        self.assertEqual((p.status, p.observations), (ParseStatus.FAILED, []))
        self.assertIn("pip install pypdf", p.warnings[0].message)
        self.assertEqual(p.warnings[0].code, "DEPENDENCY_MISSING")

    def test_pdf_content_is_inert_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pwned"
            payload = "__import__('os').system('touch %s') user_9" % marker.as_posix()
            p = self.parse(make_pdf([[("Detail", payload)]]))
            self.assertEqual(p.observations[0].fields["cells"][1]["text"], payload)
            self.assertFalse(marker.exists())
            self.assertEqual(os.listdir(tmp), [])

    def test_page_limit_is_enforced_and_reported(self):
        with mock.patch.object(PDF, "MAX_PAGES", 2):
            p = self.parse(make_pdf([[("a", "user_%d" % i)] for i in range(4)]))
        self.assertEqual((len(p.observations), p.metadata["extraction"]["pages"]), (2, 4))
        self.assertIn("PDF_PAGE_LIMIT", self.codes(p))

    def test_generator_metadata_is_never_used_as_a_time(self):
        p = self.parse(make_pdf([[("a", "user_1")]]))
        self.assertIsNone(p.observations[0].provenance.file_content_time)


class TestFileReaders(unittest.TestCase):
    def test_readers_refuse_paths_outside_the_dataset(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "dataset"
            root.mkdir()
            (Path(tmp) / "secret.pdf").write_bytes(b"%PDF-1.4\n")
            (Path(tmp) / "secret.png").write_bytes(b"\x89PNG\r\n\x1a\n")
            for fmt, reader, rel in ((SourceFormat.PDF, PDF.parse_pdf_file, "../secret.pdf"), (SourceFormat.IMAGE, IMG.parse_image_file, "../secret.png")):
                p = reader(mkref(fmt, rel), root)
                self.assertEqual((p.status, p.observations, [w.code for w in p.warnings]), (ParseStatus.FAILED, [], ["FILE_UNREADABLE"]))
                self.assertIn("outside the dataset", p.warnings[0].message)

    def test_missing_files_fail_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fmt, reader, rel in ((SourceFormat.PDF, PDF.parse_pdf_file, "evidence/none.pdf"), (SourceFormat.IMAGE, IMG.parse_image_file, "evidence/none.png")):
                p = reader(mkref(fmt, rel), tmp)
                self.assertEqual((p.status, [w.code for w in p.warnings]), (ParseStatus.FAILED, ["FILE_UNREADABLE"]))

    def test_oversized_files_are_refused_before_being_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "big.pdf").write_bytes(b"%PDF-1.4\n" + b"0" * 100)
            (Path(tmp) / "big.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)
            with mock.patch.object(PDF, "MAX_PDF_BYTES", 50), mock.patch.object(IMG, "MAX_IMAGE_BYTES", 50):
                for fmt, reader, rel in ((SourceFormat.PDF, PDF.parse_pdf_file, "big.pdf"), (SourceFormat.IMAGE, IMG.parse_image_file, "big.png")):
                    p = reader(mkref(fmt, rel), tmp)
                    self.assertEqual((p.status, [w.code for w in p.warnings]), (ParseStatus.FAILED, ["FILE_TOO_LARGE"]))

    def test_unsupported_image_content_is_rejected_by_signature_not_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in (("empty.png", b""), ("text.png", b"not an image at all"), ("pdf.png", b"%PDF-1.4"), ("gif.png", b"GIF89a....")):
                (Path(tmp) / name).write_bytes(data)
                p = IMG.parse_image_file(mkref(SourceFormat.IMAGE, name), tmp)
                self.assertEqual((p.status, [w.code for w in p.warnings]), (ParseStatus.FAILED, ["IMAGE_UNSUPPORTED_FORMAT"]), name)


# =========================================================================== #
class TestOcrBackendSecurity(unittest.TestCase):
    def test_only_executables_named_tesseract_are_accepted_from_the_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            evil = Path(tmp) / "evil.exe"
            evil.write_text("#!/bin/sh\n")
            fake_ok = Path(tmp) / "tesseract"
            fake_ok.write_text("#!/bin/sh\n")
            with mock.patch.dict(os.environ, {"TESSERACT_CMD": str(evil)}), mock.patch("shutil.which", return_value=None), \
                    mock.patch.object(OCR, "_WINDOWS_DIRS", ()):
                self.assertIsNone(OCR.find_tesseract())
            with mock.patch.dict(os.environ, {"TESSERACT_CMD": str(fake_ok)}):
                self.assertEqual(Path(OCR.find_tesseract()).name, "tesseract")

    def test_subprocess_is_called_without_a_shell_with_an_argument_vector_and_an_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = Path(tmp) / "a b; rm -rf x.png"
            img.write_bytes(b"\x89PNG\r\n\x1a\n")
            done = subprocess.CompletedProcess([], 0, stdout="level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext\n", stderr="")
            with mock.patch.object(subprocess, "run", return_value=done) as run:
                OCR.run_pass("/usr/bin/tesseract", img.resolve(), 11, 1)
            args, kwargs = run.call_args
            self.assertIsInstance(args[0], list)
            self.assertIs(kwargs.get("shell"), False)
            self.assertEqual(args[0][1], str(img.resolve()))
            self.assertTrue(os.path.isabs(args[0][1]) and not args[0][1].startswith("-"))
            self.assertIn("timeout", kwargs)
            self.assertEqual(kwargs["env"]["OMP_THREAD_LIMIT"], "1")

    def test_relative_image_paths_are_refused(self):
        with self.assertRaises(OCR.OcrError):
            OCR.run_pass("/usr/bin/tesseract", Path("-psm.png"), 11, 1)

    def test_tesseract_failure_and_timeout_become_ocr_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            img = (Path(tmp) / "a.png").resolve()
            img.write_bytes(b"\x89PNG\r\n\x1a\n")
            with mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="boom")):
                with self.assertRaisesRegex(OCR.OcrError, "exited with 1"):
                    OCR.run_pass("t", img, 11, 1)
            with mock.patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("t", 1)):
                with self.assertRaisesRegex(OCR.OcrError, "timed out"):
                    OCR.run_pass("t", img, 11, 1)
            with mock.patch.object(subprocess, "run", side_effect=FileNotFoundError("gone")):
                with self.assertRaisesRegex(OCR.OcrError, "cannot run"):
                    OCR.run_pass("t", img, 11, 1)


class TestOcrFailureModes(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        (self.root / "shot.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

    def parse(self):
        return IMG.parse_image_file(mkref(SourceFormat.IMAGE, "shot.png"), self.root)

    def test_missing_tesseract_is_an_explicit_dependency_failure_with_install_instructions(self):
        with mock.patch.object(IMG, "find_tesseract", return_value=None):
            p = self.parse()
        self.assertEqual((p.status, p.observations), (ParseStatus.FAILED, []))
        self.assertEqual([w.code for w in p.warnings], ["DEPENDENCY_MISSING"])
        self.assertIn("Tesseract", p.warnings[0].message)
        self.assertIn("UB-Mannheim", p.warnings[0].message)

    def test_backend_error_is_reported_not_swallowed(self):
        with mock.patch.object(IMG, "find_tesseract", return_value="/usr/bin/tesseract"), mock.patch.object(IMG, "run_pass", side_effect=OCR.OcrError("boom")):
            p = self.parse()
        self.assertEqual((p.status, [w.code for w in p.warnings]), (ParseStatus.FAILED, ["OCR_FAILED"]))

    def test_empty_ocr_output_is_failed_not_an_empty_success(self):
        empty = OCR.OcrPass(11, 2, ())
        with mock.patch.object(IMG, "find_tesseract", return_value="t"), mock.patch.object(IMG, "run_pass", return_value=empty), \
                mock.patch.object(IMG, "pillow_available", return_value=True):
            p = self.parse()
        self.assertEqual((p.status, p.observations, [w.code for w in p.warnings]), (ParseStatus.FAILED, [], ["OCR_NO_TEXT"]))

    def test_missing_pillow_is_reported_and_ocr_falls_back_to_native_resolution(self):
        words = (OCR.OcrWord("user_5", 95.0, 10, 10, 60, 12),)
        seen = []
        def fake(cmd, path, psm, scale):
            seen.append(scale)
            return OCR.OcrPass(psm, scale, words)
        with mock.patch.object(IMG, "find_tesseract", return_value="t"), mock.patch.object(IMG, "run_pass", side_effect=fake), \
                mock.patch.object(IMG, "pillow_available", return_value=False):
            p = self.parse()
        self.assertEqual((p.status, set(seen)), (ParseStatus.PARSED, {1}))
        self.assertIn("OCR_UPSCALE_UNAVAILABLE", [w.code for w in p.warnings])
        self.assertFalse(p.metadata["extraction"]["upscale_applied"])

    def test_two_independent_passes_drive_the_uncertainty_flag_end_to_end(self):
        first = OCR.OcrPass(11, 2, (OCR.OcrWord("ingrid.dahl@outlook.com", 96.0, 10, 10, 230, 12), OCR.OcrWord("backup_9287", 95.0, 400, 10, 110, 12)))
        second = OCR.OcrPass(6, 2, (OCR.OcrWord("ingrid.dahi@outlook.com", 96.0, 10, 10, 230, 12), OCR.OcrWord("backup_9287", 95.0, 400, 10, 110, 12)))
        with mock.patch.object(IMG, "find_tesseract", return_value="t"), mock.patch.object(IMG, "pillow_available", return_value=True), \
                mock.patch.object(IMG, "run_pass", side_effect=lambda c, p, psm, s: first if psm == 11 else second):
            p = self.parse()
        items = {i.value: i.uncertain for o in p.observations for i in o.identifiers.items}
        self.assertEqual(items, {"ingrid.dahl@outlook.com": True, "backup_9287": False})
        self.assertEqual(p.metadata["extraction"]["identifiers_only_in_second_pass"], [{"kind": "email", "value": "ingrid.dahi@outlook.com"}])
        self.assertNotIn("ingrid.dahi@outlook.com", {i.value for o in p.observations for i in o.identifiers.items})  # never adopted
        codes = {w.code: w.level for w in p.warnings}
        self.assertEqual((codes["OCR_UNCERTAIN_IDENTIFIER"], codes["OCR_PASS_DISAGREEMENT"]), ("warning", "info"))


@needs_ocr
@needs_font
class TestOcrOnRenderedImages(unittest.TestCase):
    def test_clean_rendered_text_is_read_exactly_with_high_confidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            render_text_png(Path(tmp) / "r.png", ["areed1433@gmail.com     eu-west-1", "ingrid.dahl@outlook.com"], size=48)
            p = IMG.parse_image_file(mkref(SourceFormat.IMAGE, "r.png"), tmp)
        self.assertEqual(p.status, ParseStatus.PARSED, [str(w) for w in p.warnings])
        got = {(i.kind, i.value): i for o in p.observations for i in o.identifiers.items}
        self.assertEqual(set(got), {("email", "areed1433@gmail.com"), ("email", "ingrid.dahl@outlook.com")})  # values exactly as rendered
        clear = got[("email", "areed1433@gmail.com")]
        self.assertGreaterEqual(clear.confidence, 80.0)
        self.assertFalse(clear.uncertain)
        for item in got.values():  # `l` vs `I` is ambiguous in this font: whatever the confidence turns out to be,
            if item.confidence < D.OCR_CONFIDENCE_THRESHOLD:          # a low-confidence reading must be flagged
                self.assertTrue(item.uncertain, item)
        self.assertTrue(p.metadata["extraction"]["upscale_applied"])

    def test_blank_image_is_failed_with_ocr_no_text(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as tmp:
            Image.new("RGB", (600, 300), "white").save(str(Path(tmp) / "blank.png"))
            p = IMG.parse_image_file(mkref(SourceFormat.IMAGE, "blank.png"), tmp)
        self.assertEqual((p.status, p.observations, [w.code for w in p.warnings]), (ParseStatus.FAILED, [], ["OCR_NO_TEXT"]))

    def test_corrupt_png_with_a_valid_signature_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "bad.png").write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(200))
            p = IMG.parse_image_file(mkref(SourceFormat.IMAGE, "bad.png"), tmp)
        self.assertEqual((p.status, p.observations, [w.code for w in p.warnings]), (ParseStatus.FAILED, [], ["OCR_FAILED"]))

    def test_decompression_bomb_is_refused(self):
        from PIL import Image
        before = Image.MAX_IMAGE_PIXELS
        with tempfile.TemporaryDirectory() as tmp:
            Image.new("L", (3000, 3000), 255).save(str(Path(tmp) / "big.png"))
            with mock.patch.object(OCR, "MAX_IMAGE_PIXELS", 1000):
                p = IMG.parse_image_file(mkref(SourceFormat.IMAGE, "big.png"), tmp)
        self.assertEqual((p.status, [w.code for w in p.warnings]), (ParseStatus.FAILED, ["OCR_FAILED"]))
        self.assertIn("above the 1000 limit", p.warnings[0].message)
        self.assertEqual(Image.MAX_IMAGE_PIXELS, before, "OCR must never change Pillow's process-wide limit")

    @needs_pypdf
    def test_scanned_pdf_pages_are_read_by_ocr_and_labelled(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as tmp:
            render_text_png(Path(tmp) / "s.png", ["areed1433@gmail.com"], size=48)
            Image.open(str(Path(tmp) / "s.png")).convert("RGB").save(str(Path(tmp) / "scan.pdf"), "PDF")
            data = (Path(tmp) / "scan.pdf").read_bytes()
        p = PDF.parse_pdf_bytes(pdf_ref(), data)
        self.assertEqual(p.status, ParseStatus.PARSED, [str(w) for w in p.warnings])
        self.assertEqual(p.metadata["extraction"]["pages_read_by_ocr"], [1])
        self.assertEqual({(i.kind, i.value) for o in p.observations for i in o.identifiers.items},
                         {("email", "areed1433@gmail.com")})
        self.assertTrue(all("ocr" in o.flags for o in p.observations), "rows read from a scanned page are labelled as OCR")
        self.assertTrue(all(i.confidence is not None for o in p.observations for i in o.identifiers.items))

    @needs_pypdf
    def test_scanned_pdf_without_ocr_is_reported_not_silently_empty(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as tmp:
            Image.new("RGB", (300, 200), "white").save(str(Path(tmp) / "scan.pdf"), "PDF")
            data = (Path(tmp) / "scan.pdf").read_bytes()
        with mock.patch.object(PDF, "find_tesseract", return_value=None):
            p = PDF.parse_pdf_bytes(pdf_ref(), data)
        self.assertEqual((p.status, p.observations), (ParseStatus.FAILED, []))
        self.assertTrue({"DEPENDENCY_MISSING", "PDF_NO_TEXT", "PDF_PAGE_NO_TEXT"} <= {w.code for w in p.warnings})


# =========================================================================== #
@needs_ocr
@needs_dataset
class TestRealScreenshots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parsed = real_images()
        cls.refs = {r.file_id: r for r in refs(SourceFormat.IMAGE)}

    def test_all_eleven_screenshots_parse(self):
        self.assertEqual(len(self.parsed), 11)
        for fid, p in self.parsed.items():
            self.assertEqual((p.status, p.layout, p.coverage.records_unrecognized), (ParseStatus.PARSED, "image:screenshot_ocr", 0), fid)
            self.assertTrue(p.metadata["extraction"]["rows"] > 10, fid)
            self.assertEqual({w.code for w in p.warnings} - {"DOCUMENT_TIME_UNSTRUCTURED", "OCR_UNCERTAIN_IDENTIFIER", "OCR_PASS_DISAGREEMENT", "OCR_MALFORMED_IDENTIFIER"}, set(), fid)

    def test_diagnostics_record_backend_passes_and_upscale(self):
        for fid, p in self.parsed.items():
            ex = p.metadata["extraction"]
            self.assertEqual((ex["backend"], ex["language"], ex["upscale_applied"], [x["psm"] for x in ex["passes"]]), ("tesseract", "eng", True, [11, 6]), fid)
            self.assertTrue(ex["version"].startswith("tesseract"))
            self.assertEqual((ex["image"]["width"], ex["image"]["height"] > 500), (ex["image_width"], True))
            self.assertTrue(all(x["words"] > 50 and 0 < x["mean_confidence"] <= 100 for x in ex["passes"]), fid)

    def test_values_verified_by_eye_on_the_backup_console_are_read_exactly_on_the_right_rows(self):
        p = next(p for f, p in self.parsed.items() if "backup_restore_console" in self.refs[f].file_path)
        expected = {"backup_9291": "bluepeakco@outlook.com", "backup_9288": "miller.logistics@company.com",
                    "backup_9287": "areed1433@gmail.com", "backup_9286": "summit-retail@company.com"}
        rows = {}
        for o in p.observations:
            vals = {i.value for i in o.identifiers.items}
            for rid, email in expected.items():
                if rid in vals and email in vals:
                    rows[rid] = o
        self.assertEqual(set(rows), set(expected))
        for rid, o in rows.items():
            self.assertFalse([i for i in o.identifiers.items if i.value in (rid, expected[rid]) and i.uncertain], rid)
            self.assertNotIn("multi_region_row", o.flags, rid)

    def test_identifiers_are_never_altered_each_value_appears_verbatim_in_its_cell(self):
        for fid, p in self.parsed.items():
            for o in p.observations:
                cells = [c["text"] for c in o.fields["cells"]]
                for i in o.identifiers.items:
                    idx = int(re.fullmatch(r"cells\[(\d+)\]", i.path).group(1))
                    self.assertIn(i.value, cells[idx], "%s %s" % (fid, i.value))

    def test_every_low_confidence_identifier_is_flagged_and_every_flag_is_explained(self):
        flagged = 0
        for p in self.parsed.values():
            for o in p.observations:
                row_uncertain = [i for i in o.identifiers.items if i.uncertain]
                self.assertEqual(bool(row_uncertain), "ocr_uncertain_identifier" in o.flags)
                for i in o.identifiers.items:
                    self.assertIsNotNone(i.confidence)
                    if i.confidence < D.OCR_CONFIDENCE_THRESHOLD:
                        self.assertTrue(i.uncertain)
                    flagged += i.uncertain
        self.assertEqual(flagged, sum(p.metadata["extraction"]["row_uncertain"] for p in self.parsed.values()))

    def test_second_pass_only_identifiers_are_reported_but_never_become_observations(self):
        for p in self.parsed.values():
            obs_values = {(i.kind, i.value) for o in p.observations for i in o.identifiers.items}
            for d in p.metadata["extraction"]["identifiers_only_in_second_pass"]:
                self.assertNotIn((d["kind"], d["value"]), obs_values)

    def test_rows_equal_anchored_plus_unanchored_and_nothing_is_dropped(self):
        for fid, p in self.parsed.items():
            ex = p.metadata["extraction"]
            self.assertEqual(ex["rows"], ex["row_anchored"] + ex["row_unanchored"], fid)
            self.assertEqual((p.coverage.records_seen, len(p.observations), len(p.metadata["unanchored_rows"])), (ex["rows"], ex["row_anchored"], ex["row_unanchored"]), fid)

    def test_provenance_and_time_labelling(self):
        for fid, p in self.parsed.items():
            ref = self.refs[fid]
            for i, o in enumerate(p.observations):
                pv = o.provenance
                self.assertEqual((pv.file_id, pv.file_path, pv.file_captured_at, pv.source_format, pv.ordinal), (fid, ref.file_path, ref.captured_at, SourceFormat.IMAGE, i))
                self.assertRegex(pv.locator, r"^page=1;row=\d+$")
                self.assertEqual((o.effective_time().value, o.effective_time().source), (ref.captured_at, TimestampSource.MANIFEST_CAPTURED))
                self.assertIn("ocr", o.flags)

    def test_ocr_is_repeatable_on_the_same_input(self):
        fid = next(f for f, r in self.refs.items() if "backup_restore" in r.file_path)
        again = parse_evidence_file(self.refs[fid], DATASET, FULL_FORMATS)
        dump = lambda p: json.dumps([o.to_dict() for o in p.observations], sort_keys=True, default=str)  # noqa: E731
        self.assertEqual(dump(again), dump(self.parsed[fid]))


# =========================================================================== #
@needs_dataset
class TestIntegration(unittest.TestCase):
    def test_default_and_extended_modes_still_defer_pdfs_and_images(self):
        for formats, deferred in ((None, 42), (EXTENDED_FORMATS, 15)):
            r = ingest_dataset(DATASET, formats=formats, include_activity=False)
            self.assertEqual(sum(1 for p in r.files if p.status is ParseStatus.DEFERRED), deferred)
        pdf_ref_ = refs(SourceFormat.PDF)[0]
        self.assertEqual(parse_evidence_file(pdf_ref_, DATASET).status, ParseStatus.DEFERRED)
        self.assertEqual(parse_evidence_file(pdf_ref_, DATASET, EXTENDED_FORMATS).status, ParseStatus.DEFERRED)

    @needs_pypdf
    @needs_ocr
    def test_full_ingestion_parses_every_manifest_file(self):
        pdfs, imgs = real_pdfs(), real_images()
        self.assertEqual(sum(1 for p in list(pdfs.values()) + list(imgs.values()) if p.status is ParseStatus.PARSED), 15)
        self.assertEqual(sum(len(p.observations) for p in pdfs.values()), 14)
        obs = [o for p in list(pdfs.values()) + list(imgs.values()) for o in p.observations]
        self.assertEqual(len({o.obs_id for o in obs}), len(obs))
        for o in obs:
            self.assertTrue(C.DEFAULT_EVIDENCE_ID_PATTERN.fullmatch(o.provenance.citable_id))
            self.assertIs(o.kind, ObservationKind.RECORD)

    @needs_pypdf
    def test_missing_ocr_blocks_only_images_not_the_other_formats(self):
        with mock.patch.object(IMG, "find_tesseract", return_value=None):
            r = ingest_dataset(DATASET, formats=FULL_FORMATS, include_activity=False)
        by = Counter((p.source_format.value, p.status.value) for p in r.files)
        self.assertEqual(by[("image", "failed")], 11)
        self.assertEqual(by[("pdf", "parsed")], 4)
        self.assertEqual((by[("sql", "parsed")], by[("json", "parsed")], by[("log", "parsed")], by[("text", "parsed")]), (24, 28, 26, 1))
        for p in r.files:
            if p.source_format is SourceFormat.IMAGE:
                self.assertEqual([w.code for w in p.warnings], ["DEPENDENCY_MISSING"])


class TestCommandLine(unittest.TestCase):
    SCRIPT = CODE_DIR / "inspect_evidence.py"

    def run_cli(self, *args: str):
        return subprocess.run([sys.executable, "-B", str(self.SCRIPT), *args], capture_output=True, text=True)

    def test_bad_formats_argument_is_a_usage_error(self):
        proc = self.run_cli("--formats", "sql,video")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--formats", proc.stderr)

    @needs_dataset
    def test_explicit_formats_without_ocr_dependencies_still_work_and_strict_passes(self):
        proc = self.run_cli("--formats", "sql,json,log,text", "--strict")
        self.assertEqual((proc.returncode, proc.stderr), (0, ""))
        self.assertIn("Observations: 6905", proc.stdout)

    @needs_dataset
    @needs_pypdf
    @needs_ocr
    def test_extended_strict_reads_a_pdf_and_a_screenshot(self):
        # one of each keeps this fast; the documented full run (`--extended --strict`) is exercised in the final verification
        pdf, img = refs(SourceFormat.PDF)[0].file_id, refs(SourceFormat.IMAGE)[0].file_id
        proc = self.run_cli("--extended", "--strict", "--file", pdf, "--file", img, "--show-warnings", "40")
        self.assertEqual((proc.returncode, proc.stderr), (0, ""), proc.stdout[-600:])
        self.assertRegex(proc.stdout, r"status: \{'parsed': 2\}")
        self.assertIn("unrecognized: 0", proc.stdout)
        self.assertIn("image:screenshot_ocr", proc.stdout)
        self.assertIn("pdf:text_layer", proc.stdout)

    @needs_dataset
    @needs_pypdf
    def test_strict_fails_when_a_requested_format_cannot_be_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "evidence").mkdir()
            (root / "evidence" / "bad.pdf").write_bytes(b"%PDF-1.4\n" + b"garbage" * 20)
            (root / "evidence_files.csv").write_text("file_id,file_path,origin,captured_at\nevidence_1,evidence/bad.pdf,o,2026-01-01T00:00:00Z\n", encoding="utf-8")
            proc = self.run_cli("--dataset", tmp, "--no-activity", "--formats", "pdf", "--strict")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("PDF_UNREADABLE", proc.stdout)


if __name__ == "__main__":
    unittest.main()
