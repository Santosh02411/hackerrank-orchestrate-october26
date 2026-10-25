"""Tests for the dependency pre-flight in code/main.py (a clean run without OCR must explain itself)."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock

CODE_DIR = Path(__file__).resolve().parents[1]
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))


def load_main():
    spec = importlib.util.spec_from_file_location("ghost_main_entry", CODE_DIR / "main.py")   # not `import main`: other scripts share that name
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestDependencyPreflight(unittest.TestCase):
    def setUp(self):
        self.m = load_main()

    def test_all_present_is_a_single_quiet_line(self):
        msg = self.m.dependency_message({"pypdf": True, "Pillow": True, "Tesseract": True})
        self.assertEqual(msg, "dependencies: pypdf, Pillow and Tesseract found")

    def test_missing_tools_are_named_with_the_consequence_and_the_fix(self):
        msg = self.m.dependency_message({"pypdf": True, "Pillow": False, "Tesseract": False})
        self.assertTrue(msg.startswith("DEPENDENCIES MISSING: Pillow, Tesseract."))
        for needle in ("FAIL validation", "never guessed", "pip install -r requirements.txt", "Tesseract 5.x", "TESSERACT_CMD"):
            self.assertIn(needle, msg)
        self.assertNotIn("pypdf,", msg.split(".")[0])

    def test_status_reflects_the_environment(self):
        with mock.patch("ghost_audit.evidence.ocr.find_tesseract", return_value=None), mock.patch("ghost_audit.evidence.ocr.pillow_available", return_value=False):
            st = self.m.dependency_status()
        self.assertEqual((st["Tesseract"], st["Pillow"]), (False, False))
        self.assertIn("pypdf", st)

    def test_requirements_file_lists_what_the_readers_import(self):
        text = (CODE_DIR.parent / "requirements.txt").read_text(encoding="utf-8").lower()
        self.assertIn("pypdf", text)
        self.assertIn("pillow", text)


if __name__ == "__main__":
    unittest.main()
