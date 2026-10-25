"""Tests for code/package_submission.py: the archive must satisfy the official packaging rules (AGENTS.md 6.8/6.9, README)."""
from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CODE_DIR = REPO_ROOT / "code"
if str(CODE_DIR) not in sys.path:
    sys.path.insert(0, str(CODE_DIR))

import package_submission as P  # noqa: E402

EVAL = ("# Evaluation report\nCase-level deletion-status accuracy\nStep-level and Field-level accuracy\nSequence accuracy\n"
        "Additional evaluation cases\nFailures found and improvements made\n")
USAGE = "# Usage report\nModel providers none\nModel names none\nModel calls 0\nInput tokens 0\nOutput tokens 0\nTotal tokens 0\nEstimated cost 0\n"


def make_repo(root: Path, **extra) -> None:
    files = {"README.md": "# run it\n", "requirements.txt": "pypdf\n", "code/main.py": "print('x')\n", "code/evaluation/main.py": "\n",
             "code/evaluation/evaluation_report.md": EVAL, "code/evaluation/usage_report.md": USAGE,
             "evaluation/evaluation_report.md": EVAL, "evaluation/usage_report.md": USAGE}
    files.update(extra)
    for rel, body in files.items():
        if body is None:
            continue
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body if isinstance(body, bytes) else body.encode("utf-8"))


class TestPackaging(unittest.TestCase):
    def build(self, **extra):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        make_repo(root, **extra)
        out = root / "code.zip"
        P.build(root, out)
        return root, out

    def test_a_clean_tree_produces_a_passing_archive_with_forward_slash_names(self):
        _root, out = self.build()
        self.assertEqual(P.verify(out), [])
        with zipfile.ZipFile(str(out)) as zf:
            names = zf.namelist()
        self.assertIn("evaluation/evaluation_report.md", names)
        self.assertIn("code/evaluation/usage_report.md", names)
        self.assertTrue(all("\\" not in n for n in names))

    def test_dataset_caches_environments_archives_and_separate_deliverables_are_left_out(self):
        _root, out = self.build(**{"dataset/deletion_requests.csv": "x", "code/__pycache__/a.cpython-310.pyc": b"\0", "code/.venv/lib/x.py": "x",
                                   "code/nested.zip": b"PK", "code/data.tar.gz": b"x", ".env": "TOKEN=abc", "code/.env": "K=v", "output.csv": "x", "log.txt": "x",
                                   "ocr_debug.png": b"\x89PNG", "code/ocr_debug_2.png": b"\x89PNG", "code/.DS_Store": b"x", "code/node_modules/m.js": "x"})
        with zipfile.ZipFile(str(out)) as zf:
            names = zf.namelist()
        for bad in ("dataset", "__pycache__", ".venv", "nested.zip", "data.tar.gz", ".env", "output.csv", "log.txt", "ocr_debug", ".DS_Store", "node_modules"):
            self.assertFalse([n for n in names if bad in n], bad)
        self.assertEqual(P.verify(out), [])

    def test_verify_rejects_each_violation(self):
        def archive(entries):
            tmp = tempfile.TemporaryDirectory()
            self.addCleanup(tmp.cleanup)
            path = Path(tmp.name) / "x.zip"
            with zipfile.ZipFile(str(path), "w") as zf:
                for n, b in entries.items():
                    zf.writestr(n, b)
            return path
        good = {"README.md": "r", "code/main.py": "m", "code/evaluation/main.py": "m", "code/evaluation/evaluation_report.md": EVAL, "code/evaluation/usage_report.md": USAGE,
                "evaluation/evaluation_report.md": EVAL, "evaluation/usage_report.md": USAGE}
        self.assertEqual(P.verify(archive(good)), [])
        cases = {
            "missing report": ({k: v for k, v in good.items() if k != "evaluation/usage_report.md"}, "missing required file: evaluation/usage_report.md"),
            "missing readme": ({k: v for k, v in good.items() if k != "README.md"}, "missing required file: README.md"),
            "nested archive": (dict(good, **{"code/a.zip": "x"}), "nested archive"),
            "dataset bundled": (dict(good, **{"dataset/a.csv": "x"}), "dataset must not be bundled"),
            "bytecode": (dict(good, **{"code/__pycache__/a.pyc": "x"}), "cache"),
            "env file": (dict(good, **{".env": "x"}), "environment file"),
            "output.csv inside": (dict(good, **{"output.csv": "x"}), "separate submission item"),
            "api key": (dict(good, **{"code/cfg.py": "API" + "_KEY = " + chr(34) + "abcd1234" + "efgh5678" + chr(34)}), "possible credential"),   # built at runtime: no literal in source
            "openai-style key": (dict(good, **{"code/k.md": "sk-" + "A" * 30}), "possible credential"),
            "report missing sequence accuracy": (dict(good, **{"evaluation/evaluation_report.md": EVAL.replace("Sequence accuracy", ""),
                                                               "code/evaluation/evaluation_report.md": EVAL.replace("Sequence accuracy", "")}), "sequence accuracy"),
            "usage report missing tokens": (dict(good, **{"code/evaluation/usage_report.md": USAGE.replace("Input tokens 0", "")}), "input tokens"),
            "copies differ": (dict(good, **{"code/evaluation/evaluation_report.md": EVAL + "extra"}), "two copies"),
            "built explorer page": (dict(good, **{"code/page.html": '<script id="ghost-data" type="application/json">{"datasets":{"evaluation":{}}}</script>'}), "BUILT explorer page"),
        }
        for label, (entries, expected) in cases.items():
            with self.subTest(label):
                joined = " | ".join(P.verify(archive(entries)))
                self.assertIn(expected, joined)

    def test_the_explorer_template_is_packaged_but_a_built_explorer_page_never_is(self):
        template = '<script id="ghost-data" type="application/json">/*__GHOST_EXPLORER_DATA__*/null</script>'
        _root, out = self.build(**{"code/ghost_audit/explorer/template.html": template, "code/ghost-audit-explorer.html": '{"datasets":{}}',
                                   "explorer/ghost-audit-explorer.html": '{"datasets":{}}'})
        with zipfile.ZipFile(str(out)) as zf:
            names = zf.namelist()
        self.assertIn("code/ghost_audit/explorer/template.html", names)
        self.assertFalse([n for n in names if n.endswith("ghost-audit-explorer.html")])
        self.assertEqual(P.verify(out), [])

    def test_verify_on_a_missing_archive_reports_it(self):
        self.assertIn("does not exist", P.verify(Path(tempfile.gettempdir()) / "no_such_code.zip")[0])

    def test_main_exit_codes(self):
        root, out = self.build()
        self.assertEqual(P.main(["--root", str(root), "--output", str(out)]), 0)
        (root / "evaluation" / "usage_report.md").unlink()
        self.assertEqual(P.main(["--root", str(root), "--output", str(out)]), 1)

    def test_the_real_repository_packages_cleanly(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "code.zip"
            names = P.build(REPO_ROOT, out)
            self.assertEqual(P.verify(out), [], "the repository does not satisfy the packaging rules")
            self.assertTrue(any(n == "code/main.py" for n in names))
            self.assertFalse([n for n in names if n.startswith("dataset/")])


if __name__ == "__main__":
    unittest.main()
