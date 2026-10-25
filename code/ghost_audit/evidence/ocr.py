"""Offline OCR through the Tesseract command-line program (no runtime model/API calls).

Why the CLI and not a Python wrapper: it needs no extra pip package, exposes per-word confidence
through ``tsv`` output, and is a plain, auditable subprocess call:

* ``shell=False``, a fixed argument vector, a timeout, and an absolute image path (so it can never
  be read as an option);
* the executable comes only from ``$TESSERACT_CMD``, ``PATH`` or the standard Windows install
  directories, and must be named ``tesseract[.exe]``;
* pictures are upscaled with Pillow into a private ``TemporaryDirectory`` (the evidence is only read).

Measured on the supplied screenshots, native-resolution OCR misreads identifiers
(``areed1433`` -> ``areedi433``) while 2x upscaling reads them exactly, so upscaling is the default
whenever Pillow is present; without Pillow OCR still runs at 1x and says so.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

_WINDOWS_DIRS = (r"C:\Program Files\Tesseract-OCR", r"C:\Program Files (x86)\Tesseract-OCR")
INSTALL_HINT = ("install Tesseract (Windows: https://github.com/UB-Mannheim/tesseract/wiki, then add it to PATH or set "
                "TESSERACT_CMD; Linux: apt install tesseract-ocr; macOS: brew install tesseract) and `pip install Pillow`")
DEFAULT_TIMEOUT_S = 120
MAX_IMAGE_PIXELS = 40_000_000   # refuse decompression bombs / absurd inputs


@dataclass(frozen=True)
class OcrWord:
    text: str
    conf: float          # 0-100 as reported by Tesseract
    left: int            # original-image pixel coordinates (already divided by the upscale)
    top: int
    width: int
    height: int


@dataclass(frozen=True)
class OcrPass:
    psm: int
    scale: int
    words: Tuple[OcrWord, ...]


def find_tesseract() -> Optional[str]:
    candidates: List[str] = []
    env = os.environ.get("TESSERACT_CMD")
    if env:
        candidates.append(env)
    which = shutil.which("tesseract")
    if which:
        candidates.append(which)
    candidates += [os.path.join(d, "tesseract.exe") for d in _WINDOWS_DIRS]
    for c in candidates:
        if Path(c).name.lower() in ("tesseract", "tesseract.exe") and Path(c).is_file():
            return str(Path(c).resolve())
    return None


def tesseract_version(cmd: str) -> Optional[str]:
    try:
        out = subprocess.run([cmd, "--version"], capture_output=True, text=True, timeout=30, shell=False)
    except (OSError, subprocess.SubprocessError):
        return None
    text = (out.stdout or out.stderr).strip().splitlines()
    return text[0].strip() if text else None


def pillow_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("PIL") is not None


class OcrError(Exception):
    pass


def run_pass(cmd: str, image_path: Path, psm: int, scale: int, timeout: int = DEFAULT_TIMEOUT_S) -> OcrPass:
    """OCR one image with one configuration. Raises :class:`OcrError` on any failure."""
    if not image_path.is_absolute():
        raise OcrError("image path must be absolute")
    with tempfile.TemporaryDirectory() as tmp:
        target = image_path
        if scale != 1:
            try:
                from PIL import Image
                with Image.open(str(image_path)) as im:   # lazy: reads the header only
                    if im.width * im.height > MAX_IMAGE_PIXELS:
                        raise OcrError("image has %d pixels, above the %d limit" % (im.width * im.height, MAX_IMAGE_PIXELS))
                    big = im.convert("RGB").resize((im.width * scale, im.height * scale), Image.LANCZOS)
                    target = Path(tmp) / "upscaled.png"
                    big.save(str(target))
            except OcrError:
                raise
            except Exception as exc:  # corrupt image, decompression bomb, ...
                raise OcrError("cannot decode image: %s: %s" % (type(exc).__name__, exc))
        try:
            proc = subprocess.run([cmd, str(target), "stdout", "--psm", str(psm), "-l", "eng", "tsv"],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, shell=False,
                                  env=dict(os.environ, OMP_THREAD_LIMIT="1"))  # one thread per process: passes run in parallel
        except subprocess.TimeoutExpired:
            raise OcrError("tesseract timed out after %ds" % timeout)
        except OSError as exc:
            raise OcrError("cannot run tesseract: %s" % exc)
    if proc.returncode != 0:
        raise OcrError("tesseract exited with %d: %s" % (proc.returncode, (proc.stderr or "").strip()[:200]))
    words: List[OcrWord] = []
    for line in proc.stdout.splitlines()[1:]:
        cols = line.split("\t")
        if len(cols) != 12 or not cols[11].strip():
            continue
        try:
            conf = float(cols[10])
            left, top, w, h = (int(cols[i]) for i in (6, 7, 8, 9))
        except ValueError:
            continue
        if conf < 0:
            continue
        words.append(OcrWord(cols[11].strip(), conf, left // scale, top // scale, max(1, w // scale), max(1, h // scale)))
    return OcrPass(psm, scale, tuple(words))
