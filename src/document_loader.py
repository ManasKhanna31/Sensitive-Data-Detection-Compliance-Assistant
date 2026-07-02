"""
document_loader.py
-------------------
Normalizes PDF / TXT / CSV uploads into plain text for the detection engine.

OCR fallback: if a PDF yields little/no extractable text via pypdf (common
for scanned documents that are just page images with no text layer), we
rasterize each page and run Tesseract OCR on it. This is best-effort: if the
OCR system dependencies (tesseract-ocr, poppler-utils) aren't installed in
the current environment, we fail gracefully and just return whatever pypdf
found, rather than crashing the app.
"""

import io
import csv
from typing import Union

import pandas as pd
from pypdf import PdfReader

# Minimum characters we expect from a genuinely text-based PDF page before
# we consider it "empty" and worth trying OCR on instead.
_OCR_TRIGGER_THRESHOLD = 20


def _ocr_pdf(file_bytes: bytes) -> str:
    """Best-effort OCR fallback for scanned/image-only PDFs. Returns an
    empty string (never raises) if OCR dependencies aren't available."""
    try:
        import pytesseract
        from pdf2image import convert_from_bytes
    except ImportError:
        return ""

    try:
        pages = convert_from_bytes(file_bytes, dpi=200)
    except Exception:
        # poppler-utils (the `pdftoppm` binary) not installed, or a
        # malformed/encrypted PDF pdf2image can't rasterize.
        return ""

    ocr_text = []
    for page_image in pages:
        try:
            ocr_text.append(pytesseract.image_to_string(page_image))
        except Exception:
            # tesseract binary not installed/misconfigured
            return ""
    return "\n".join(ocr_text)


def load_text(file_bytes: bytes, filename: str) -> str:
    ext = filename.lower().split(".")[-1]

    if ext == "txt":
        return file_bytes.decode("utf-8", errors="ignore")

    if ext == "csv":
        try:
            df = pd.read_csv(
                io.BytesIO(file_bytes), dtype=str, keep_default_na=False,
                on_bad_lines="skip", engine="python",
            )
            # Flatten the whole CSV into text so regexes can scan every cell,
            # while keeping row/column context readable.
            lines = [", ".join(df.columns)]
            for _, row in df.iterrows():
                lines.append(", ".join(str(v) for v in row.values))
            return "\n".join(lines)
        except Exception:
            # Malformed/non-standard CSV: fall back to raw text so detection
            # can still run on whatever content is present, instead of crashing.
            return file_bytes.decode("utf-8", errors="ignore")

    if ext == "pdf":
        reader = PdfReader(io.BytesIO(file_bytes))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        text = "\n".join(pages)

        if len(text.strip()) < _OCR_TRIGGER_THRESHOLD:
            ocr_text = _ocr_pdf(file_bytes)
            if len(ocr_text.strip()) > len(text.strip()):
                return ocr_text
        return text

    raise ValueError(f"Unsupported file type: .{ext}. Supported: pdf, txt, csv")
