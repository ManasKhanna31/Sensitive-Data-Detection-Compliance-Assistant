"""
document_loader.py
-------------------
Normalizes PDF / TXT / CSV uploads into plain text for the detection engine.
"""

import io
import csv
from typing import Union

import pandas as pd
from pypdf import PdfReader


def load_text(file_bytes: bytes, filename: str) -> str:
    ext = filename.lower().split(".")[-1]

    if ext == "txt":
        return file_bytes.decode("utf-8", errors="ignore")

    if ext == "csv":
        df = pd.read_csv(io.BytesIO(file_bytes), dtype=str, keep_default_na=False)
        # Flatten the whole CSV into text so regexes can scan every cell,
        # while keeping row/column context readable.
        lines = [", ".join(df.columns)]
        for _, row in df.iterrows():
            lines.append(", ".join(str(v) for v in row.values))
        return "\n".join(lines)

    if ext == "pdf":
        reader = PdfReader(io.BytesIO(file_bytes))
        pages = []
        for page in reader.pages:
            pages.append(page.extract_text() or "")
        return "\n".join(pages)

    raise ValueError(f"Unsupported file type: .{ext}. Supported: pdf, txt, csv")
