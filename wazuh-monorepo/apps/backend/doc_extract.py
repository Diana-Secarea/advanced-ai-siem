"""
Multi-format document extraction for the RAG knowledge base.

Turns PDF / DOCX / HTML / TXT / MD / JSON uploads into clean plain text,
with TABLES preserved as pipe-delimited rows so tabular knowledge survives
chunking and embedding (a plain text-dump loses row/column relationships).

Design choices (documented for the PoC write-up):
  PDF   — pdfplumber: layout-aware text + real table detection. Falls back to
          pypdf raw text when pdfplumber chokes on a page. Scanned/image-only
          PDFs are detected (no extractable text) and rejected with a clear
          message rather than silently indexing nothing — OCR is a deliberate
          non-goal at PoC stage.
  DOCX  — python-docx: walks the document body in order, so paragraphs and
          tables stay interleaved the way the author wrote them.
  HTML  — BeautifulSoup(lxml): strips script/style/nav chrome, converts
          <table> to pipe rows, keeps heading structure as text.

Every extractor returns (text, notes) — notes lists anything lossy that
happened (e.g. pages skipped) so the API response can be transparent.
"""

import io
import json


SUPPORTED_EXTS = (".pdf", ".docx", ".html", ".htm", ".txt", ".md", ".json")


def _table_to_text(rows):
    """Render a table (list of row-lists) as pipe-delimited lines."""
    lines = []
    for row in rows:
        cells = [(str(c).strip().replace("\n", " ") if c is not None else "") for c in row]
        if any(cells):
            lines.append(" | ".join(cells))
    return "\n".join(lines)


# ---------------------------------------------------------------- PDF ------

def _extract_pdf(raw: bytes):
    notes = []
    parts = []
    try:
        import pdfplumber
        with pdfplumber.open(io.BytesIO(raw)) as pdf:
            for page_no, page in enumerate(pdf.pages, 1):
                try:
                    text = page.extract_text() or ""
                    tables = page.extract_tables() or []
                except Exception as e:
                    notes.append(f"page {page_no}: extraction failed ({e})")
                    continue
                if text.strip():
                    parts.append(text.strip())
                for t in tables:
                    rendered = _table_to_text(t)
                    if rendered:
                        parts.append(f"[TABLE p.{page_no}]\n{rendered}")
    except Exception as e:
        notes.append(f"pdfplumber failed ({e}) — falling back to pypdf")
        try:
            from pypdf import PdfReader
            reader = PdfReader(io.BytesIO(raw))
            for page in reader.pages:
                text = page.extract_text() or ""
                if text.strip():
                    parts.append(text.strip())
        except Exception as e2:
            raise ValueError(f"Cannot parse PDF: {e2}")

    text = "\n\n".join(parts)
    if not text.strip():
        raise ValueError(
            "No extractable text found — this looks like a scanned/image-only "
            "PDF. OCR is not enabled; please provide a text-based export.")
    return text, notes


# ---------------------------------------------------------------- DOCX -----

def _extract_docx(raw: bytes):
    from docx import Document
    from docx.table import Table
    from docx.text.paragraph import Paragraph

    doc = Document(io.BytesIO(raw))
    parts = []
    # Walk the body in author order so tables stay next to their context
    for element in doc.element.body:
        if element.tag.endswith("}p"):
            para = Paragraph(element, doc)
            if para.text.strip():
                parts.append(para.text.strip())
        elif element.tag.endswith("}tbl"):
            table = Table(element, doc)
            rows = [[cell.text for cell in row.cells] for row in table.rows]
            rendered = _table_to_text(rows)
            if rendered:
                parts.append(f"[TABLE]\n{rendered}")
    text = "\n\n".join(parts)
    if not text.strip():
        raise ValueError("DOCX contains no extractable text")
    return text, []


# ---------------------------------------------------------------- HTML -----

def _extract_html(raw: bytes):
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(raw, "lxml")
    for junk in soup(["script", "style", "noscript", "iframe"]):
        junk.decompose()

    parts = []
    # Tables first: render + remove so the text pass doesn't flatten them
    for table in soup.find_all("table"):
        rows = [[cell.get_text(" ", strip=True) for cell in tr.find_all(["td", "th"])]
                for tr in table.find_all("tr")]
        rendered = _table_to_text(rows)
        if rendered:
            parts.append(f"[TABLE]\n{rendered}")
        table.decompose()

    body_text = soup.get_text("\n", strip=True)
    if body_text:
        parts.insert(0, body_text)

    text = "\n\n".join(parts)
    if not text.strip():
        raise ValueError("HTML contains no extractable text")
    return text, []


# ------------------------------------------------------------- dispatch ----

def extract_text(filename: str, raw: bytes, ext: str):
    """Return (text, notes) for a supported upload; raises ValueError otherwise."""
    if ext == ".pdf":
        return _extract_pdf(raw)
    if ext == ".docx":
        return _extract_docx(raw)
    if ext in (".html", ".htm"):
        return _extract_html(raw)
    if ext == ".json":
        try:
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
        return json.dumps(parsed, indent=2, ensure_ascii=False), []
    if ext in (".txt", ".md", ""):
        return raw.decode("utf-8", errors="replace"), []
    raise ValueError(
        f"Unsupported file type '{ext}'. Supported: {', '.join(SUPPORTED_EXTS)}")
