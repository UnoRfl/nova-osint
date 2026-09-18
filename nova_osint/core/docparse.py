"""Reading a public document for the things it says about the people in it.

A PDF on a company's website is one of the most under-read sources in OSINT.
Not for its prose - for its *metadata*: the author field naming an employee
who never appears on the site, the producer string naming the software and
therefore the platform, the creation date placing a decision in time, and the
body text carrying addresses, handles and third-party names.

All of it is extractable with the standard library. PDF text streams are
Flate-compressed and `zlib` is built in; DOCX and XLSX are Zip archives of
XML and `zipfile` is built in. `pypdf` does a better job of difficult PDFs and
is used when present, but it is never required.

The three rules
---------------

**Metadata is a lead, not an identification.** An author field says which
account was logged into the machine that saved the file. That is a genuinely
strong lead and it is not proof the named person wrote it, still less that
they agree with it. Extracted names are emitted at `POSSIBLE` and described
as what they literally are.

**Extract, never execute.** Nothing here evaluates JavaScript in a PDF,
follows an embedded action, or opens an external reference. It reads bytes.

**A document NOVA could not parse says so.** A failed extraction returns a
:class:`Document` carrying the reason. "No author" and "this is an encrypted
PDF" are different facts and the second must not be rendered as the first.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
import xml.etree.ElementTree as ET
import zipfile
import zlib
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

log = logging.getLogger(__name__)

__all__ = ["Document", "parse", "kind_of", "extract_entities"]

#: Cap on how much text is kept. A thousand-page PDF's full text in a case
#: file helps nobody and makes every later render slow.
MAX_TEXT = 200_000


@dataclass
class Document:
    """What could be read out of one document."""

    source: str                 # URL or path
    kind: str = ""              # pdf | docx | xlsx | html | csv | json | xml | text
    sha256: str = ""
    size_bytes: int = 0
    title: str = ""
    author: str = ""
    creator: str = ""           # the application that made it
    producer: str = ""          # the application that wrote the file out
    created: str = ""
    modified: str = ""
    subject: str = ""
    keywords: str = ""
    company: str = ""
    last_modified_by: str = ""
    pages: int = 0
    text: str = ""
    #: ``{kind: [values]}`` - emails, urls, domains, handles, names.
    entities: dict[str, list[str]] = field(default_factory=dict)
    gaps: list[tuple[str, str]] = field(default_factory=list)

    @property
    def people(self) -> list[str]:
        """Names the document's own metadata attaches to it."""
        found = [v for v in (self.author, self.last_modified_by, self.creator)
                 if v and not _looks_like_software(v)]
        seen: set[str] = set()
        return [v for v in found if not (v.casefold() in seen
                                         or seen.add(v.casefold()))]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source, "kind": self.kind, "sha256": self.sha256,
            "size_bytes": self.size_bytes, "title": self.title,
            "author": self.author, "creator": self.creator,
            "producer": self.producer, "created": self.created,
            "modified": self.modified, "subject": self.subject,
            "keywords": self.keywords, "company": self.company,
            "last_modified_by": self.last_modified_by, "pages": self.pages,
            "text_length": len(self.text), "entities": self.entities,
            "gaps": [{"stage": s, "reason": r} for s, r in self.gaps],
        }


#: Producer and creator strings are software names far more often than human
#: ones. A report listing "Microsoft Word" as a person is a report nobody
#: trusts again.
_SOFTWARE = re.compile(
    r"(word|excel|powerpoint|acrobat|distiller|ghostscript|libreoffice|"
    r"openoffice|pages|latex|pdftex|pdflatex|quartz|chrome|skia|canva|"
    r"indesign|photoshop|illustrator|crystal reports|jasper|wkhtmltopdf|"
    r"reportlab|itext|fpdf|tcpdf|nitro|foxit|pdfkit|prince|weasyprint)", re.I)


def _looks_like_software(value: str) -> bool:
    return bool(_SOFTWARE.search(value)) or bool(re.fullmatch(r"[\d.\s-]+", value))


def kind_of(data: bytes, hint: str = "") -> str:
    """The format, from the bytes first and the filename only as a tiebreak."""
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:2] == b"PK":
        low = hint.lower()
        if low.endswith(".xlsx") or low.endswith(".xlsm"):
            return "xlsx"
        if low.endswith(".pptx"):
            return "pptx"
        return "docx"
    head = data[:2048].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        return "html"
    if head.startswith(b"<?xml") or head.startswith(b"<"):
        return "xml"
    if head[:1] in (b"{", b"["):
        return "json"
    low = hint.lower()
    for suffix, kind in ((".csv", "csv"), (".tsv", "csv"), (".json", "json"),
                         (".xml", "xml"), (".html", "html"), (".htm", "html")):
        if low.endswith(suffix):
            return kind
    return "text"


def parse(data: bytes, source: str = "", hint: str = "") -> Document:
    """Read a document. Never raises; an unreadable file carries its reason."""
    doc = Document(source=source or hint, size_bytes=len(data),
                   sha256=hashlib.sha256(data).hexdigest())
    doc.kind = kind_of(data, hint or source)
    try:
        if doc.kind == "pdf":
            _pdf(data, doc)
        elif doc.kind in ("docx", "xlsx", "pptx"):
            _ooxml(data, doc)
        elif doc.kind == "html":
            _html(data, doc)
        elif doc.kind == "csv":
            _csv(data, doc)
        elif doc.kind == "json":
            _json(data, doc)
        elif doc.kind == "xml":
            _xml(data, doc)
        else:
            doc.text = data.decode("utf-8", "replace")[:MAX_TEXT]
    except Exception as exc:  # noqa: BLE001 - a bad file is not a crash
        doc.gaps.append(("parse", f"{type(exc).__name__}: {exc}"))

    doc.text = doc.text[:MAX_TEXT]
    doc.entities = extract_entities(doc.text)
    return doc


# ------------------------------------------------------------------------ pdf


_PDF_INFO = re.compile(
    rb"/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate)"
    rb"\s*(?:\(((?:[^()\\]|\\.)*)\)|<([0-9A-Fa-f\s]+)>)", re.S)


def _pdf(data: bytes, doc: Document) -> None:
    """Metadata and text, with pypdf when it is installed and by hand when not.

    The hand-rolled path decompresses every Flate stream and pulls the text
    out of the `Tj` / `TJ` show-text operators. It is not a typesetting engine
    and does not try to be: word order within a line survives, exotic
    encodings and column layouts do not. That is enough for the job here,
    which is finding names, addresses and domains - not reproducing the page.
    """
    if _pypdf(data, doc):
        return

    for match in _PDF_INFO.finditer(data[:400_000]):
        key = match.group(1).decode("ascii").lower()
        raw = match.group(2)
        value = (_pdf_string(raw) if raw is not None
                 else _pdf_hex(match.group(3) or b""))
        if not value:
            continue
        setattr_map = {
            "title": "title", "author": "author", "subject": "subject",
            "keywords": "keywords", "creator": "creator",
            "producer": "producer", "creationdate": "created",
            "moddate": "modified",
        }
        attr = setattr_map.get(key)
        if attr and not getattr(doc, attr):
            setattr(doc, attr, _pdf_date(value) if attr in ("created", "modified")
                    else value)

    doc.pages = data.count(b"/Type/Page") + data.count(b"/Type /Page")
    if b"/Encrypt" in data:
        doc.gaps.append(("text", "the PDF is encrypted; metadata only"))
        return

    chunks: list[str] = []
    total = 0
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", data, re.S):
        if total > MAX_TEXT:
            break
        try:
            body = zlib.decompress(match.group(1))
        except zlib.error:
            continue
        text = _pdf_show_text(body)
        if text:
            chunks.append(text)
            total += len(text)
    doc.text = "\n".join(chunks)
    if not doc.text:
        doc.gaps.append(("text", "no extractable text layer - the PDF is "
                                 "probably scanned images (try OCR)"))


def _pypdf(data: bytes, doc: Document) -> bool:
    try:
        from pypdf import PdfReader
    except Exception:  # noqa: BLE001
        return False
    try:
        reader = PdfReader(io.BytesIO(data))
        info = reader.metadata or {}
        doc.title = str(info.get("/Title", "") or "")
        doc.author = str(info.get("/Author", "") or "")
        doc.subject = str(info.get("/Subject", "") or "")
        doc.keywords = str(info.get("/Keywords", "") or "")
        doc.creator = str(info.get("/Creator", "") or "")
        doc.producer = str(info.get("/Producer", "") or "")
        doc.created = _pdf_date(str(info.get("/CreationDate", "") or ""))
        doc.modified = _pdf_date(str(info.get("/ModDate", "") or ""))
        doc.pages = len(reader.pages)
        parts = []
        for page in reader.pages[:200]:
            try:
                parts.append(page.extract_text() or "")
            except Exception:  # noqa: BLE001 - one bad page is not the document
                continue
        doc.text = "\n".join(parts)
        return True
    except Exception as exc:  # noqa: BLE001
        log.debug("pypdf failed, falling back to the built-in reader: %s", exc)
        return False


def _pdf_string(raw: bytes) -> str:
    out = raw.replace(b"\\(", b"(").replace(b"\\)", b")").replace(b"\\\\", b"\\")
    if out[:2] == b"\xfe\xff":
        return out[2:].decode("utf-16-be", "replace").strip()
    return out.decode("utf-8", "replace").strip()


def _pdf_hex(raw: bytes) -> str:
    try:
        blob = bytes.fromhex(re.sub(rb"\s", b"", raw).decode("ascii"))
    except ValueError:
        return ""
    if blob[:2] == b"\xfe\xff":
        return blob[2:].decode("utf-16-be", "replace").strip()
    return blob.decode("utf-8", "replace").strip()


def _pdf_date(value: str) -> str:
    """``D:20240131120000+00'00'`` into something a human and a sort agree on."""
    m = re.match(r"D?:?(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?", value)
    if not m:
        return value.strip()
    y, mo, d, h, mi, s = (g or "" for g in m.groups())
    out = y
    if mo:
        out += f"-{mo}"
    if d:
        out += f"-{d}"
    if h:
        out += f" {h}:{mi or '00'}:{s or '00'}"
    return out


_SHOW = re.compile(rb"\((?:[^()\\]|\\.)*\)")


def _pdf_show_text(body: bytes) -> str:
    if b"Tj" not in body and b"TJ" not in body:
        return ""
    parts = [_pdf_string(m.group(0)[1:-1]) for m in _SHOW.finditer(body)]
    text = " ".join(p for p in parts if p)
    return re.sub(r"\s{2,}", " ", text).strip()


# ---------------------------------------------------------------------- ooxml


_OOXML_FIELDS = {
    "title": "title", "creator": "author", "lastModifiedBy": "last_modified_by",
    "subject": "subject", "keywords": "keywords", "created": "created",
    "modified": "modified", "description": "subject",
}


def _ooxml(data: bytes, doc: Document) -> None:
    """DOCX/XLSX/PPTX: a Zip of XML, so the metadata is two files.

    ``docProps/core.xml`` carries the author and the revision history's last
    editor - which is frequently a *different* person from the author and is
    the more interesting of the two, because it is whoever touched it most
    recently rather than whoever set up the template.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = set(zf.namelist())
        if "docProps/core.xml" in names:
            root = ET.fromstring(zf.read("docProps/core.xml"))
            for el in root:
                tag = el.tag.rsplit("}", 1)[-1]
                attr = _OOXML_FIELDS.get(tag)
                if attr and el.text and not getattr(doc, attr):
                    setattr(doc, attr, el.text.strip())
        if "docProps/app.xml" in names:
            root = ET.fromstring(zf.read("docProps/app.xml"))
            for el in root:
                tag = el.tag.rsplit("}", 1)[-1]
                if tag == "Company" and el.text:
                    doc.company = el.text.strip()
                elif tag == "Application" and el.text and not doc.producer:
                    doc.producer = el.text.strip()
                elif tag == "Pages" and el.text and el.text.isdigit():
                    doc.pages = int(el.text)

        parts = []
        for name in sorted(names):
            if not (name.startswith(("word/", "ppt/slides/", "xl/"))
                    and name.endswith(".xml")):
                continue
            if sum(len(p) for p in parts) > MAX_TEXT:
                break
            try:
                root = ET.fromstring(zf.read(name))
            except ET.ParseError:
                continue
            parts += [t.strip() for t in root.itertext() if t and t.strip()]
        doc.text = " ".join(parts)


# ----------------------------------------------------------------------- html


class _Text(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False
        self._skip = 0

    def handle_starttag(self, tag, attrs) -> None:
        if tag in ("script", "style", "noscript"):
            self._skip += 1
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            a = {k.lower(): (v or "") for k, v in attrs}
            key = (a.get("name") or a.get("property") or "").lower()
            if key and a.get("content"):
                self.meta[key] = a["content"]

    def handle_endtag(self, tag) -> None:
        if tag in ("script", "style", "noscript") and self._skip:
            self._skip -= 1
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data) -> None:
        if self._skip:
            return
        text = data.strip()
        if not text:
            return
        if self._in_title:
            self.title += text
        else:
            self.parts.append(text)


def _html(data: bytes, doc: Document) -> None:
    parser = _Text()
    parser.feed(data.decode("utf-8", "replace"))
    doc.title = parser.title.strip()
    doc.text = " ".join(parser.parts)
    meta = parser.meta
    doc.author = meta.get("author", "") or meta.get("article:author", "")
    doc.subject = meta.get("description", "")
    doc.keywords = meta.get("keywords", "")
    doc.producer = meta.get("generator", "")
    doc.created = meta.get("article:published_time", "")
    doc.modified = meta.get("article:modified_time", "")


def _csv(data: bytes, doc: Document) -> None:
    text = data.decode("utf-8", "replace")
    sample = text[:8192]
    try:
        dialect = csv.Sniffer().sniff(sample)
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    doc.pages = len(rows)
    if rows:
        doc.title = ", ".join(rows[0][:8])
    doc.text = "\n".join(" ".join(r) for r in rows[:2000])


def _json(data: bytes, doc: Document) -> None:
    parsed = json.loads(data.decode("utf-8", "replace"))
    doc.text = json.dumps(parsed, indent=1)[:MAX_TEXT]


def _xml(data: bytes, doc: Document) -> None:
    root = ET.fromstring(data)
    doc.title = root.tag.rsplit("}", 1)[-1]
    doc.text = " ".join(t.strip() for t in root.itertext() if t and t.strip())


# ------------------------------------------------------------------ entities


_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_DOI = re.compile(r"\b10\.\d{4,9}/[-._;()/:A-Za-z0-9]+\b")
_PHONEISH = re.compile(r"(?<![\d-])\+?\d[\d\s().-]{8,16}\d(?![\d-])")
_HANDLE = re.compile(r"(?<![\w@/])@([A-Za-z0-9_]{3,30})\b")


def extract_entities(text: str) -> dict[str, list[str]]:
    """Identifiers a document contains. Kept as *contents*, not attributions.

    Whose they are is a separate question the graph answers with evidence. A
    contact address in a report's footer belongs to the organisation; one in
    the body may belong to a third party; and a parser that hands both to the
    caller as "the author's address" invents a person.
    """
    if not text:
        return {}
    out: dict[str, list[str]] = {}

    def collect(key: str, values: Any) -> None:
        seen: set[str] = set()
        kept = []
        for v in values:
            v = v.strip().rstrip(".,;:)")
            low = v.casefold()
            if v and low not in seen:
                seen.add(low)
                kept.append(v)
            if len(kept) >= 200:
                break
        if kept:
            out[key] = kept

    collect("emails", _EMAIL.findall(text))
    collect("urls", _URL.findall(text))
    collect("dois", _DOI.findall(text))
    collect("usernames", _HANDLE.findall(text))
    collect("domains", sorted({
        (u.split("//", 1)[-1].split("/", 1)[0].split(":")[0]).lower()
        for u in out.get("urls", [])
    } | {
        a.split("@", 1)[1].lower() for a in out.get("emails", [])
    }))
    # Phone-shaped strings only; the phone module decides whether they are
    # real numbers, because "looks like a phone number" catches invoice
    # numbers, ISBNs and dates written three different ways.
    collect("phone_like", _PHONEISH.findall(text))
    return out
