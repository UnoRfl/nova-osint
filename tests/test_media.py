"""Image and document intelligence, on fixtures the tests build themselves.

Every fixture here is generated in-process - a PNG assembled chunk by chunk, a
JPEG with a hand-written EXIF block, a DOCX zipped on the fly - so the suite
stays offline, stays fast, and does not carry binary blobs nobody can review.
"""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib

import pytest

from nova_osint.core.docparse import Document, extract_entities, kind_of, parse
from nova_osint.core.imageint import (
    ImageFacts,
    analyse,
    dimensions,
    hamming,
    have_pillow,
    read_clues,
    read_exif,
)

# ------------------------------------------------------------------ fixtures


def png(width: int = 8, height: int = 8, text: dict[str, str] | None = None,
        seed: int = 0) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        c = kind + body
        return (struct.pack(">I", len(body)) + c
                + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF))

    raw = b"".join(
        b"\x00" + bytes((x * 31 + y * 17 + seed) % 256 for x in range(width))
        for y in range(height))
    out = [b"\x89PNG\r\n\x1a\n",
           chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))]
    for key, value in (text or {}).items():
        out.append(chunk(b"tEXt", key.encode() + b"\x00" + value.encode()))
    out.append(chunk(b"IDAT", zlib.compress(raw)))
    out.append(chunk(b"IEND", b""))
    return b"".join(out)


def jpeg_with_exif(make: str = "NOVA", model: str = "Test Cam",
                   software: str = "") -> bytes:
    """A minimal JPEG carrying a real little-endian TIFF block in APP1."""
    entries: list[tuple[int, bytes]] = [(0x010F, make.encode() + b"\x00"),
                                        (0x0110, model.encode() + b"\x00")]
    if software:
        entries.append((0x0131, software.encode() + b"\x00"))

    count = len(entries)
    header = b"II*\x00" + struct.pack("<I", 8)
    ifd = struct.pack("<H", count)
    # Values go after the IFD and its next-offset field.
    data_at = 8 + 2 + count * 12 + 4
    blobs = b""
    for tag, value in entries:
        if len(value) <= 4:
            payload = value.ljust(4, b"\x00")
        else:
            payload = struct.pack("<I", data_at + len(blobs))
            blobs += value
        ifd += struct.pack("<HHI", tag, 2, len(value)) + payload
    ifd += struct.pack("<I", 0)
    tiff = header + ifd + blobs

    app1 = b"Exif\x00\x00" + tiff
    seg = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    sof = (b"\xff\xc0" + struct.pack(">H", 11) + b"\x08"
           + struct.pack(">HH", 40, 60) + b"\x01\x01\x11\x00")
    return b"\xff\xd8\xff\xe0" + struct.pack(">H", 16) + b"JFIF\x00" + \
        b"\x01\x01\x00\x00\x01\x00\x01\x00\x00" + seg + sof + b"\xff\xd9"


def docx(author: str = "Ada Lovelace", last: str = "Charles Babbage",
         company: str = "Analytical Engines Ltd", body: str = "hello") -> bytes:
    buf = io.BytesIO()
    core = f"""<?xml version="1.0"?>
    <cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
      xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:title>A Memorandum</dc:title>
      <dc:creator>{author}</dc:creator>
      <cp:lastModifiedBy>{last}</cp:lastModifiedBy>
      <dcterms:created xmlns:dcterms="http://purl.org/dc/terms/">2024-01-31T09:00:00Z</dcterms:created>
    </cp:coreProperties>"""
    app = f"""<?xml version="1.0"?>
    <Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
      <Application>Microsoft Office Word</Application>
      <Company>{company}</Company><Pages>3</Pages>
    </Properties>"""
    doc = f"""<?xml version="1.0"?>
    <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:body><w:p><w:r><w:t>{body}</w:t></w:r></w:p></w:body>
    </w:document>"""
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("docProps/core.xml", core)
        zf.writestr("docProps/app.xml", app)
        zf.writestr("word/document.xml", doc)
    return buf.getvalue()


def pdf(author: str = "Ada Lovelace", producer: str = "pdfTeX-1.40",
        body: str = "Contact ada@example.org about the engine") -> bytes:
    stream = zlib.compress(f"BT /F1 12 Tf ({body}) Tj ET".encode())
    return (b"%PDF-1.4\n"
            b"1 0 obj<</Type/Page>>endobj\n"
            b"2 0 obj<</Title (A Report) /Author (" + author.encode() +
            b") /Producer (" + producer.encode() +
            b") /CreationDate (D:20240131120000)>>endobj\n"
            b"3 0 obj<</Length " + str(len(stream)).encode() + b">>stream\n"
            + stream + b"\nendstream endobj\n%%EOF")


# -------------------------------------------------------------------- images


@pytest.mark.parametrize("data,expected", [
    (png(20, 10), ("png", 20, 10)),
    (jpeg_with_exif(), ("jpeg", 60, 40)),
    (b"GIF89a" + struct.pack("<HH", 7, 3) + b"\x00" * 10, ("gif", 7, 3)),
    (b"not an image at all", ("", 0, 0)),
])
def test_dimensions_are_read_from_the_header_alone(data, expected) -> None:
    assert dimensions(data) == expected


def test_jpeg_exif_gives_up_the_camera() -> None:
    exif = read_exif(jpeg_with_exif("Canon", "EOS 5D"))
    assert exif.get("make") == "Canon"
    assert exif.get("model") == "EOS 5D"


def test_png_text_chunks_are_metadata_too() -> None:
    exif = read_exif(png(text={"Software": "NOVA", "Author": "Ada"}))
    assert exif["software"] == "NOVA" and exif["author"] == "Ada"


def test_a_file_that_is_not_an_image_yields_nothing_rather_than_raising() -> None:
    assert read_exif(b"\x00\x01\x02 rubbish") == {}
    assert dimensions(b"") == ("", 0, 0)


def test_an_unreadable_path_is_a_gap_not_an_exception(tmp_path) -> None:
    facts = analyse(tmp_path / "nothing-here.png")
    assert isinstance(facts, ImageFacts)
    assert any(stage == "read" for stage, _ in facts.gaps)


def test_analyse_always_hashes_the_bytes(tmp_path) -> None:
    p = tmp_path / "a.png"
    p.write_bytes(png())
    facts = analyse(p, do_ocr=False)
    assert len(facts.sha256) == 64
    assert facts.format == "png" and facts.width == 8


def test_missing_exif_is_reported_as_a_finding_in_itself(tmp_path) -> None:
    p = tmp_path / "bare.png"
    p.write_bytes(png())
    facts = analyse(p, do_ocr=False)
    reasons = " ".join(r for _, r in facts.gaps)
    assert "strips it" in reasons, \
        "stripped metadata says where an image has been; it is not nothing"


def test_no_ocr_engine_is_a_named_gap_not_an_empty_result(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("nova_osint.core.imageint.have_ocr", lambda: (False, ""))
    p = tmp_path / "a.png"
    p.write_bytes(png())
    facts = analyse(p)
    assert facts.text == ""
    assert any(stage == "text" and "tesseract" in reason
               for stage, reason in facts.gaps)


@pytest.mark.skipif(not have_pillow(), reason="perceptual hashing needs Pillow")
def test_the_same_picture_hashes_the_same_and_a_different_one_does_not(tmp_path) -> None:
    a, b, c = tmp_path / "a.png", tmp_path / "b.png", tmp_path / "c.png"
    a.write_bytes(png(32, 32, seed=0))
    b.write_bytes(png(32, 32, seed=0))
    c.write_bytes(png(32, 32, seed=97))
    fa, fb, fc = (analyse(p, do_ocr=False) for p in (a, b, c))
    assert hamming(fa.ahash, fb.ahash) == 0
    assert hamming(fa.ahash, fc.ahash) > 0


def test_hashes_that_cannot_be_compared_report_maximum_distance() -> None:
    assert hamming("", "abcd") == 64
    assert hamming("zz", "zz") == 64, "non-hex is not a distance of zero"


def test_no_pillow_means_no_hash_and_a_gap_rather_than_a_guess(
        tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("nova_osint.core.imageint.phash", lambda data: ("", ""))
    p = tmp_path / "a.png"
    p.write_bytes(png())
    facts = analyse(p, do_ocr=False)
    assert facts.ahash == ""
    assert any("Pillow" in reason for _, reason in facts.gaps)


def test_clues_found_in_image_text_become_searchable_things() -> None:
    text = ("EXAMPLE CONFERENCE 2026\nada@example.org\n@adalovelace\n"
            "https://engines.example.org/talks")
    clues = dict(read_clues(text))
    assert clues["email"] == "ada@example.org"
    assert clues["username"] == "adalovelace"
    assert clues["year"] == "2026"
    assert "engines.example.org" in " ".join(v for _, v in read_clues(text))


def test_clue_reading_does_not_turn_stopwords_into_organisations() -> None:
    kinds = [k for k, _ in read_clues("The Meeting Room")]
    assert "phrase" not in kinds or all(
        not v.startswith("The ") for k, v in read_clues("The Meeting Room")
        if k == "phrase")


def test_image_clues_become_queries_that_keep_their_provenance() -> None:
    from nova_osint.core.imageint import clues_to_queries
    from nova_osint.core.queryplan import QueryPlanner

    facts = ImageFacts(path="/tmp/badge.png",
                       clues=[("email", "ada@example.org"),
                              ("phrase", "Example Conference")])
    made = clues_to_queries(facts, QueryPlanner(), subject="Ada Lovelace")
    assert made
    assert all("image:badge.png" in q.origin for q in made), \
        "a result three hops later must still trace back to the photograph"


# ----------------------------------------------------------------- documents


@pytest.mark.parametrize("data,hint,expected", [
    (b"%PDF-1.7\n...", "", "pdf"),
    (docx(), "memo.docx", "docx"),
    (b"<!DOCTYPE html><html>", "", "html"),
    (b'{"a": 1}', "", "json"),
    (b"<?xml version='1.0'?><a/>", "", "xml"),
    (b"a,b,c\n1,2,3\n", "table.csv", "csv"),
    (b"just words", "notes.txt", "text"),
])
def test_the_format_is_read_from_the_bytes_first(data, hint, expected) -> None:
    assert kind_of(data, hint) == expected


def test_a_pdf_gives_up_its_author_and_the_software_that_wrote_it() -> None:
    doc = parse(pdf(), source="https://x.test/report.pdf")
    assert doc.kind == "pdf"
    assert doc.author == "Ada Lovelace"
    assert doc.producer.startswith("pdfTeX")
    assert doc.created.startswith("2024-01-31")


def test_pdf_body_text_yields_the_addresses_inside_it() -> None:
    doc = parse(pdf(body="write to ada@example.org or see https://e.test/x"))
    assert "ada@example.org" in doc.entities.get("emails", [])
    assert any("e.test" in d for d in doc.entities.get("domains", []))


def test_an_encrypted_pdf_says_so_instead_of_reporting_no_text() -> None:
    data = pdf().replace(b"%%EOF", b"/Encrypt 9 0 R\n%%EOF")
    doc = parse(data)
    assert any("encrypted" in reason for _, reason in doc.gaps)


def test_a_scanned_pdf_is_distinguished_from_an_empty_one() -> None:
    doc = parse(b"%PDF-1.4\n1 0 obj<</Type/Page>>endobj\n%%EOF")
    assert any("scanned" in reason for _, reason in doc.gaps), \
        "no text layer and no text are different facts"


def test_software_in_the_author_field_is_not_reported_as_a_person() -> None:
    doc = parse(pdf(author="Microsoft Word", producer="Acrobat Distiller"))
    assert doc.people == [], \
        "a report naming Microsoft Word as a person is a report nobody trusts"


def test_a_docx_gives_up_both_the_author_and_the_last_editor() -> None:
    doc = parse(docx(), hint="memo.docx")
    assert doc.author == "Ada Lovelace"
    assert doc.last_modified_by == "Charles Babbage"
    assert doc.company == "Analytical Engines Ltd"
    assert doc.pages == 3
    assert "Ada Lovelace" in doc.people and "Charles Babbage" in doc.people


def test_docx_body_text_is_extracted() -> None:
    doc = parse(docx(body="the engine weaves algebraic patterns"), hint="a.docx")
    assert "algebraic patterns" in doc.text


def test_html_metadata_and_text_are_read_without_scripts() -> None:
    html = (b"<html><head><title>A Page</title>"
            b"<meta name='author' content='Ada'>"
            b"<meta name='generator' content='Hugo'>"
            b"</head><body><script>var x='SECRET';</script>"
            b"<p>visible text</p></body></html>")
    doc = parse(html, hint="p.html")
    assert doc.title == "A Page" and doc.author == "Ada"
    assert doc.producer == "Hugo"
    assert "visible text" in doc.text and "SECRET" not in doc.text


def test_a_corrupt_file_carries_its_reason_rather_than_raising() -> None:
    doc = parse(b"PK\x03\x04 truncated nonsense", hint="broken.docx")
    assert isinstance(doc, Document)
    assert doc.gaps and doc.gaps[0][0] == "parse"


def test_extracted_identifiers_are_contents_not_attributions() -> None:
    found = extract_entities("mail a@x.test and b@y.test, see https://z.test/p")
    assert set(found["emails"]) == {"a@x.test", "b@y.test"}
    assert "z.test" in found["domains"]
    # Two addresses and no claim about which belongs to the subject: whose
    # they are is the graph's question, answered with evidence.
    assert "author" not in found


def test_text_is_capped_so_one_huge_pdf_cannot_bloat_a_case() -> None:
    from nova_osint.core.docparse import MAX_TEXT

    doc = parse(("x" * (MAX_TEXT + 5000)).encode(), hint="big.txt")
    assert len(doc.text) <= MAX_TEXT


def test_the_documents_module_declares_itself_active() -> None:
    from nova_osint.modules.documents import DocumentModule

    assert DocumentModule.active is True, \
        "it fetches from the target's own server"
    from nova_osint.core.models import TargetType

    assert TargetType.URL in DocumentModule.accepts


def test_the_documents_module_reports_properties_as_what_they_are() -> None:
    from nova_osint.core.config import Config
    from nova_osint.core.http import Response
    from nova_osint.core.models import ScanResult, TargetType
    from nova_osint.modules.documents import DocumentModule

    class Fetch:
        def get(self, url, **kw):
            return Response(url=url, status=200, body=docx(),
                            headers={"content-type": "application/vnd.openxmlformats"})

    result = ScanResult(module="documents", target="https://x.test/a.docx",
                        target_type=TargetType.URL)
    DocumentModule(Fetch(), Config()).run("https://x.test/a.docx", result)

    named = [f for f in result.findings if f.label == "named in document properties"]
    assert {f.value for f in named} == {"Ada Lovelace", "Charles Babbage"}
    assert all("not proof of authorship" in f.extra.get("meaning", "")
               for f in named)
    assert all(f.acquisition is not None for f in result.findings)


def test_an_oversized_document_is_named_not_downloaded_silently() -> None:
    from nova_osint.core.config import Config
    from nova_osint.core.http import Response
    from nova_osint.core.models import ModuleStatus, ScanResult, TargetType
    from nova_osint.modules.documents import MAX_BYTES, DocumentModule

    class Fetch:
        def get(self, url, **kw):
            return Response(url=url, status=200, body=b"%PDF-" + b"x" * MAX_BYTES,
                            headers={"content-type": "application/pdf"})

    result = ScanResult(module="documents", target="https://x.test/big.pdf",
                        target_type=TargetType.URL)
    DocumentModule(Fetch(), Config()).run("https://x.test/big.pdf", result)
    assert result.status is ModuleStatus.PARTIAL
    assert any("too large" in e for e in result.errors)


def test_json_and_csv_are_read_as_text_for_identifier_extraction() -> None:
    doc = parse(json.dumps({"contact": "ada@example.org"}).encode(), hint="a.json")
    assert "ada@example.org" in doc.entities.get("emails", [])
    csv_doc = parse(b"name,email\nAda,ada@example.org\n", hint="a.csv")
    assert csv_doc.pages == 2
    assert "ada@example.org" in csv_doc.entities.get("emails", [])
