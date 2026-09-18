"""Fetching a public document and reading what it says about who made it.

Pointed at a URL that turns out to be a PDF, a DOCX or a spreadsheet, this
reports the file's metadata, the identifiers in its text, and the people its
own properties attach to it.

The distinction the module exists to keep
-----------------------------------------

``/Author`` is not "who wrote this". It is "the display name configured on
the account that was logged into the machine when the file was saved". Those
coincide often enough to be a strong lead and differ often enough - shared
workstations, templates, an assistant, a contractor, a document converted by
a service - that reporting the first as the second is exactly the kind of
confident nonsense this tool is built not to produce.

So the author becomes an entity on ``document-author`` evidence, which is
worth rather less than a profile page and rather more than a name match, and
the finding says what the field literally is.
"""

from __future__ import annotations

import urllib.parse

from ..core.acquisition import Acquisition, Method, SourceType
from ..core.docparse import parse
from ..core.entities import EntityType
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

#: Extensions worth fetching as documents. A URL with none of these is still
#: fetched when the server says it is one - the content type is the truth and
#: the extension is a hint.
DOC_SUFFIXES = (".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".csv",
                ".tsv", ".rtf", ".odt", ".ods", ".xml", ".json", ".txt")

DOC_TYPES = ("application/pdf", "application/vnd.openxmlformats",
             "application/msword", "application/vnd.ms-", "text/csv",
             "application/rtf", "application/vnd.oasis")

#: Above this, the file is reported and not downloaded. A report that stalls
#: for four minutes on a 600 MB dataset has cost more than it found.
MAX_BYTES = 25 * 1024 * 1024


@register
class DocumentModule(Module):
    name = "documents"
    title = "Document metadata"
    description = ("Fetches a public document and reports its metadata, the "
                   "people its properties name, and the identifiers in its "
                   "text.")
    accepts = frozenset({TargetType.URL})
    #: It fetches from the target's own server, so it is an active module.
    active = True

    def run(self, target: str, result: ScanResult) -> None:
        resp = self.http.get(target)
        if resp.access.is_refusal:
            result.degrade(ModuleStatus.UNAVAILABLE, resp.describe())
            result.error(f"{target}: {resp.describe()}")
            return
        if not resp.ok:
            return

        ctype = resp.header("content-type").lower()
        path = urllib.parse.urlsplit(target).path.lower()
        looks_like_a_document = (
            path.endswith(DOC_SUFFIXES)
            or any(ctype.startswith(t) for t in DOC_TYPES)
        )
        # An HTML page is still worth its metadata; anything else that is
        # neither a document nor a page is not this module's business.
        if not looks_like_a_document and "text/html" not in ctype:
            return

        if len(resp.body) > MAX_BYTES:
            result.degrade(ModuleStatus.PARTIAL,
                           f"{len(resp.body) // 1_048_576} MB is above the "
                           f"{MAX_BYTES // 1_048_576} MB download limit")
            result.error(f"{target}: too large to read ({len(resp.body):,} bytes)")
            return

        doc = parse(resp.body, source=target, hint=path)
        acq = Acquisition.from_response(resp, "documents", method=Method.PAGE,
                                        source_type=SourceType.DOCUMENT,
                                        requested=target)
        self._report(doc, acq, result)

    # ------------------------------------------------------------ reporting

    def _report(self, doc, acq, result: ScanResult) -> None:
        def add(label, value, **kw):
            if not value:
                return None
            finding = result.add(label, value, source="documents", **kw)
            finding.acquisition = acq
            return finding

        add("document type", doc.kind, confidence=Confidence.CONFIRMED)
        add("title", doc.title)
        add("sha256", doc.sha256, confidence=Confidence.CONFIRMED)
        if doc.pages:
            add("pages", doc.pages)
        add("created", doc.created)
        add("modified", doc.modified)
        add("subject", doc.subject)
        add("keywords", doc.keywords)
        add("organisation", doc.company, severity=Severity.NOTABLE)

        # The software trail. Rarely identifying on its own and frequently
        # the thing that ties three documents from different sites together.
        for label, value in (("created with", doc.creator),
                             ("written out by", doc.producer)):
            add(label, value)

        for who in doc.people:
            add("named in document properties", who,
                confidence=Confidence.LIKELY, severity=Severity.HIGH,
                extra={"meaning": "the account name saved in the file's "
                                  "properties - a strong lead about who "
                                  "produced it, not proof of authorship"})
            result.entity(EntityType.PERSON, who, relation="document-author",
                          evidence="document-author", url=doc.source,
                          detail="named in the document's own properties")

        for address in doc.entities.get("emails", [])[:25]:
            add("address in document", address, severity=Severity.NOTABLE)
            result.entity(EntityType.EMAIL, address, relation="in-document",
                          evidence="mentioned", url=doc.source,
                          detail="appears in the document text")
        for domain in doc.entities.get("domains", [])[:25]:
            result.entity(EntityType.DOMAIN, domain, relation="in-document",
                          evidence="mentioned", url=doc.source,
                          detail="appears in the document text")
        for handle in doc.entities.get("usernames", [])[:15]:
            add("handle in document", handle, confidence=Confidence.POSSIBLE)
        if urls := doc.entities.get("urls"):
            add("links in document", urls[:30])
        if dois := doc.entities.get("dois"):
            add("DOIs cited", dois[:20], severity=Severity.NOTABLE)

        if doc.company and doc.people:
            result.entity(EntityType.ORG, doc.company, relation="in-document",
                          evidence="mentioned", url=doc.source,
                          detail="the Company property of the document")

        for stage, reason in doc.gaps:
            result.error(f"{stage}: {reason}")
        if doc.gaps and not doc.text:
            result.degrade(ModuleStatus.PARTIAL, doc.gaps[0][1])
