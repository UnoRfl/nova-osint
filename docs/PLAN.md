# NOVA phase 2 — the free-first investigation engine

The plan for turning NOVA from *a scanner with an investigation layer* into a
**free-first, browser-assisted, evidence-driven investigation engine** whose
front door is:

```
nova investigate "John Smith"
nova investigate "John Smith" --image reference.jpg --browser
```

Nothing here is a rewrite. Every item below either reuses an existing
abstraction or sits beside one. The rules in `ARCHITECTURE.md` still hold: the
fetcher is the only socket, modules never call each other, a refusal is never
rendered as an absence, and the core engine imports nothing outside the
standard library.

---

## A. Architecture map (what exists today)

**20,273 lines, 29 modules, 15 CLI commands, 634 offline tests.**

```
cli.py ──► ConfigManager ──► Config ──► Engine
                                          │
   plan()  registry.select(type)          │  two thread pools, never shared
   scan()  modules on the module pool ────┤    nova-module → Module.run()
   investigate()  frontier expansion      │    nova-http   → one request
                                          ▼
                              core/http.py  Fetcher
                     rate limit → single-flight → retry → cache → Response
                                          │
                                          ▼
                     ScanResult.add / .entity / .link / .degrade
                                          │
          ┌───────────────┬───────────────┼────────────────┬──────────────┐
          ▼               ▼               ▼                ▼              ▼
    normalizer.py     graph.py       store.py         identity.py    report.py
    de-duplicate    log-odds edges  SQLite + CAS     brief/verdict   12 formats
                    hub demotion    audit chain
                    widest path     replay
```

| Layer | Files | What it already gives phase 2 |
|---|---|---|
| Acquisition | `core/http.py`, `core/opsec.py`, `core/retry.py` | the only socket, per-host limiting, single-flight, on-disk cache, `AccessStatus` — the vocabulary for *why* a source said nothing |
| Sources | `modules/*.py` (29) | `Module.accepts` / `active` / `requires_key`, `@register`, isolated failures |
| Orchestration | `core/engine.py` | `Budget` (depth/score/entities/runs/seconds), `Expansion` (what was cut and why), frontier walk that rescores after every round |
| Meaning | `core/entities.py`, `core/graph.py` | 20 entity kinds, 48 evidence kinds in log-odds, hub self-demotion, transmittance propagation |
| Memory | `core/store.py`, `core/replay.py` | cases, content-addressed evidence, hash-chained audit, offline re-derivation |
| Judgement | `core/identity.py`, `core/brief.py`, `core/scoring.py`, `core/target_dossier.py` | claims weighted by identifying power, five verdicts, `EvidenceSet` that cannot overwrite |
| Presentation | `core/report.py` + 6 renderers, `gui/` | `status_rows()` already forces coverage gaps into every format |

**The single most important existing asset:** `Engine.investigate()` is already
an adaptive pivot engine. Frontier expansion, information-gain ordering by
widest-path relevance, hub demotion and a four-dimensional budget are done.
Phase 2 does not rebuild it — it *feeds* it more and better leads.

## B. Dependency map

Runtime dependencies: **none**. `rich` and `phonenumbers` are optional and CI
proves the tool runs with both uninstalled. Python ≥ 3.10.

Phase 2 adds no *required* dependency. Every new capability degrades:

| Capability | Preferred | Degrades to | If absent |
|---|---|---|---|
| Browser | `playwright` | `selenium` | a named coverage gap; the operator is given the URL to open by hand |
| OCR | `pytesseract` + local `tesseract` | `tesseract` binary via subprocess | image text marked `NOT CHECKED` |
| Image pixels | `Pillow` | stdlib header parse (size, format) | EXIF + dimensions only, no perceptual hash |
| PDF text | `pypdf` | stdlib zlib stream extraction | metadata only |
| YARA | `yara-python` | local `yara` binary | rules reported as not runnable |

Rule inherited from phase 1: an optional import failure is a *coverage gap*,
never a traceback, and never a silent empty result.

## C. Provider map (today)

| Class | Sources | Key |
|---|---|---|
| Keyless HTTP API | RDAP, DoH, crt.sh, CertSpotter, InternetDB, Wayback, Gravatar, GitHub (anon), Keybase, WebFinger, npm/PyPI, Bluesky, Wikidata, HIBP `/breaches` | — |
| Optional key | GitHub (60/hr → 5,000/hr) | free |
| Required key | VirusTotal, AbuseIPDB, HIBP `/pwned` | free tier / paid |
| Required key, paid | SecurityTrails | **$500/mo — no free tier** |
| Declared, unread | shodan, hunter, numverify, emailrep | — |
| Built, never run | `dorks` — generates search URLs and hands them to the analyst | — |

**The gap that defines this phase:** NOVA generates 40 search queries and runs
none of them. Everything downstream — candidates, pivots, documents, images —
is starved because the largest free corpus on the internet is addressed only
by printing links.

## D. Free-source gaps to close

1. **Search is never executed.** No SERP text ever becomes evidence.
2. **No browser.** Anything behind JavaScript or without an API is invisible.
3. **Name → nothing.** `PERSON` targets reach two modules (wikidata, bluesky).
4. **No documents.** PDFs and DOCX files are found as URLs and never read.
5. **No images.** No EXIF, no OCR, no hashing, no image-derived queries.
6. **Thin code-host coverage.** GitHub only; no GitLab, Codeberg, Bitbucket,
   Stack Overflow, Docker Hub.
7. **No scholarly or public-record sources.** OpenAlex, Crossref, ORCID are
   free, documented, and absent.
8. **No temporal model.** Observations have no `observed_at`, so nothing can be
   marked stale or historical.
9. **No provider health.** A rate-limited source is rediscovered on every run.
10. **No acquisition provenance.** A finding says which *module* produced it,
    never which *method* obtained it.

## E. Browser-automation architecture

```
BrowserProvider (ABC, core/browser.py)
  open() search() navigate() extract() capture() close()
        │
        ├── PlaywrightBrowser    preferred; channel=chrome|msedge|chromium
        ├── SeleniumBrowser      compatibility
        └── NullBrowser          always present; every call returns
                                 UNAVAILABLE with the URL to open by hand
```

* **Optional at import time.** `core/browser.py` imports nothing heavy at
  module scope; the engine starts without Playwright installed.
* **Temporary profile by default.** A named profile is opt-in
  (`nova browser setup`), and NOVA never reads cookies, passwords, tokens or
  history out of it.
* **Human-action state is first class.** A login wall, a consent interstitial
  or a CAPTCHA returns `HUMAN_ACTION_REQUIRED` — a new `AccessStatus` member
  that flows into the existing coverage-gap machinery. NOVA never solves,
  never retries past it, never swaps identity.
* **Every page becomes evidence**: visible text, canonical URL, redirect
  chain, HTTP status, screenshot and (when permitted) HTML, all hashed into
  the existing content-addressed store so `nova replay` still works.
* **Honest identity preserved.** The browser reports itself as a browser; the
  report says `method=browser` and never claims an API answered.

## F. Data-model changes (all additive)

| Change | Where | Compatibility |
|---|---|---|
| `Acquisition` record (method, provider, url, query, status, `obtained_at`, evidence hash, source type) | new `core/acquisition.py` | new file |
| `Finding.acquisition: Acquisition \| None = None` | `core/models.py` | defaulted field; every existing constructor unchanged |
| `Finding.observed_at`, `.first_seen`, `.last_seen` | `core/models.py` | defaulted |
| `AccessStatus.HUMAN_ACTION_REQUIRED`, `.PAYMENT_REQUIRED` | `core/http.py` | new enum members; `is_refusal` covers them |
| `Availability`, `Health`, `ProviderInfo` | new `core/providers.py` | new file |
| `SearchResult`, independence clustering | new `core/search.py` | new file |
| `EntityType.DOCUMENT`, `.IMAGE`, `.REPO`, `.PUBLICATION`, `.ACCOUNT` | `core/entities.py` | additive enum members |
| evidence kinds: `search-result`, `document-author`, `exif-owner`, `ocr-text`, `image-hash-match`, … | `core/graph.py` `EVIDENCE` | additive dict entries |
| `cases.acquisitions`, `observations.observed_at` | `core/store.py` | schema v4 + migration, existing rows keep working |

Nothing is removed. Nothing changes meaning. `SCHEMA_VERSION` 3 → 4 with a
forward migration, following the two that already exist.

## G. New modules

| File | Responsibility |
|---|---|
| `core/acquisition.py` | the provenance record every finding can carry |
| `core/providers.py` | `Availability`, `Health`, `ProviderInfo`, `ProviderHealth` manager, provider registry |
| `core/router.py` | `SourceRouter` — the free-first fallback ladder, and the record of which rung answered |
| `core/search.py` | `SearchResult`, engine adapters, dedupe + independence clustering |
| `core/queryplan.py` | `QueryPlanner` — name variants, category queries, value-ordered |
| `core/browser.py` | `BrowserProvider` ABC + Playwright/Selenium/Null adapters |
| `core/investigate.py` | the orchestration `nova investigate` drives, and the live tree |
| `core/docparse.py` | PDF/DOCX/HTML/CSV/JSON/XML text + metadata extraction |
| `core/imageint.py` | EXIF, dimensions, perceptual hash, OCR, image→query clues |
| `core/timeline.py` | observation timeline, staleness, contradiction by time |
| `core/feeds.py` | pluggable public dataset / IOC feed ingestion |
| `core/localaudit.py` | read-only local posture inspection |
| `core/remediate.py` | defensive recommendations derived from actual findings |
| `modules/websearch.py` | the module that turns planned queries into evidence |
| `modules/codehosts.py` | GitLab, Codeberg, Bitbucket, Stack Overflow, Docker Hub |
| `modules/scholar.py` | OpenAlex, Crossref, ORCID |
| `modules/documents.py` | fetch + parse discovered documents |
| `modules/images.py` | image intelligence as a module |
| `modules/ioc.py` | IOC matching against configured feeds |

## H. Modified modules

| File | Change | Risk |
|---|---|---|
| `core/http.py` | two new `AccessStatus` members; `Response.method` tag | low |
| `core/models.py` | additive fields on `Finding`; `ScanResult.add(acquisition=)` | low |
| `core/engine.py` | `_ModuleHttp` stamps the acquisition; router + browser passed through | medium — the ledger and passive guard both live here |
| `core/registry.py` | one import line per new module; `PERSON` reaches more modules | low |
| `core/report.py` | **Source Availability** section in every renderer; acquisition shown per finding | medium — 6 renderers |
| `core/store.py` | schema v4, acquisitions persisted, replay keyed on them | medium — migration |
| `core/identity.py` | independence groups feed corroboration; syndicated copies stop counting twice | medium — this is the false-positive core |
| `cli.py` | `investigate`, `browser`, `local-audit`, `local-scan`, `feeds`, `sources` | low |
| `gui/console.py` | new tabs | low |
| `modules/dorks.py` | keeps generating; now also *offers* its queries to the planner | low |

## I. Migration strategy

Nine phases, each independently shippable, each its own commit, each ending
with the **full** suite green.

| Phase | Ships | Depends on |
|---|---|---|
| **1. Provenance spine** | `acquisition.py`, `providers.py`, `router.py`, new `AccessStatus` members, Source Availability in reports | — |
| **2. Search** | `search.py`, engine adapters, `modules/websearch.py` | 1 |
| **3. Query planning** | `queryplan.py`, name expansion, category queries, value ordering | 2 |
| **4. `nova investigate`** | `investigate.py`, the command, the live tree | 1–3 |
| **5. Browser** | `browser.py`, adapters, `nova browser setup`, `--browser` | 1, 2 |
| **6. Documents** | `docparse.py`, `modules/documents.py` | 1 |
| **7. Images** | `imageint.py`, `modules/images.py`, image→query pipeline | 1, 3 |
| **8. Time + correlation** | `timeline.py`, independence groups, false-positive suppression | 1–4 |
| **9. Local + defensive** | `localaudit.py`, `remediate.py`, `feeds.py`, `modules/ioc.py` | 1 |

Then reports and GUI absorb everything (phase 10), because a surface that
renders a half-built model is a surface that has to be rebuilt.

**Rollback:** every phase is additive and behind a flag or a new command. The
existing `nova scan` path is not modified in phases 2–9; it *gains* sources.

## J. Test strategy

Offline, always. No phase may add a test that needs the network.

| Area | How it is tested without a socket |
|---|---|
| Router fallback | fake steps that fail in a chosen order; assert the ladder, the recorded attempts, and that exhaustion yields UNAVAILABLE rather than an exception |
| Paid-provider disabling | a provider marked PAID is never attempted unless explicitly enabled; assert the report says PAID, not "no result" |
| Provider health | rate-limit one provider, assert it is skipped for the backoff window and that the investigation continues |
| Search adapters | saved fixture payloads parsed by `parse()` classmethods; no fetcher involved |
| Result normalisation | syndicated copies of one article cluster to one independence group and corroborate once |
| Name expansion | table-driven: "John Smith" → ordered variants, no duplicates, no invented middle names |
| Query generation | assert planner output is ordered by estimated value and bounded |
| Browser | `NullBrowser` plus a `FakeBrowser` double; assert CAPTCHA → `HUMAN_ACTION_REQUIRED`, never a retry |
| CAPTCHA detection | fixture pages; assert detection and that no circumvention path exists |
| OCR / EXIF / phash | tiny generated PNG/JPEG fixtures; assert graceful skip when Pillow absent |
| Documents | fixture PDF/DOCX bytes built in the test |
| Entity resolution | **synthetic ambiguous identity fixtures**: two real people sharing a name, overlapping city, different employer — assert they are never merged and both survive as candidates |
| Temporal | observations across years; assert stale vs current classification |
| Redaction | assert acquisition URLs and browser artefacts are redacted too |
| Replay | a case containing browser and search acquisitions replays to the same graph |

Two standing invariants become tests in phase 1 and are asserted in every
phase after it:

1. **No renderer may show a finding without its acquisition method**, so a
   browser result can never be mistaken for an API result.
2. **`CANNOT ACCESS` never renders as `NO RESULT`** — already true for modules,
   extended to providers, engines and browser steps.
