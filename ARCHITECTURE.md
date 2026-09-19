# Architecture

How NOVA is put together, what each file is responsible for, and where to add
things. Read this before changing anything in `core/`.

---

## The shape of a scan

```
        nova scan example.com
                 │
                 ▼
  cli.py ── builds the Config ──────────────────► core/config.py
    │        (flag > env > config.json > default)   ConfigManager
    │
    ▼
  core/engine.py  Engine.plan()  ──► core/registry.py   which modules accept
    │                                                   a "domain", which are
    │                                                   skipped and why
    │
    ├─ Engine.scan() runs each module on the MODULE pool
    │     │
    │     ├─ modules/domain.py  WhoisModule.run(target, result)
    │     ├─ modules/domain.py  DnsModule.run(...)         each one fans out on
    │     ├─ modules/web.py     HeadersModule.run(...)     the HTTP pool via
    │     └─ modules/dorks.py   DorksModule.run(...)       self.http.map(...)
    │                                    │
    │                                    ▼
    │                         core/http.py  Fetcher
    │                         rate limit → retry → cache → Response
    │
    ├─ core/normalizer.py cleans and de-duplicates each ScanResult
    ├─ engine records a ModuleStatus (success / rate limited / blocked / ...)
    │
    ▼
  Investigation ──► core/report.py ──► console | json | csv | markdown | html
```

Two thread pools, on purpose. See **Threading** below.

---

## The tree

```
nova-osint/
├── launcher.py              PyInstaller entry point (see the table below)
├── pyproject.toml           packaging, console scripts, ruff and pytest config
├── NOVA.spec / NOVA.bat     frozen Windows build
│
├── nova_osint/
│   ├── __init__.py          public API: Config, Engine, models, __version__
│   ├── __main__.py          python -m nova_osint
│   ├── cli.py               argument parsing, precedence, progress, exit codes
│   │
│   ├── core/
│   │   ├── config.py        Config + ConfigManager (config.json, env, validation)
│   │   ├── logging_config.py logging + SecretRedactingFilter
│   │   ├── retry.py         RetryPolicy, Retry-After parsing
│   │   ├── http.py          Fetcher, Response, AccessStatus  (the only socket)
│   │   ├── models.py        Finding, Pivot, ScanResult, Investigation, enums
│   │   ├── normalizer.py    DataNormalizer: clean, canonicalise, de-duplicate
│   │   ├── registry.py      Module base class, @register, detect_type
│   │   ├── engine.py        runs modules, isolates failures, assigns status
│   │   ├── report.py        console / json / csv / markdown / html renderers
│   │   ├── dns.py           DNS-over-HTTPS helper
│   │   └── art.py           banners, spinner, per-module glyphs
│   │
│   ├── modules/             one file per source family - see the table below
│   ├── gui/                 Tkinter desktop app (boot, console, settings, theme)
│   └── data/                bundled site catalogue and disposable-mail list
│
├── tests/
│   ├── test_core.py         detection, registry, renderers, module helpers
│   ├── test_pipeline.py     config, retry, normaliser, status, logging
│   ├── test_sources.py      VirusTotal and SecurityTrails parsers, key wiring
│   └── test_gui.py          desktop app and settings window
│
├── output/                  default destination for reports (git-ignored)
├── ARCHITECTURE.md          this file
├── ETHICS.md                what this tool will and will not do
└── README.md
```

## File by file

### Entry points

| File | Responsibility |
|---|---|
| `nova_osint/__main__.py` | `python -m nova_osint` → `cli.main()` |
| `nova_osint/cli.py` | Argument parsing, precedence, progress line, exit codes. Contains no OSINT logic. |
| `launcher.py` | PyInstaller entry point for the frozen desktop app. **Never** point PyInstaller at `gui/__main__.py` — the bootloader runs the entry file top-level and a relative import dies before the window exists. |

### `core/` — the engine

| File | Responsibility |
|---|---|
| `config.py` | `Config` (the resolved settings one scan runs with) and `ConfigManager` (reads, validates and writes `config.json`). Also `load_env_file`. The only place that touches the environment or the filesystem for settings. |
| `logging_config.py` | `setup_logging`, `get_logger`, and `SecretRedactingFilter`, which scrubs API keys out of every log line before it is written. |
| `retry.py` | `RetryPolicy` — what is worth retrying and how long to wait. Pure and side-effect free, so it can be tested without a socket. Parses `Retry-After` in both its formats. |
| `http.py` | `Fetcher`: the *only* thing in the project that opens a socket. Per-host rate limiting, bounded concurrency, on-disk cache, retries, and `AccessStatus` — the vocabulary for "the source refused". |
| `models.py` | `Finding`, `Pivot`, `ScanResult`, `Investigation`, and the `Confidence` / `Severity` / `ModuleStatus` enums. Pure data; no behaviour beyond serialisation. |
| `normalizer.py` | `DataNormalizer`: cleans strings, canonicalises URLs, drops empty and duplicate findings. Runs on every result; **never** invents or upgrades a value. |
| `registry.py` | The `Module` base class, the `@register` decorator, and `detect_type()`. Adding a source touches this file once (an import) and nothing else. |
| `engine.py` | Runs the modules, isolates their failures, records their status, applies the normaliser. |
| `report.py` | Every renderer. Takes an `Investigation`, returns a string. |
| `dns.py` | DNS-over-HTTPS helper shared by several modules. Not a module itself. |
| `art.py` | The banners, spinner and per-module glyphs. |

### `modules/` — the sources

Each file holds one or more `Module` subclasses. They are independent: nothing
in `modules/` imports anything else in `modules/`.

| File | Modules it registers |
|---|---|
| `domain.py` | `whois` (RDAP), `dns`, `mailsec` (SPF/DMARC/DKIM/BIMI), `subdomains` (CT + passive DNS) |
| `web.py` | `headers`, `exposed` (robots/security.txt/sitemaps), `wayback` |
| `username.py` | `username` (Sherlock-schema site sweep with control-handle verification) |
| `github.py` | `github`, `gists` |
| `email.py` | `email` (structure, deliverability, Gravatar, GitHub) |
| `ip.py` | `ip` (geo/ASN/PTR/InternetDB/RDAP), `abuseipdb` |
| `phone.py` | `phone` (libphonenumber when installed, country-code fallback when not) |
| `breach.py` | `breaches` (domain-level, keyless), `pwned` (per-address, needs a key) |
| `virustotal.py` | `virustotal` (reputation, categories, passive DNS) |
| `securitytrails.py` | `securitytrails` (DNS history, pre-privacy WHOIS) |
| `dorks.py` | `dorks` — builds search URLs, never runs them |
| `declared.py` | `declared` — accounts, owner, occupation and business type from the site's own structured data |

> `declared` is the only route into the platforms that refuse anonymous
> lookups. Facebook, Instagram, Threads and LinkedIn cannot be tested by any
> username catalogue — and they are exactly the platforms a business
> advertises, in a `schema.org` block put there for search engines. `sameAs`
> means "these accounts are also me"; `founder`, `jobTitle` and `worksFor`
> answer what someone does and whether they own the company, and they land as
> `<name>: occupation` / `<name>: employer` findings, which is the shape
> `biography.ATTRIBUTES` already reads. Several accounts per platform survive:
> a business has a page *and* a profile. `core/structured.py` is the parser —
> pure, stdlib, no socket — and it also reads Open Graph, microdata, `rel="me"`
> and plain links, because most small sites publish none of the first three.

### `gui/` — the desktop app

`boot.py` (animated init, waits for Enter), `console.py` (the main window),
`settings.py` (the config editor), `orbit.py` and `theme.py` (drawing),
`app.py` (wiring). The GUI drives the same `Engine` the CLI does and reads the
same `config.json` through `runtime_config()`; it has no OSINT logic of its own.

The settings window writes through `ConfigManager`, never straight to the file,
so the GUI and the CLI cannot drift apart. Two rules it enforces: a stored key
is shown as a placeholder and never rendered back, and a key present in the
environment disables its field, because a file value could not override it.

---

## How modules communicate

They do not. That is the design.

A module receives a target string and a fresh `ScanResult`, and writes into it:

```python
result.add(label, value, source=..., confidence=..., severity=..., url=...)
result.pivot(new_target, TargetType.IP, "why")
result.error("what went wrong")
result.degrade(ModuleStatus.PARTIAL, "one source was down")
```

Everything a module wants to say to the rest of the system goes through that
object. Two consequences worth keeping:

* **Modules never call each other.** If `email` wants DNS, it uses the shared
  `core/dns.py` helper, not `DnsModule`. A module that imported another module
  would break the "delete one file, lose one source" property.
* **Modules never print, log a finding, or write a file.** The engine collects,
  the renderer formats. A module that printed would corrupt `--format json`.

Cross-module discovery happens through **pivots**: the `dns` module emits the
IP it resolved, and `--pivot` feeds that to the `ip` module as a fresh scan.
That is the only path from one source's output to another's input, and it is
explicit and visible in the report.

---

## How configuration works

Four layers, highest priority first:

```
1. command-line flag      --timeout 30
2. environment variable   GITHUB_TOKEN=...          (secrets only)
3. config.json            {"settings": {"timeout": 20}}
4. built-in default       DEFAULT_CONFIG in core/config.py
```

The mechanism is simple: every network flag in `cli.py` defaults to `None`,
meaning "the user did not say". `ConfigManager.to_config(**flags)` drops the
`None`s, so a flag only wins when it is actually given.

`config.json` lives at `~/.config/nova-osint/config.json` (`nova config path`
prints it, `nova config show` prints it with the keys masked) and is created
with defaults on first run. `--config other.json` points at a different one.

`ConfigManager` is written so that **no configuration mistake can stop a scan**:

| What you wrote | What happens |
|---|---|
| file does not exist | created with defaults |
| file is not valid JSON | warning, defaults used, scan continues |
| `"timeout": "banana"` | warning, default used |
| `"max_concurrent_tasks": 9999` | clamped to 128, warning |
| `request_delay_max` below `request_delay_min` | both set to the min, warning |
| `"api_keys": {"nonsense": "x"}` | reported as unknown, ignored |
| `"api_keys": {"haveibeenpwned": "x"}` | accepted — long-form names are aliased |
| `"proxies": {"socks5": ...}` | refused loudly (stdlib HTTP cannot do SOCKS) |
| `"module_options": {...}` | passed through to `config.option(name)` for any module |
| a key present and the file world-readable | warning telling you to `chmod 600` |

### Secrets

Keys are read from the environment by default (`.env.example` lists them). They
may also live in the `api_keys` block of `config.json`, in which case the file
is written `0600` where the OS supports it and the environment still wins.

Keys never leave the process except as a request header:

* `nova config show` masks them (`"set (hidden)"`).
* `SecretRedactingFilter` scrubs them from every log line, plus anything that
  *looks* like a secret (`?apikey=`, `Authorization: Bearer ...`).
* Reports contain findings only — no configuration is serialised into them.
* Responses to authenticated requests are **never** written to the disk cache.

---

## Threading

Two pools, and the rule that keeps them honest:

```
module pool  (engine.py, "nova-module" threads)  runs Module.run()
http pool    (http.py,   "nova-http"   threads)  runs individual requests
```

**The outer pool never does network work itself.** Sharing one pool deadlocks:
a module occupies a worker while waiting for requests that themselves need a
free worker, so at `--concurrency 8` with nine modules nothing can ever
progress. `Fetcher.map` additionally notices when it is called from a
`nova-http` thread and runs those items inline rather than submitting them, so
re-introducing the bug by accident is not possible.

Rate limiting is per host and shared across both pools, so twenty modules
hitting `crt.sh` still queue behind one another.

---

## The investigation layer

Everything above describes one scan. These four files turn a sequence of scans
into an investigation, and they are the part worth understanding first.

### `core/entities.py` — what things *are*

A finding is a statement; an entity is a thing that can be looked up again,
pivoted from, and compared across cases. Twenty-odd typed kinds — domain, host,
ip, asn, email, username, cert, spki, key, tracker, favicon — each with one
canonical spelling, so a name from a certificate log and the same name from DNS
become one node rather than two.

Three rules that are easy to get wrong:

- **Canonicalising never loses the original.** A hostname that arrived with a
  trailing dot came from DNS; an email that arrived tagged tells you how the
  address was handed out. `Entity.raw` keeps it.
- **Confusables are a finding, not a normalisation.** `exampIe.com` with a
  capital I is *not* `example.com`. It gets its own node and a `looks-like`
  edge, because noticing it is the entire point.
- **Hex folds, base64 does not.** An OpenSSH fingerprint is base64 and
  case-significant; casefolding one would merge two unrelated identities and
  claim somebody holds both keys.

### `core/graph.py` — how strongly things connect

Edges carry a log-likelihood ratio, not a label. Independent evidence adds,
disconfirming evidence subtracts, and repeated observations *of the same kind*
are discounted geometrically — crt.sh and CertSpotter reading the same CT log is
one fact told twice.

`EVIDENCE` is the single table of what each kind of observation is worth. It
exists so the numbers can be argued with in one place instead of being scattered
through fifteen modules as magic `confidence=LIKELY` calls.

Two mechanisms keep transitive expansion from swallowing the internet:
`effective_llr` divides an edge by the log of the busier endpoint's degree, so
hubs demote themselves; and `rescore` is a widest-path search — a node's
relevance is the strongest chain of belief back to the seed, not the shortest
hop count.

> The subtle bug, recorded so nobody reintroduces it: what propagates along an
> edge is **transmittance**, not probability. A no-evidence edge sits at p≈0.5,
> so propagating probability hands half the parent's relevance through a link we
> have no reason to believe — and a one-hop guess then outranks a three-hop
> cryptographic proof.

#### Four rules about what counts as evidence

Each was measured on the live code before it was written down, and each has a
test in `tests/test_evidence_quality.py` naming the number the old code gave.

**An observation is discounted for its source as well as its kind.**
`Edge.weights` halves an observation once per stronger observation sharing its
kind, and again per stronger observation sharing its `independence` — which
defaults to *module plus the host it read*. A tracker id, a favicon hash and a
page-structure hash pulled out of one fetch by one module used to sum to 9.5
nats and grade **A1**: "practically certain, three independent sources", off a
single HTTP response. `corroborations` counts sources now, not kinds, because
that is what the Admiralty digit says it means. Two modules known to read one
upstream pass an explicit `group=` and count once.

**Converging routes corroborate.** A widest path keeps a node's best chain and
throws the rest away, so an account found *both* through the registrant's
address *and* through a pushed commit scored exactly what it would have scored
on either alone — 0.2412 either way, and the frontier could not tell them
apart. `_corroborate` combines independent routes as a noisy-OR, capped at
three routes and at 1.0, degrading to the old maximum when there is one route.

**Evidence that makes a present-tense claim expires.** `HALF_LIFE` ages a kind
of observation, and the distinction is not how old the record is but what the
record *claims*: an A record says where a name points **now**, a certificate
says something that happened, and a thing that happened stays happened. Passive
DNS has a 90-day half-life; `cert-san` has none. Decay applies to positive
strength only — a denial recorded in 2019 is still a denial. The graph stays
clock-free: a module stamps `observed_at`, the engine stamps `recorded_at`, and
a case reopened next year rebuilds to identical scores.

**A lead that was ruled out is not a lead.** The search skips non-positive
edges, which is right for routing and was wrong for judgement — disconfirming
evidence had no effect at all on a node some other edge had already reached, so
a handle carrying an explicit `-4.0` denial sat in the frontier on the strength
of an unverified `+0.4` elsewhere. `_contradict` records `support` and `against`
on every node, `frontier` skips the losers, and `Expansion.ruled_out` names them
with the objection — kept apart from `below_floor`, because "we checked and it
is not him" and "nobody said much either way" are different results.

### `core/assist.py` — the optional local model, and the fence around it

Off by default. Free, local, and governed by one rule:

> **It produces questions and hypotheses. It never produces findings.**

Nothing it says reaches the evidence graph — not as a weak edge, not as a
`pivot-derived` node, not as a low-confidence finding. The graph is for things
a source said, and a model has no sources. What it is good at is the thing the
query planner does badly: looking at forty entities and a half-finished picture
and noticing what nobody has asked.

Three guards, because "never produces findings" has to be enforced rather than
promised:

**A hypothesis must cite evidence that exists.** Every hypothesis names the
entity ids it rests on, and any id the graph has never heard of discards the
whole hypothesis — a model that invents a connection almost always invents the
node it hangs off. The count of what was thrown away is reported, in the
console *and* in the JSON, because a consumer shown the questions but not the
discards has been told the flattering half.

**A question is a question.** Surviving questions go through the same
`SearchService` as every other query, as `Category.GENERAL` via
`QueryPlanner.free_text` — the weakest category there is. A suggestion that
turns out to be right is evidenced by the page that confirmed it, never by
having been suggested. Operators in the text are detected rather than trusted,
so an engine without `site:` gets the degraded form.

**It runs on your machine or it does not run.** Loopback and RFC1918 pass; a
public endpoint is refused before a socket opens, and the refusal says that
enabling it discloses the investigation and may cost money.

Providers: Ollama (`/api/chat`) and anything OpenAI-compatible
(`/v1/chat/completions`) — llama.cpp's server, LM Studio, vLLM. Absent one, the
`assist` stage is a named coverage gap like any other, exactly as it is without
`playwright`. `nova assist status` says which, and `nova assist test` proves the
round trip.

### `core/calibration.py` — measuring the evidence table instead of asserting it

`EVIDENCE` says a shared tracker id is worth 5.0 nats and a matching handle
0.4, and `graph.py`'s own docstring admits those are "judgements, not
measurements". Every number downstream inherits that — the Admiralty grade, the
frontier ordering, the word *probable* in the report. A tool that publishes
probabilities it has never scored is asserting calibration, which is the one
thing this project exists not to do.

`nova calibrate` closes the loop. Given links somebody adjudicated it reports
the **Brier score** and the skill against guessing the base rate, **reliability
bin by bin** (of the links called 90% likely, how many were real), **AUC** — kept
separate on purpose, because a tool can be perfectly calibrated and useless, or
sharply discriminating and badly scaled, and only the second is fixable by
editing a table — and **a suggested weight per evidence kind**.

The fit is a logistic regression with one feature per kind and **no intercept**,
which is not a modelling choice so much as an identity: the graph already
assumes log-odds add across independent evidence, and that assumption *is* the
logistic model, so the fitted coefficients are the table's own units. The
harness measures the real `Edge` — independence discount, temporal decay, hub
demotion and all — rather than a copy of it. No intercept because a free one
would let a lopsided corpus's base rate leak into every kind.

Two deliberate conservatisms, and one thing it never does:

- **It regularises toward the current table**, not toward zero. Forty cases
  should nudge a number the authors reasoned about, not overturn it.
- **It refuses to recommend on thin evidence** — fewer than `MIN_CASES`, or
  perfect separation, gets no suggestion and says why.
- **It never writes `EVIDENCE`.** It prints a diff.

`nova calibrate selftest` measures the measuring instrument: cases generated
*from* the table must read as calibrated, and cases generated from a table
inflated 2.2× must read as over-confident. A harness with a sign error, a
double-counted discount or a broken hub divisor fails it.

> Recorded because it was hit: the ridge term's own gradient is
> `lam * (coef - prior)`, so a fixed step size diverges once `rate * lam`
> nears 2 — which a strong prior on a small corpus reaches easily, and which
> produced NaN weights instead of the conservative answer the prior existed to
> give. The step is scaled by the curvature, and a diverged fit returns the
> table unchanged rather than printing garbage as a measurement.

> And: an all-true corpus makes the base-rate baseline perfect by construction,
> so skill reads `+0.000` — which the first version rendered as "WORSE THAN
> GUESSING". It is not; there is nothing to be better than. `Report.one_sided`
> says so instead, and tells the adjudicator to record some links that went the
> other way.

### `core/store.py` — what was found, and proof of it

SQLite for cases, entities, edges, observations, findings, per-module status and
every request made. A content-addressed evidence store for the raw response
bodies. A hash-chained audit log.

`finding_id` deliberately excludes the value, which is what lets two scans a
week apart agree that "mail exchangers" is the same finding so a change reads as
a change.

### `core/replay.py` — re-deriving a case offline

Feeds each module its own recorded bytes with the network hard-disabled.
`ReplayFetcher` deliberately does **not** subclass `Fetcher`: inheriting would
make one forgotten override a live socket.

### `core/opsec.py` — behaviour on the wire

`SingleFlight` coalesces identical concurrent requests. `budget_key` keys rate
limiting on the operator rather than the hostname, because api.github.com and
raw.githubusercontent.com are one rate limit. `PassiveGuard` blocks a passive
module from reaching the target's registrable domain at all.

### `modules/correlators.py` — links without shared metadata

Each correlator extracts a fingerprint, emits it as an entity, and lets the
graph do the linking. No code anywhere compares one target to another: a
pairwise check is quadratic and only finds what it was told to look for, while a
shared node is linear and works across the entire case history.

## Writing a module that feeds the graph

`result.add(...)` still reports a fact. To make it *connect*, also say what kind
of thing it is and what kind of evidence you have:

```python
result.entity(
    EntityType.EMAIL, address,
    relation="contact",            # what to call the edge
    evidence="rdap-contact",       # a key in graph.EVIDENCE
    url=source_url,                # where it came from
    detail="RDAP registrant contact",
)
```

The engine turns that into a weighted edge, so a module never has to know about
log-odds or hub demotion — it says what it saw and the scoring layer decides what
that is worth. Modules still calling `result.pivot()` keep working; their pivots
become nodes on a deliberately weaker `pivot-derived` edge, so migrating is
rewarded rather than required.

Two rules worth stating outright:

1. **Only claim what you can attribute.** If a source hands you addresses from
   several people, emit the target's own with real evidence and the rest as
   contributors at `mentioned`. A co-contributor's address asserted as the
   target's is a false identity in a report, and it is the single easiest
   mistake to make here.
2. **Declare `active = True` if you touch the target's own infrastructure.** The
   passive guard will stop you anyway, but it will stop you by reporting a
   coverage gap, which is a worse outcome than the flag being right.

## Adding a new OSINT module

Two steps, no central switchboard to edit beyond one import.

**1. Write the class** in `nova_osint/modules/mysource.py`:

```python
"""One paragraph: what this source is, and why it is worth querying."""

from __future__ import annotations

from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register


@register
class MySourceModule(Module):
    name = "mysource"                       # what --only takes
    title = "My source"
    description = "Shown by `nova modules`."
    accepts = frozenset({TargetType.DOMAIN})
    active = False          # True if it sends traffic to the target's own servers
    requires_key = None     # or "shodan" - the module is skipped without it
    slow = False

    def run(self, target: str, result: ScanResult) -> None:
        resp = self.http.get(f"https://api.example.com/lookup?q={target}")

        # The fetcher never raises, so check the answer rather than catching.
        if resp.access.is_refusal:
            result.degrade(ModuleStatus.UNAVAILABLE, resp.describe())
            result.error(f"api.example.com: {resp.describe()}")
            return

        data = resp.json()
        if not isinstance(data, dict):
            return                          # nothing found is not an error

        result.add(
            "organisation",
            data["org"],
            source="mysource",
            confidence=Confidence.CONFIRMED,   # only if the source is authoritative
            severity=Severity.NOTABLE,
            url=data.get("link"),
        )
        if ip := data.get("ip"):
            result.pivot(ip, TargetType.IP, "resolved by mysource")
```

**2. Import it** in `core/registry.py`'s `import_modules()`. That is the whole
registration step; the `@register` decorator does the rest.

**3. Add a test** in `tests/` that does not touch the network — parse a saved
payload, or assert the module declares itself correctly. `test_core.py` already
asserts every registered module has a name, a description and an `accepts` set,
so a malformed module fails the suite immediately.

### Rules a module must follow

* **Never raise on purpose.** Put the problem in `result.error(...)` and, if it
  changes what the result means, `result.degrade(...)`. The engine will catch a
  genuine bug, but a caught bug costs you that module's whole output.
* **Do not invent confidence.** `CONFIRMED` means an authoritative source said
  so. A 200 from a profile page is `LIKELY`. A guess is `POSSIBLE`.
* **Mark yourself `active = True`** if you touch infrastructure the target
  controls. `--passive` disables active modules outright — it is a gate, not a
  volume knob, and mislabelling a module breaks a promise the tool makes.
* **Never work around a refusal.** If a source answers 403, 429 or a CAPTCHA
  page, record it and stop. No retry loops past the policy, no alternate
  identities, no fingerprint spoofing.
* **Do not retrieve credentials.** Breach modules report *that* an address
  appears in an incident and what classes of data it held — never passwords,
  tokens or session material.

---

## The dossier layer

`report` groups output by module, `profile` groups it by entity kind, and
`biography` groups it by attribute label. All three are the right shape for
checking the tool's work and the wrong shape for reading it: none of them
answers "so what do you know about this person" in one place.

`core/target_dossier.py` does, via `generate_target_dossier(inv)`. It is a pure
read over a finished `Investigation` - no network, so it re-runs identically
over a stored case or a replayed one - and it returns one `Dossier` with the
shape `identity` / `background` / `digital_footprint` / `confidence`.

Rendered with `-f dossier` (Markdown) or `-f dossier-json`, and shown in the
desktop app's **Dossier** tab, which is built from the same function so the two
surfaces cannot drift apart.

### The evidence model

`core/scoring.py` is the part that makes the dossier honest, and it is
deliberately free of any import from the rest of the package.

Every field is an `EvidenceSet` rather than a value. There is no API on it that
replaces anything: `add` can only merge or append, so "never silently
overwrite" is structural rather than a rule each caller has to remember.

- **Merging keeps provenance.** Two sources asserting one value become one
  record naming both, and the score gains a capped corroboration bonus. That
  bonus can never reach 1.0, because a value must not become certain by
  repetition.
- **Competing values are ranked, not resolved.** Two dates of birth from two
  sources produce two rows and a `disputed` flag. The renderers print both and
  say nothing has been chosen.
- **A multi-valued field never reports a conflict.** A second phone number is
  ordinary. Only single-valued fields can contradict.
- **`SOURCE_WEIGHTS` is the single place** that decides what a class of source
  is worth, so every number in a dossier traces to one reviewable line.
- **Synthetic values never earn corroboration** and are carried through every
  layer still marked synthetic; the Markdown renderer refuses to print a
  dossier containing one without a banner.

### Two things it will not do

**It will not invent a role-to-employer pairing.** A source that carried both
("Systems Administrator at Acme") is split and paired. One company and one role
are paired because there is no other candidate pairing to be wrong about.
Three companies and two roles are left unpaired with `role_paired=False`, and
the report says so. Zipping the two lists manufactures plausible, checkable,
wrong sentences - the worst failure mode this tool has.

**It will not read credentials.** `modules/exposure_parser.py` extracts the
biographical metadata around an exposure record through two independent gates:
an allowlist of fields, so an unrecognised `ntlm_hash:` column is refused by
default rather than by having been anticipated, and a value-shape guard, so a
credential hiding inside a permitted field is dropped anyway. Credential
columns are *named* in the output and never read, because a reader who knows a
dump had a password column can reason about it; one shown a thinner record
silently cannot.

### Scoring a guess as a guess

`biography.Value` carries `origin` - the finding's own `source` - alongside
`source`, which is the *module*. The two differ in exactly the case that
matters: the email module reports both a parsed domain and a name guessed from
the local part, and attributing the guess to "email" loses the one word that
said it was a guess. Read `Value.basis` when weighting, never `Value.source`.

## Adding a new output format

Write `render_myformat(inv: Investigation) -> str` in `core/report.py` and add
it to the `RENDERERS` dict. It is picked up by `--format` and by
`report.write()`'s suffix inference automatically.

Whatever you render, include `status_rows(inv)`. A report that lists findings
without saying which instruments failed presents "we could not look" as
"there was nothing there", which is the one error this tool must not make.

---

## The free-first acquisition layer

Everything above describes *what* NOVA asks. This describes **how it decides
where to ask, and what it records about having asked**. Read `docs/PLAN.md`
for the phase map; this is the part that has landed.

```
   a need: "the subject's public repositories"
                    │
                    ▼
        core/router.py  SourceRouter.acquire()
                    │
     local → cache → store → API → page → search → browser
       │       │       │      │      │       │        │
       └───────┴───────┴──────┴──────┴───────┴────────┘
                    │  first rung that answers wins
                    ▼
        Outcome(value, Acquisition, [Attempt, ...])
                    │
   every attempt recorded, including the ones skipped and why
```

### `core/acquisition.py` — how a fact was obtained

`Finding.source` says which module produced a value. `Finding.acquisition`
says how it was fetched: method, provider, URL, query, HTTP status, timestamp
and evidence hash. The two are different questions, and before this the second
one had no answer.

The method is stamped **at acquisition time by the thing that did the
acquiring**, never inferred at render time. `Method` is ordered cheapest and
most authoritative first, and that order is the router's ladder.

A method is not a confidence. An authoritative registry read through a
browser is still authoritative; a guess served by a JSON API is still a guess.

### `core/providers.py` — what a source costs and whether it can answer

`Availability` splits "needs a key" into the five answers it was hiding: free,
free with limits, optional key, user-provided key, paid. Each key declares its
own in `KEY_INFO["<name>"]["availability"]`, because the free-text `cost` line
cannot be parsed — SecurityTrails' honest string is *"paid - no free tier
advertised"*, and every substring rule that catches "paid" also catches the
"free" three words later.

`ProviderHealth` is per-run memory of which sources are answering. A source
that rate limits us is benched for two minutes; one that refuses outright is
benched for the run. Nothing is persisted: a source that was down this
afternoon is not evidence about tomorrow.

### `core/router.py` — the ladder

`acquire()` has no failure path that raises. Exhausting every rung is an
ordinary `Outcome` with `found=False`, a reason per rung, and
`unavailable=True` when nothing could even be asked — which is the property
the renderers key **CANNOT ACCESS** off, as distinct from **NOT FOUND**.

A paid rung is skipped and named rather than attempted. "There is a source for
this, it costs money, you have not enabled it" is a different answer from
"nothing found", and occasionally the most useful line in a report.

### `core/search.py` — engines as sources

Wikipedia's API, Marginalia's public API and an operator-configured SearXNG
instance are asked by default. Mojeek and DuckDuckGo Lite read pages built for
people, so they are behind `--serp-pages`.

Two normalisation rules carry the weight:

- One document returned by three engines is **one row**, keeping the best
  position any engine gave it.
- One wire story on ten sites is **one independence group**. Syndication is
  the dominant failure mode of search-derived intelligence, and without this
  a rumour acquires the evidential weight of a fact.

`core/robots.py` honours `robots.txt` for anything that reads a human page. It
deliberately does **not** apply it to a documented API: Wikipedia disallows
`/w/api.php` so search engines will not index JSON, while publishing that
endpoint for programmatic use and writing an etiquette page for it. Treating
that as a refusal refuses an invitation. `module_options.strict_robots`
applies it everywhere for anyone who disagrees.

### `core/queryplan.py` — what to ask

Name variants are **rearrangements only**. "John A. Smith" is never generated
from "John Smith": that is a different person's name until somebody says
otherwise, and finding somebody at it is how these tools manufacture a match.

Queries are ordered by how *identifying* their terms are, not by the order the
templates were written. A bare common name is generated, ranked last, marked
`ambiguous`, and its results can never become graph entities. Categories are
re-weighted during the run by what they actually returned.

### `core/browser.py` — the operator's own browser

Optional at import time: with neither Playwright nor Selenium installed,
`open_browser()` returns `NullBrowser`, every call reports the URL to open by
hand, and the investigation continues.

It will not solve a CAPTCHA, log in, pass a consent wall or defeat a paywall.
`detect_challenge` names which kind of wall it is, the page comes back with
`human_action` set, and the operator decides. `Page` is duck-typed like
`Response` — `ok`, `status`, `access`, `describe()` — so the router, the
health manager and the evidence store need no new vocabulary.

Default profile is a temporary directory, deleted on close. A named profile is
opt-in, and nothing reads cookies, passwords or history out of it.

### `core/investigate.py` — the command

Search runs **before** the expansion walk, deliberately: a bare name gives the
frontier nothing to walk from, and search is what turns it into handles,
domains and organisations the existing engine already knows how to pursue.
After the walk, the strongest new entities generate follow-up queries.

The live tree is the report's skeleton, not decoration. Every stage says what
it asked, what answered, and what could not be reached.

### Where to add things

| You want to add | Do this |
|---|---|
| A source with an API | A `Module`, exactly as before. Nothing changed. |
| A search engine | Subclass `SearchEngine`: `build_url` + `parse`, then add it to `_ENGINES` and `DEFAULT_ORDER`. Set `scraping = True` if it is a human page. |
| A fallback chain for one need | Build `Step`s and hand them to `SourceRouter.acquire()`. |
| A browser backend | Subclass `BrowserProvider`, implement `installed()`, `open()` and `navigate()`. |
| A document format | A branch in `docparse.parse` and a `kind_of` signature. |
| A new evidence kind | One line in `graph.EVIDENCE`, with a comment arguing for the number. |

---

## Pivot quality: the rules that stop a scan chasing strangers

Three bugs produced most of the bad output this tool has ever generated, and
all three were the same mistake — **the entity layer trusting the caller's
label instead of the value's shape.** A module says `USERNAME` and gets a
username node; say it about a person's name and the engine points a 481-site
sweep at a string containing a space.

So the shape gate lives in `entities.Entity.make`, where it covers every
emitter at once, beside the older rule that a name with a subdomain is a HOST
whatever the caller said.

| Rule | What it stopped |
|---|---|
| A handle cannot contain whitespace, `/`, `:`, or be an IP or 200 characters long | `Ryan Rafael`, `jireh joy pancho` becoming handles, and the "stuck on names" hang |
| One `@` only in the fediverse `user@host` form | addresses mislabelled as handles |
| A domain-shaped handle is **allowed** | on Bluesky a domain *is* the handle (`eastdakota.com`) |
| An IP literal is an IP entity whatever it was called | fourteen domain modules running against `216.150.1.1` |

### `core/infra.py` — co-location is not a relation

`judge_host()` decides whether an address is shared infrastructure from three
signals, strongest first: provider **naming** (a PTR or cert CN like
`no-sni.vercel-infra.com`), AS **ownership**, and **population** — the signal
that needs no list, because if forty unrelated names resolve there it is
shared whoever runs it.

A shared address keeps its finding and stops generating pivots. This is the
same posture Amass takes when it declines to expand into cloud netblocks, and
SpiderFoot when it files co-hosted sites as *affiliates* with a cap.

### Three more rules of the same kind

* **An unverified hit is not a confirmed one.** The username control probe
  promotes a hit to `CONFIRMED` only when the control was actually tested and
  rejected. A control that timed out, or that the site's own `regexCheck`
  refuses, verifies nothing — and the control is generated to satisfy that
  regex so it can be tested at all.
* **An engine is never sent an operator it does not implement.** Every
  `SearchEngine` declares `supports`; `SearchService._phrase_for` degrades the
  query or skips the engine, and says which.
* **Declining to follow a lead is a finding.** `Expansion.below_floor` names
  what was discovered and deliberately not pursued, and the report says what
  would raise it above the floor.

### Bounds

`work_key()` collapses a URL and its own host to one subject, so the nine
modules that ask both the same question run once. A per-module time limit
(`--module-time-limit`, default 180s) starves a slow module rather than
letting it hold the run open — a thread cannot be killed, so past the
deadline its requests return "module time limit reached" without a socket
being opened, and the result degrades with that reason on it.

### The suite is offline by construction

`tests/conftest.py` closes the socket for every test not marked
`@pytest.mark.network`. `Fetcher._once` is the only place that opens one.
Before this, one phone test spent 95 seconds of a 105-second run on live
lookups and nobody noticed, because it passed.
