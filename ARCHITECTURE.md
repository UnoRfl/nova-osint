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
│   ├── gui/                 Tkinter desktop app (boot, console, orbit, theme)
│   └── data/                bundled site catalogue and disposable-mail list
│
├── tests/
│   ├── test_core.py         detection, registry, renderers, module helpers
│   ├── test_pipeline.py     config, retry, normaliser, status, logging
│   └── test_gui.py          desktop app, headless
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
| `dorks.py` | `dorks` — builds search URLs, never runs them |

### `gui/` — the desktop app

`boot.py` (animated init), `console.py` (the main window), `orbit.py` and
`theme.py` (drawing), `app.py` (wiring). The GUI drives the same `Engine` the
CLI does; it has no OSINT logic of its own.

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

## Adding a new output format

Write `render_myformat(inv: Investigation) -> str` in `core/report.py` and add
it to the `RENDERERS` dict. It is picked up by `--format` and by
`report.write()`'s suffix inference automatically.

Whatever you render, include `status_rows(inv)`. A report that lists findings
without saying which instruments failed presents "we could not look" as
"there was nothing there", which is the one error this tool must not make.
