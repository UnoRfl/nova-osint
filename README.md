<div align="center">

```
              ·  ·  ·  ·  ·
           ·                 ·        ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗
  ✦      ·           ◉          ●    ████╗  ██║██╔═══██╗██║   ██║██╔══██╗
           ·                 ·        ██╔██╗ ██║██║   ██║██║   ██║███████║
              ·  ·  ·  ·  ·           ██║╚██╗██║██║   ██║╚██╗ ██╔╝██╔══██║
        ·                       ˙     ██║ ╚████║╚██████╔╝ ╚████╔╝ ██║  ██║
             ·          ✦             ╚═╝  ╚═══╝ ╚═════╝   ╚═══╝  ╚═╝  ╚═╝
                                       o p e n   s o u r c e   i n t e l
                                              b y   u n o
```

**One target in, every public source out.**

31 modules · free-first · browser-assisted · 480+ username platforms · desktop app + CLI

</div>

---

Give NOVA a name, a domain, an email address, a username, an IP or a phone
number. It works out what you handed it, decides what is worth asking, asks
it across free public sources, follows what the answers imply, and returns one
report with the findings ranked, the sources named, **how each fact was
obtained**, and — just as importantly — what it could not reach and why.

```bash
nova investigate "Ada Lovelace"
nova investigate "Ada Lovelace" -K employer=Acme -K city=Cambridge
nova investigate ada@example.org --browser --image badge.jpg
nova investigate example.com --depth 3 --search-engine all
```

`nova scan` is still there and unchanged — one target, every module that
accepts it, one flat report. `nova investigate` is the same engine with a plan
in front of it.

The engine is **standard library only** — no `requests`, no `dnspython`, no
build step. `rich` and `phonenumbers` are optional and only make the output
prettier and the phone parsing better.

## Free first, always

NOVA never assumes you have paid for anything. For every question it asks, it
walks a ladder and stops at the first rung that answers:

```
local  →  cache  →  stored case  →  public API  →  public page  →  search  →  your browser
```

Whichever rung answered is recorded on the finding, so a search snippet can
never be mistaken for a registry record. A source that needs a key you do not
have, or costs money, is **named and skipped** — never quietly attempted and
never rendered as "nothing found":

```
sources not consulted        these are gaps in coverage, not absences of evidence
  securitytrails   paid            no key - paid source, not queried
  virustotal       requires key    needs $VT_API_KEY
  crtsh            rate limited    asked us to slow down
  mojeek           not checked     result-page engine, not enabled (--serp-pages)
```

Paid sources are off unless you pass `--allow-paid`. Nothing here needs a
subscription to work.

## Install

```bash
git clone https://github.com/UnoRfl/nova-osint && cd nova-osint
pip install -e ".[full]"
```

Or run it straight out of the folder with no install at all:

```bash
python -m nova_osint scan example.com
```

Python 3.10+. Works on Windows, macOS and Linux.

## Desktop app

```bash
nova gui
```

Or double-click **`NOVA.bat`** in the project folder — or `dist/NOVA.exe` if you
built the standalone binary (see below).

It opens on a boot screen with the orbit animation while it does real work:
importing the module registry, reading the configuration and environment for
keys, opening the HTTP transport, pulling the 480-site catalogue and probing
every upstream source. If crt.sh is down you find out there, not halfway
through a scan.

**The boot screen waits for you.** It does not advance on a timer - it sits
there with the log on screen until you press Enter (or Space, or the button),
so a warning about a dead source or a rejected key cannot scroll past before
you have read it.

Then the console:

- **Type a target** and the instrument list rebuilds for whatever it is. The
  chip beside the box shows the detected type; key-gated modules appear greyed
  with the reason on hover.
- **Every instrument has its own colour**, used consistently for its group in
  the results, its tag in the live log and its pill in the activity strip — so
  you can follow one source through all three without reading a word.
- **Results stream in** as each module finishes rather than appearing all at
  once at the end. Findings are coloured by interest level; double-click any
  row with a URL to open it.
- **Pivots are one double-click away** from becoming the next scan.
- **Export** to HTML, JSON, CSV or Markdown from the status bar.
- **Settings** (bottom of the sidebar) edits the same `config.json` the CLI
  reads: API keys, network behaviour and which instruments are enabled. A
  stored key is never rendered back into the field, and a key set in the
  environment shows as locked, because a file value could not override it.

`--no-art` on the CLI has a GUI equivalent: nothing. The animation is 2.6
seconds and then it gets out of the way.

### Building a standalone .exe

```bash
pip install pyinstaller && pyinstaller NOVA.spec --noconfirm
```

Produces `dist/NOVA.exe` — ~22 MB with Python, Tk and the site catalogue
inside, so it runs on a machine with no Python installed. Cold start to a
visible window is about 2 seconds.

The spec points at `launcher.py`, not `nova_osint/gui/__main__.py`: the
bootloader runs the entry file as a top-level script, so `__main__.py`'s
relative import has no parent package to resolve against and the frozen app
dies before it draws anything. If you rebuild, close any running NOVA.exe
first — a live process holds the file and PyInstaller will leave the stale
binary in place while still exiting 0.

## What it collects

| Module | Target | What it gets | Key |
|---|---|---|---|
| `username` | username, email | 480+ platforms, soft-404 verified | – |
| `github` | username | profile, orgs, SSH/GPG keys, **commit emails and timezone** | optional |
| `gists` | username | public gists and their filenames | optional |
| `email` | email | structure, deliverability, disposability, Gravatar, linked accounts | – |
| `mailsec` | domain, email | SPF, DMARC, DKIM selectors, BIMI, provider | – |
| `breaches` | domain, email | HIBP incidents for the organisation | – |
| `pwned` | email | HIBP lookup for the specific address | HIBP |
| `whois` | domain | RDAP registration, dates, status, registrar | – |
| `dns` | domain | A, AAAA, MX, NS, TXT, SOA, CAA over DoH | – |
| `subdomains` | domain | crt.sh + CertSpotter + HackerTarget + RapidDNS, resolved | – |
| `headers` | domain | banners, cookie flags, missing hardening, favicon hash | – |
| `exposed` | domain | robots.txt, security.txt, sitemaps, `.well-known` | – |
| `wayback` | domain | first/last capture, archived files, historic parameters | – |
| `ip` | IP | geo, ASN, rDNS, Shodan InternetDB, netblock | – |
| `abuseipdb` | IP | abuse confidence and report categories | AbuseIPDB |
| `virustotal` | domain, IP | blocklist verdicts, categories, **passive DNS** | VirusTotal |
| `securitytrails` | domain | historical DNS and **pre-privacy WHOIS** | SecurityTrails |
| `phone` | phone | validity, region, carrier, line type, timezone | – |
| `dorks` | all | targeted search-engine and GitHub code-search queries | – |
| `websearch` | name, username, email, domain | runs the planned queries against free engines; syndicated copies collapse to one source | – |
| `documents` | URL | PDF/DOCX/XLSX metadata, the people its properties name, identifiers in its text | – |
| `wikidata` | name, domain | curated claims, one subject per Q-id | – |
| `bluesky` | name, username | accounts whose display name matches, ranked | – |
| `social-graph` | username | mutual follows, which are relationships | – |
| correlators | various | keys, keybase, trackers, fingerprints, packages, webfinger, confusables | – |

Run `nova modules` to see which are live right now and which are waiting on a key.

Images and documents are read locally and for free: `nova image badge.jpg`
gives you format, dimensions, EXIF, GPS, camera, a sha256 and two perceptual
hashes, plus OCR text when Tesseract is installed. It compares *pictures*, not
people — two photographs of one person are two different pictures and will
read as unrelated, which is the honest answer.

## Three things it does better than the usual stack

**1. Username hits are verified, not guessed.** Sites that answer an unclaimed
handle with a pretty 200-OK "user not found" page are the reason these tools
have a reputation for noise. After collecting hits, NOVA re-runs each one
against a handle nobody could own and drops any site that claims both.

> Measured on a 45-site sample with a nonexistent handle:
> **7 false positives without verification, 0 with it.** It is on by default;
> `--no-verify` turns it off.

**2. GitHub commit metadata, not just the profile page.** The profile says what
someone chose to type. Their commits carry the author email git was configured
with and a UTC offset on every timestamp — so NOVA reports the email addresses
behind the account and infers a timezone from the distribution of recent commit
offsets, with the distribution shown so you can judge it yourself.

**3. Passive actually means passive, and is enforced.** `--passive` does not
just "go quieter". It disables every module that would send a packet to
infrastructure the target controls — and then a guard *blocks* any remaining
module from reaching the target's domain anyway, so a mislabelled module is
stopped rather than trusted. A promise a tool cannot check is not worth making.

**3b. Things are linked by shared fingerprints, not by guesswork.** Two sites
carrying the same Google Analytics property, two handles holding the same SSH
key, two hosts serving the same favicon: each becomes a node both sides point
at, so the connection is found without any code comparing A to B, and the reason
is visible in the report.

**4. A refusal is reported, not hidden.** NOVA identifies itself honestly in
every request (`NOVA-OSINT/1.1.0`), respects `Retry-After`, and makes no attempt
to defeat rate limits, CAPTCHAs, bot detection, WAFs or authentication. When a
source says no, the module is marked `rate limited` / `blocked` / `unavailable`
and that appears in the report:

```
instruments that did not report cleanly
 instrument   status         reason
 subdomains   partial        2 source request(s) came back 'rate limited'
 pwned        skipped        needs $HIBP_API_KEY
```

"We could not look" and "there was nothing to find" are different answers, and
a tool that renders them identically will eventually get someone's conclusion
badly wrong.

## Output

Seven formats: `console` (the default), `json`, `csv`, `markdown`, `html`,
`graph` (an interactive page) and `graphml` (for Gephi / yEd / Cytoscape).

```bash
nova scan example.com --format html --output report.html   # standalone, dark-mode aware
nova scan example.com --format json | jq '.results[].findings[]'
nova scan example.com --format csv --output findings.csv
```

Every finding carries a **source**, a **confidence** (`confirmed` / `likely` /
`possible`) and a **severity** (`info` / `notable` / `high` — investigative
interest, not vulnerability severity). `--min-severity notable` cuts the noise
on a big scan. See [`examples/`](examples/) for a real report.

### The dossier

One subject, every field, with the working kept:

```bash
nova scan alice@example.com --expand --format dossier
nova scan alice@example.com --expand --format dossier-json | jq .identity
```

Unlike the other formats this one consolidates rather than lists. Competing
values from different sources are both kept and ranked by the weight of their
source, conflicts get their own section, and nothing is chosen for you. The
desktop app shows the same thing in its **Dossier** tab.

Exposure records contribute only their non-credential metadata. Passwords,
hashes, tokens, cookies and keys are never read, never stored and never
printed; a record that contained them says so instead.

## Following the connections

A scan answers "what is true about this target". `--expand` answers the harder
question: *and what is connected to that, and to that*.

```bash
nova scan example.com --expand                 # sensible default budget
nova scan example.com --expand --budget deep   # go further
nova scan alice@example.com --expand --depth 3 --max-entities 80
```

Each round rescores the graph, takes the best-evidenced entities nobody has
looked at yet, runs the modules that accept them, and feeds what they find back
in — so what round two discovers changes what round three thinks is worth doing.

The reason most tools do not do this is that it explodes. A domain resolves to a
Cloudflare address that answers for four million other names, and two hops later
the graph is the internet and the target is gone. Three things stop that:

- **Evidence is weighted in log-odds.** A shared SSH key is +7.5; a handle
  guessed from an email local part is +0.3. Independent evidence adds,
  disconfirming evidence subtracts, and a control-handle match that proves a
  site says yes to everyone is −3.0.
- **Hubs demote themselves.** An edge through a node is divided by the log of
  that node's degree, so shared infrastructure loses its pull *as the scan
  discovers how big it is*. No hand-maintained list of things to ignore.
- **Relevance is a widest path, not a hop count.** A two-hop chain of
  cryptographic proof outranks a one-hop string match, so the request budget
  goes to the best-evidenced part of the graph first.

Four budget limits bound the walk — depth, evidence quality, entity count and
wall clock — and the report says which one stopped it and which leads it never
reached. A truncated investigation that does not admit it was truncated is the
same failure as a blocked source reported as an empty result.

`--pivot` still exists and still does one flat level, for when that is all you
want.

## Seeing it

```bash
nova scan example.com --expand --format graph --output graph.html
nova scan example.com --format graphml --output graph.graphml   # Gephi, yEd
```

The graph page is self-contained: the force-directed layout is about a hundred
lines of plain JavaScript, with no CDN, so it still works offline and attached
to a case file. Node radius is relevance to the target. Edge thickness is the
strength of the evidence — click any node and the panel tells you *why* it is
connected, with the Admiralty grade, the specific observations, the source URL
and the sha256 of the stored response.

The text reports carry the same thing:

```
how the pieces connect
 grade  connected to                   how          evidence                reading
 A3     ssh/SHA256:SlSdsTYgtT3jhz1Q…   holds-key    key-fingerprint-shared  near certain
 B3     torvalds@linux-foundation.org  commits-as   commit-email            probable
 D3     djwong@kernel.org              contributes  mentioned               weakly suggestive

 grades are Admiralty: letter = strength of the evidence (A best, E
 disconfirming), digit = independent corroboration (1 most, 5 none)
```

Source reliability and corroboration are separate letters on purpose. Collapsing
them into one "confidence" is how a rumour ends up presented with the authority
of a registry record.

## Cases: history, diffs and proof

Every scan is recorded unless you pass `--no-save`.

```bash
nova history                       # what you have scanned
nova show 20260917-2026            # one case, by id or unambiguous prefix
nova diff example.com              # what changed between the last two runs
nova link <case-a> <case-b>        # entities two investigations share
nova where alice@example.com       # which cases have ever seen this
```

`diff` is the feature that makes the tool worth running twice: a new subdomain,
a changed MX, a handle that now exists. Findings are keyed so a changed value
reads as *changed* rather than as an unexplained removal beside an unexplained
addition — and a module that went dark between runs is reported as a **coverage**
change first, because it reframes every removal underneath it.

### Proving a result

Every response body is stored, sha256-addressed and compressed, next to the
case. A finding can be traced to the exact bytes it was parsed from, months
later, after the source has changed its mind or disappeared.

```bash
nova replay <case>          # re-derive the findings from stored evidence, no network
nova evidence <case>        # re-hash every blob, verify the audit chain
nova evidence --digest <sha256>   # print one stored response
```

`replay` hard-disables the network. A URL with no recording comes back as an
explicit miss and is counted, so *reproduced exactly* means exactly that:

```
  modules re-run      3
  responses served    27  (100% of requests)
  findings then/now   19 / 19

  reproduced exactly.
```

That also makes every saved case a free regression test. A parser that quietly
stops reading a field shows up as drift against real captured bytes rather than
against a hand-written fixture containing only what its author thought of.

The audit log is hash-chained, so an edited or deleted entry breaks the chain at
a line `nova evidence` will name.

### Before you scan

```bash
nova doctor                 # can this machine actually reach each source?
nova doctor --keyless       # skip the ones needing an API key
nova doctor --leak-check --proxy socks5h://127.0.0.1:9050
```

`doctor` separates *reachable*, *refused us*, *rate limited* and *needs a key
you do not have*. Those four produce an identical empty section in a report and
mean four different things; knowing which before a fifteen-minute scan beats
finding out after. `--leak-check` compares the address the direct and proxied
routes present — a proxy that silently is not carrying your traffic looks
identical from the inside.

## Sharing a report

```bash
nova scan alice@example.com --redact --format html --output share.html
```

`--redact` masks emails, handles and phone numbers **in the output**; the case
store keeps the real values, because an investigation that loses its own data is
useless. Masking is consistent within a document, so two accounts sharing an
address still visibly share it, and salted so tokens are not comparable between
reports unless you pass the same `--redact-salt` deliberately.

## Options worth knowing

```
--passive              never touch the target's own infrastructure
--only / --exclude     pick modules by name
--max-sites N          cap username sites and subdomain probes
--delay 1.0            seconds between requests to the same host (raise it, don't lower it)
--concurrency 24       parallel requests
--no-cache             bypass the 1-hour response cache
--proxy URL            route everything through a proxy
--min-severity high    show only what matters
--pivot                follow discovered targets one level deep
--no-art               keep the progress line, drop the animation
-q / --quiet           machine-friendly: no banner, no progress
-v / -vv               log what each instrument is doing (-vv for debug)
--log-file scan.log    full debug log; API keys are redacted out of it
-c / --config PATH     use a different config.json
```

Exit codes: `0` findings, `1` no findings, `2` bad arguments, `3` nothing ran.

## Configuration

Settings live in a JSON file; secrets live in the environment. Four layers,
highest priority first:

```
command-line flag  >  environment variable  >  config.json  >  built-in default
```

```bash
nova config path      # where the file is
nova config init      # write it with defaults
nova config show      # print it, API keys masked
```

```jsonc
{
    "settings": {
        "timeout": 12.0,
        "max_retries": 2,
        "max_concurrent_tasks": 24,
        "request_delay_min": 0.30,     // each wait is drawn from this range,
        "request_delay_max": 0.45,     // per host, so workers do not lockstep
        "cache_enabled": true,
        "cache_ttl": 3600.0,
        "verify_tls": true,
        "user_agent": "",              // blank = NOVA-OSINT/1.1
        "output_directory": "./output",
        "passive_only": false,
        "max_sites": 0
    },
    "proxies": { "enabled": false, "http": "", "https": "", "socks5": "" },
    "api_keys": { "github": "", "hibp": "" },
    "modules_enabled": { "dorks": false }
}
```

No configuration mistake stops a scan: a missing file is created, a malformed
one falls back to defaults with a warning, an out-of-range number is clamped,
and an unknown key is reported and ignored. `ARCHITECTURE.md` has the full
table of what happens to each kind of mistake.

## API keys

Every module works without one; keys only raise limits or unlock a source.
Copy `.env.example` to `.env`, fill in what you have, and pass `--env-file .env`
— nothing auto-loads, because a tool that silently picks up credentials from
the working directory is a tool that leaks them when you run it elsewhere.

```bash
export GITHUB_TOKEN=...        # 60/hr -> 5000/hr; a no-scope classic token is enough
nova scan someuser --only github
```

Three keys do something today, and the tool tells you which:

| Key | Unlocks | Cost |
|---|---|---|
| `GITHUB_TOKEN` | 60 -> 5,000 req/hr for `github`, `gists`, `email` | free |
| `VT_API_KEY` | `virustotal`: blocklist verdicts + passive DNS | free tier |
| `ABUSEIPDB_API_KEY` | `abuseipdb`: IP abuse score | free tier |
| `SECURITYTRAILS_API_KEY` | `securitytrails`: DNS and WHOIS history | **paid** — no free tier advertised |
| `HIBP_API_KEY` | `pwned`: per-address breach lookup | paid |

`SHODAN_API_KEY`, `HUNTER_API_KEY`, `NUMVERIFY_API_KEY` and `EMAILREP_API_KEY`
are declared but **no module reads them yet** - setting one does nothing. The
settings window and `.env.example` both say so rather than implying otherwise.

Easiest route: open the desktop app and press **Settings**. Every key has its
own row with what it unlocks, what it costs, which modules use it, and a
**Get a key** button that opens the right page. Keys can also go in the
`api_keys` block of `config.json`, which is written `0600` where the OS
supports it. Wherever they come from, a key never leaves
the process except as a request header: `nova config show` masks them, the
logger redacts them, reports never contain them, and responses to authenticated
requests are never written to the disk cache.

## Extending it

Full guide, including the rules a module must follow, in
[`ARCHITECTURE.md`](ARCHITECTURE.md). The short version:

A module is one class. Drop it in `nova_osint/modules/`, add it to the import
list in `core/registry.py`, and it appears in `nova modules` and in every scan
of a matching target.

```python
from ..core.models import ScanResult, Severity, TargetType
from ..core.registry import Module, register

@register
class MyModule(Module):
    name = "mysource"
    description = "What it gets."
    accepts = frozenset({TargetType.DOMAIN})
    active = False          # True if it touches the target's own servers
    requires_key = None     # or "shodan", etc.

    def run(self, target: str, result: ScanResult) -> None:
        data = self.http.get_json(f"https://api.example/{target}")
        if data:
            result.add("thing", data["thing"], source="mysource",
                       severity=Severity.NOTABLE)
            result.pivot(data["ip"], TargetType.IP, "from mysource")
```

`self.http` is the shared fetcher: rate-limited per host, cached, retried, and
it never raises — you always get a `Response`.

## Development

```bash
pip install -e ".[dev]"
pytest -q          # offline and deterministic; nothing hits the network
ruff check .
nova art           # the full banner gallery
```

CI runs the suite on Python 3.10/3.12/3.13, plus CodeQL (`security-extended`),
gitleaks over full history, a credential-shape guard and zizmor on the workflows
themselves. Third-party actions are pinned to commit SHAs.

## Please read this part

NOVA queries public sources, which is a real limit on what it can do and no
defence at all for what you choose to do with it. It deliberately will not
handle breach credentials, probe SMTP, enumerate messaging apps, brute-force
paths or scrape search engines.

**"Publicly available" is not the same as "fair to aggregate."** Each finding
here is already public; the assembled report is not, and that is both why the
tool is useful and how it causes harm. Have authorisation, know your
jurisdiction, keep the output like the sensitive material it is, and verify
before you act on anything.

[**ETHICS.md**](ETHICS.md) has the full version. `nova legal` prints the short one.

## Credits

The username catalogue follows the schema maintained by
[sherlock-project/sherlock](https://github.com/sherlock-project/sherlock) (MIT)
and `--refresh-sites` pulls their list directly. The throwaway-mail blocklist
comes from
[disposable-email-domains](https://github.com/disposable-email-domains/disposable-email-domains)
(MIT). See [NOTICE](NOTICE) for the full list of projects and services.

## License

**All rights reserved.** The source is public so you can read it, audit it and
see how it works. It is not licensed for reuse — you may not copy, modify or
redistribute it without written permission. GitHub lets you fork any public
repo; that is GitHub's Terms talking, not a licence. If you want to use part of
this, open an issue and ask.

The bundled site catalogue and disposable-mail list are MIT-licensed material
from other projects and stay MIT — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
