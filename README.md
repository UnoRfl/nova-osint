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

17 modules · 480+ username platforms · zero required dependencies · passive by default

</div>

---

Give NOVA a domain, an email address, a username, an IP or a phone number. It
works out what you handed it, runs every module that accepts that type in
parallel, and returns one report with the findings ranked, the sources named,
and the next targets worth scanning listed at the bottom.

```bash
nova scan example.com
nova scan alice@example.com --format html --output report.html
nova scan someuser --only username
nova scan 8.8.8.8 --pivot
```

The engine is **standard library only** — no `requests`, no `dnspython`, no
build step. `rich` and `phonenumbers` are optional and only make the output
prettier and the phone parsing better.

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
| `phone` | phone | validity, region, carrier, line type, timezone | – |
| `dorks` | all | targeted search-engine and GitHub code-search queries | – |

Run `nova modules` to see which are live right now and which are waiting on a key.

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

**3. Passive actually means passive.** `--passive` does not just "go quieter".
It disables every module that would send a packet to infrastructure the target
controls. What is left queries only third parties, so the target sees nothing.

## Output

Five formats: `console` (the default), `json`, `csv`, `markdown`, `html`.

```bash
nova scan example.com --format html --output report.html   # standalone, dark-mode aware
nova scan example.com --format json | jq '.results[].findings[]'
nova scan example.com --format csv --output findings.csv
```

Every finding carries a **source**, a **confidence** (`confirmed` / `likely` /
`possible`) and a **severity** (`info` / `notable` / `high` — investigative
interest, not vulnerability severity). `--min-severity notable` cuts the noise
on a big scan. See [`examples/`](examples/) for a real report.

## Pivoting

Modules emit *pivots*: new targets found mid-scan. A domain scan surfaces its
IPs, its RDAP contacts and its subdomains; an email scan surfaces the usernames
it might correspond to; a GitHub scan surfaces the addresses in commit metadata.

```bash
nova scan example.com --pivot --pivot-limit 5
```

That scans up to five discovered targets one level deep and folds the results
into the same report. It is deliberately one level: automatic recursion turns
into a crawl of the internet very quickly.

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
```

## API keys

Every module works without one; keys only raise limits or unlock a source.
Copy `.env.example` to `.env`, fill in what you have, and pass `--env-file .env`
— nothing auto-loads, because a tool that silently picks up credentials from
the working directory is a tool that leaks them when you run it elsewhere.

```bash
export GITHUB_TOKEN=...        # 60/hr -> 5000/hr; a no-scope classic token is enough
nova scan someuser --only github
```

## Extending it

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
