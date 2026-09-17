"""Search-engine dork generation.

This module builds query URLs; it does not run them. Scraping Google or Bing
from a script gets you a CAPTCHA within a dozen queries and breaches their
terms, so the honest design is to generate the queries and let the analyst open
the ones that matter in a browser.

The queries themselves are the value: knowing to ask for
``site:trello.com "acme.com"`` is the skill, not fetching the result page.
"""

from __future__ import annotations

import urllib.parse

from ..core.http import hostname_of
from ..core.models import ScanResult, TargetType
from ..core.registry import Module, register

ENGINES = {
    "google": "https://www.google.com/search?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
    "duckduckgo": "https://duckduckgo.com/?q={q}",
}

DOMAIN_DORKS = [
    ("subdomains indexed", 'site:*.{d} -www'),
    ("documents", 'site:{d} (filetype:pdf OR filetype:docx OR filetype:xlsx)'),
    ("config and backups", 'site:{d} (ext:env OR ext:bak OR ext:sql OR ext:log OR ext:conf)'),
    ("directory listings", 'site:{d} intitle:"index of"'),
    ("login portals", 'site:{d} (inurl:login OR inurl:signin OR inurl:admin)'),
    ("exposed dashboards", 'site:{d} (intitle:"dashboard" OR intitle:"phpMyAdmin" OR intitle:"Grafana")'),
    ("API docs and keys", 'site:{d} (inurl:api OR inurl:swagger OR "api_key" OR "apikey")'),
    ("staging and dev hosts", 'site:{d} (inurl:dev OR inurl:staging OR inurl:test OR inurl:uat)'),
    ("employees on LinkedIn", 'site:linkedin.com/in "{d}"'),
    ("code leaks on GitHub", 'site:github.com "{d}"'),
    ("pastebin mentions", 'site:pastebin.com "{d}"'),
    ("public Trello boards", 'site:trello.com "{d}"'),
    ("S3 buckets", '(site:s3.amazonaws.com OR site:storage.googleapis.com) "{d}"'),
    ("open Jira / Confluence", '(site:atlassian.net OR inurl:jira) "{d}"'),
    ("mentioned in job posts", '("{d}") (site:greenhouse.io OR site:lever.co OR site:workable.com)'),
]

EMAIL_DORKS = [
    ("exact address", '"{t}"'),
    ("in breach dumps and pastes", '"{t}" (site:pastebin.com OR site:ghostbin.com OR site:throwbin.io)'),
    ("in public code", '"{t}" (site:github.com OR site:gitlab.com OR site:bitbucket.org)'),
    ("in documents", '"{t}" (filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:txt)'),
    ("on social platforms", '"{t}" (site:x.com OR site:facebook.com OR site:linkedin.com)'),
    ("in forum posts", '"{t}" (inurl:forum OR inurl:thread OR inurl:viewtopic)'),
]

USERNAME_DORKS = [
    ("exact handle", '"{t}"'),
    ("profile pages", '"{t}" (inurl:user OR inurl:profile OR inurl:member OR inurl:u/)'),
    ("on code hosts", '"{t}" (site:github.com OR site:gitlab.com OR site:stackoverflow.com)'),
    ("on social platforms", '"{t}" (site:reddit.com OR site:x.com OR site:instagram.com OR site:tiktok.com)'),
    ("in leaked lists", '"{t}" (site:pastebin.com OR "combolist" OR "dehashed")'),
    ("gaming and voice", '"{t}" (site:steamcommunity.com OR site:twitch.tv OR site:discord.com)'),
]

GITHUB_CODE_DORKS = [
    ("hardcoded secrets", '"{d}" (password OR secret OR api_key OR token) language:yaml'),
    ("environment files", '"{d}" filename:.env'),
    ("cloud credentials", '"{d}" (AWS_SECRET_ACCESS_KEY OR aws_access_key_id)'),
    ("internal hostnames", '"{d}" (internal OR intranet OR vpn)'),
    ("database strings", '"{d}" (jdbc OR mongodb+srv OR postgres://)'),
]


@register
class DorksModule(Module):
    name = "dorks"
    title = "Search queries to run by hand"
    description = "Builds targeted search-engine and GitHub code-search URLs."
    accepts = frozenset({TargetType.DOMAIN, TargetType.EMAIL, TargetType.USERNAME,
                         TargetType.URL, TargetType.PHONE})

    def run(self, target: str, result: ScanResult) -> None:
        ttype = result.target_type
        if ttype in (TargetType.DOMAIN, TargetType.URL):
            domain = hostname_of(target)
            self._emit(DOMAIN_DORKS, {"d": domain, "t": domain}, result)
            for label, tmpl in GITHUB_CODE_DORKS:
                q = tmpl.format(d=domain, t=domain)
                result.add(f"github code: {label}", q, source="dorks",
                           url="https://github.com/search?type=code&q=" + urllib.parse.quote(q))
        elif ttype == TargetType.EMAIL:
            self._emit(EMAIL_DORKS, {"t": target, "d": target.split("@")[-1]}, result)
        elif ttype == TargetType.USERNAME:
            self._emit(USERNAME_DORKS, {"t": target, "d": target}, result)
        elif ttype == TargetType.PHONE:
            variants = _phone_variants(target)
            for v in variants:
                q = f'"{v}"'
                result.add(f"search {v}", q, source="dorks",
                           url=ENGINES["google"].format(q=urllib.parse.quote(q)))

    def _emit(self, dorks: list[tuple[str, str]], fields: dict[str, str],
              result: ScanResult) -> None:
        for label, tmpl in dorks:
            q = tmpl.format(**fields)
            result.add(label, q, source="dorks",
                       url=ENGINES["google"].format(q=urllib.parse.quote(q)),
                       extra={"bing": ENGINES["bing"].format(q=urllib.parse.quote(q)),
                              "duckduckgo": ENGINES["duckduckgo"].format(q=urllib.parse.quote(q))})


def _phone_variants(number: str) -> list[str]:
    import re

    digits = re.sub(r"\D", "", number)
    out = {number.strip(), "+" + digits, digits}
    if len(digits) == 11 and digits.startswith("1"):
        d = digits[1:]
        out |= {f"({d[:3]}) {d[3:6]}-{d[6:]}", f"{d[:3]}-{d[3:6]}-{d[6:]}", f"{d[:3]}.{d[3:6]}.{d[6:]}"}
    elif len(digits) == 10:
        out |= {f"({digits[:3]}) {digits[3:6]}-{digits[6:]}", f"{digits[:3]}-{digits[3:6]}-{digits[6:]}"}
    return sorted(out)
