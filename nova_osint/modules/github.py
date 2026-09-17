"""GitHub account reconnaissance.

The interesting part is not the profile page - it is the metadata around it:
public SSH/GPG keys, the author email baked into every commit, and the
distribution of commit timezone offsets, which localises someone far more
reliably than a self-reported profile location.

An unauthenticated caller gets 60 requests/hour, which this module will exhaust
on a busy account. Set ``GITHUB_TOKEN`` (a read-only classic token with no
scopes is enough) to get 5000.
"""

from __future__ import annotations

import collections
import re

from ..core.entities import EntityType
from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

API = "https://api.github.com"
NOREPLY = re.compile(r"^\d+\+?[\w.-]*@users\.noreply\.github\.com$", re.I)


@register
class GithubModule(Module):
    name = "github"
    title = "GitHub account"
    description = "Profile, repos, public keys, commit emails and timezone inference."
    accepts = frozenset({TargetType.USERNAME})
    slow = True

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token := self.config.key("github"):
            h["Authorization"] = f"Bearer {token}"
        return h

    def run(self, target: str, result: ScanResult) -> None:
        user = self.http.get(f"{API}/users/{target}", headers=self._headers())
        data = user.json()
        if user.status == 404 or not isinstance(data, dict) or "login" not in data:
            if user.status == 403:
                result.error("GitHub API rate limit hit - set GITHUB_TOKEN")
            else:
                result.error(f"no GitHub account named {target}")
            return

        result.add("profile", data["html_url"], source="github", url=data["html_url"],
                   severity=Severity.HIGH)
        for key, label, sev in (
            ("name", "display name", Severity.NOTABLE),
            ("company", "company", Severity.NOTABLE),
            ("location", "stated location", Severity.NOTABLE),
            ("email", "public email", Severity.HIGH),
            ("blog", "website", Severity.NOTABLE),
            ("twitter_username", "Twitter/X", Severity.NOTABLE),
            ("bio", "bio", Severity.INFO),
            ("hireable", "open to work", Severity.INFO),
        ):
            if value := data.get(key):
                result.add(label, value, source="github", severity=sev)
        if email := data.get("email"):
            result.entity(EntityType.EMAIL, str(email), relation="contact",
                          evidence="profile-email",
                          detail="address published on the GitHub profile")
        if handle := data.get("twitter_username"):
            result.entity(EntityType.USERNAME, str(handle), relation="linked-account",
                          evidence="profile-link",
                          detail="X/Twitter handle on the GitHub profile")
        if blog := data.get("blog"):
            from ..core.http import hostname_of

            if host := hostname_of(str(blog)):
                result.entity(EntityType.DOMAIN, host, relation="linked-site",
                              evidence="profile-link",
                              detail="website on the GitHub profile")

        result.add("account id", data.get("id"), source="github")
        result.add("created", str(data.get("created_at", ""))[:10], source="github")
        result.add("last profile update", str(data.get("updated_at", ""))[:10], source="github")
        result.add("counts",
                   f"{data.get('public_repos', 0)} repos, {data.get('public_gists', 0)} gists, "
                   f"{data.get('followers', 0)} followers, {data.get('following', 0)} following",
                   source="github")
        if data.get("type") == "Organization":
            result.add("account type", "Organization", source="github", severity=Severity.NOTABLE)

        self._keys(target, result)
        self._orgs(target, result)
        repos = self._repos(target, result)
        self._commits(target, repos, result)

    # ------------------------------------------------------------------ pieces

    def _keys(self, user: str, result: ScanResult) -> None:
        keys = self.http.get(f"https://github.com/{user}.keys")
        if keys.ok and keys.text.strip():
            lines = [line for line in keys.text.splitlines() if line.strip()]
            result.add("public SSH keys", f"{len(lines)} key(s)", source="github",
                       url=f"https://github.com/{user}.keys", severity=Severity.NOTABLE,
                       extra={"types": sorted({line.split()[0] for line in lines if line.split()})})
        gpg = self.http.get(f"https://github.com/{user}.gpg")
        if gpg.ok and "BEGIN PGP" in gpg.text:
            # The GPG block carries the UIDs, which usually include real emails.
            uids = sorted(set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", gpg.text)))
            result.add("public GPG key", "present", source="github",
                       url=f"https://github.com/{user}.gpg", severity=Severity.NOTABLE)
            for uid in uids[:10]:
                result.add("email in GPG key", uid, source="github", severity=Severity.HIGH)
                result.entity(EntityType.EMAIL, uid, relation="key-identity",
                              evidence="key-uid",
                              detail="UID baked into the published GPG key")

    def _orgs(self, user: str, result: ScanResult) -> None:
        orgs = self.http.get_json(f"{API}/users/{user}/orgs?per_page=100", headers=self._headers())
        if isinstance(orgs, list) and orgs:
            names = [o.get("login", "") for o in orgs]
            result.add("organisations", names, source="github", severity=Severity.NOTABLE)

    def _repos(self, user: str, result: ScanResult) -> list[dict]:
        repos = self.http.get_json(
            f"{API}/users/{user}/repos?per_page=100&sort=pushed", headers=self._headers()
        )
        if not isinstance(repos, list) or not repos:
            return []
        own = [r for r in repos if not r.get("fork")]
        result.add("repositories", f"{len(own)} own, {len(repos) - len(own)} forked",
                   source="github")

        langs = collections.Counter(r.get("language") for r in own if r.get("language"))
        if langs:
            result.add("languages", ", ".join(f"{lang} ({count})" for lang, count in langs.most_common(8)),
                       source="github")

        top = sorted(own, key=lambda r: r.get("stargazers_count", 0), reverse=True)[:5]
        for r in top:
            result.add(f"repo: {r.get('name')}",
                       f"{r.get('stargazers_count', 0)} stars - {(r.get('description') or '')[:90]}",
                       source="github", url=r.get("html_url"))
        if own:
            result.add("most recent push", str(own[0].get("pushed_at", ""))[:10], source="github")
        return own

    def _commits(self, user: str, repos: list[dict], result: ScanResult) -> None:
        """Harvest author emails and timezone offsets from recent commits."""
        if not repos:
            return
        targets = repos[:5]
        batches = self.http.map(
            lambda r: self.http.get_json(
                f"{API}/repos/{r['full_name']}/commits?per_page=100", headers=self._headers()
            ),
            targets,
        )
        emails: collections.Counter[str] = collections.Counter()
        offsets: collections.Counter[str] = collections.Counter()
        names: collections.Counter[str] = collections.Counter()
        #: Addresses on commits in this user's repos that are *not* theirs -
        #: either another account's, or one GitHub could not attribute at all.
        #: Kept, but kept separate; see below.
        others_seen: collections.Counter[str] = collections.Counter()

        for batch in batches:
            if not isinstance(batch, list):
                continue
            for c in batch:
                commit = (c or {}).get("commit") or {}
                author = commit.get("author") or {}
                login = ((c or {}).get("author") or {}).get("login")
                email = author.get("email")
                # Attribution must be positive. The old test was "skip it if the
                # login is *someone else*", which let every commit GitHub could
                # not map to an account through - and in a busy repo that is
                # mostly other contributors. It claimed the owner of the repo
                # was every kernel developer who had ever sent a patch.
                if not login or login.lower() != user.lower():
                    if email:
                        others_seen[email] += 1
                    continue
                if email:
                    emails[email] += 1
                if name := author.get("name"):
                    names[name] += 1
                if date := author.get("date"):
                    if m := re.search(r"([+-]\d{2}:\d{2})$", str(date)):
                        offsets[m.group(1)] += 1
                    elif str(date).endswith("Z"):
                        offsets["+00:00"] += 1

        real = [(e, n) for e, n in emails.most_common() if not NOREPLY.match(e)]
        masked = [e for e in emails if NOREPLY.match(e)]
        for e, n in real[:8]:
            result.add("commit author email", f"{e} ({n} commits)", source="github-commits",
                       severity=Severity.HIGH, confidence=Confidence.CONFIRMED)
            result.entity(EntityType.EMAIL, e, relation="commits-as",
                          evidence="commit-email",
                          detail="author address in public commit metadata")
        if masked:
            result.add("privacy", "uses GitHub's noreply commit email", source="github-commits")

        others = [e for e, _ in others_seen.most_common(15) if not NOREPLY.match(e)]
        if others:
            # Reported, because "who else commits here" is a real lead, and
            # weighted at almost nothing, because it is not this person. The
            # distinction is the whole point: a co-contributor's address
            # asserted as the target's is a false identity in a report.
            result.add("other contributor addresses", others, source="github-commits",
                       confidence=Confidence.POSSIBLE,
                       severity=Severity.INFO)
            for other in others:
                result.entity(EntityType.EMAIL, other, relation="contributes-with",
                              evidence="mentioned",
                              detail="commits in this user's repos, not attributed "
                                     "to their account")
        for n, count in names.most_common(3):
            result.add("commit author name", f"{n} ({count})", source="github-commits",
                       severity=Severity.NOTABLE)

        if offsets:
            top, count = offsets.most_common(1)[0]
            total = sum(offsets.values())
            result.add(
                "likely timezone",
                f"UTC{top} ({count}/{total} recent commits)",
                source="analysis",
                confidence=Confidence.LIKELY if count / total > 0.6 else Confidence.POSSIBLE,
                severity=Severity.HIGH,
                extra={"distribution": dict(offsets.most_common(5))},
            )


@register
class GistModule(Module):
    name = "gists"
    title = "Public gists"
    description = "Recent gists, which often leak snippets and config."
    accepts = frozenset({TargetType.USERNAME})

    def run(self, target: str, result: ScanResult) -> None:
        headers = {"Accept": "application/vnd.github+json"}
        if token := self.config.key("github"):
            headers["Authorization"] = f"Bearer {token}"
        gists = self.http.get_json(f"{API}/users/{target}/gists?per_page=30", headers=headers)
        if not isinstance(gists, list) or not gists:
            return
        result.add("public gists", len(gists), source="github")
        for g in gists[:10]:
            files = ", ".join(list((g.get("files") or {}).keys())[:4])
            result.add(
                f"gist {str(g.get('created_at', ''))[:10]}",
                f"{(g.get('description') or '(no description)')[:70]} [{files}]",
                source="github",
                url=g.get("html_url"),
            )
