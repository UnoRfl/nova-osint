"""People, organisations, and who is connected to whom.

Everything else in NOVA starts from an identifier - a domain, a handle, an
address - which identifies exactly one thing. This file starts from a **name**,
which identifies a set of people, and that difference drives every decision
here.

The rule these modules are built around
---------------------------------------

**A name match is not an identification.** "Matthew Prince" is a Cloudflare
founder, a wrestler, and an unknown number of people who are neither. So:

* Name lookups return **candidates**, plural, with whatever disambiguates them
  (occupation, description, location, follower count) attached to each.
* A name-derived edge carries ``name-similarity`` (+0.2), which is almost
  nothing - it takes four more independent observations to reach the weight of
  a single verified proof. That is the correct arithmetic, not a hedge.
* Nothing here ever collapses two candidates into one person. Confirming which
  candidate is the right one is the analyst's job, and the graph is built so
  that corroborating evidence arriving later raises the right one on its own.

Relationships
-------------

The second job is edges between *other* entities, not just between the target
and something. ``result.link(a, b, ...)`` draws those, and they are what makes
"who does this person work with" answerable:

``wikidata``    employer, founder, officer, board member, education, spouse -
                curated statements, and corporate hierarchy for a company.
``bluesky``     a real, public, keyless social graph: who someone follows and
                who follows them, plus search by display name.
``social-graph``GitHub followers, following and organisation membership, and
                npm co-maintainers.

Mutual follows are worth more than one-way ones, and the module says so rather
than treating an edge as an edge.
"""

from __future__ import annotations

import urllib.parse
from typing import Any

from ..core.entities import Entity, EntityType
from ..core.models import Confidence, ModuleStatus, ScanResult, Severity, TargetType
from ..core.registry import Module, register

# ---------------------------------------------------------------------------
# wikidata
# ---------------------------------------------------------------------------

WD_API = "https://www.wikidata.org/w/api.php"

#: The claims worth reading, and what each one means for an investigation.
#: ``(property, label, entity type the value becomes, relation, evidence)``.
#: ``None`` as the entity type means "report it, do not make a node of it".
WD_CLAIMS: list[tuple[str, str, EntityType | None, str, str]] = [
    ("P108", "employer", EntityType.ORG, "works-at", "wikidata-claim"),
    ("P169", "chief executive", EntityType.PERSON, "ceo-of", "corporate-officer"),
    ("P112", "founded by", EntityType.PERSON, "founded-by", "corporate-officer"),
    ("P1037", "director", EntityType.PERSON, "directs", "corporate-officer"),
    ("P3320", "board member", EntityType.PERSON, "board-member", "corporate-officer"),
    ("P463", "member of", EntityType.ORG, "member-of", "wikidata-claim"),
    ("P69", "educated at", EntityType.ORG, "educated-at", "wikidata-claim"),
    ("P26", "spouse", EntityType.PERSON, "spouse", "wikidata-claim"),
    ("P749", "parent organisation", EntityType.ORG, "subsidiary-of", "wikidata-claim"),
    ("P355", "subsidiary", EntityType.ORG, "owns", "wikidata-claim"),
    ("P127", "owned by", EntityType.ORG, "owned-by", "wikidata-claim"),
    ("P1830", "owner of", EntityType.ORG, "owns", "wikidata-claim"),
    # Reported, not turned into nodes: these describe the person rather than
    # connecting them to anything, and a node for "male" or "English" would be
    # a hub joining every unrelated subject in the case store.
    ("P106", "occupation", None, "", ""),
    ("P27", "citizenship", None, "", ""),
    ("P159", "headquarters", None, "", ""),
    ("P571", "founded", None, "", ""),
    ("P569", "date of birth", None, "", ""),
    ("P570", "date of death", None, "", ""),
    ("P19", "place of birth", None, "", ""),
    ("P21", "gender", None, "", ""),
    ("P551", "residence", None, "", ""),
    ("P937", "work location", None, "", ""),
    ("P1412", "languages", None, "", ""),
    ("P39", "position held", None, "", ""),
    ("P1477", "birth name", None, "", ""),
]

#: External identifiers, which are the genuinely useful part: they are stable,
#: they belong to exactly one entity, and each one is a pivot somewhere else.
WD_IDENTIFIERS: list[tuple[str, str, EntityType | None]] = [
    ("P2002", "X/Twitter", EntityType.USERNAME),
    ("P2037", "GitHub", EntityType.USERNAME),
    ("P4033", "Mastodon", EntityType.USERNAME),
    ("P2003", "Instagram", EntityType.USERNAME),
    ("P2013", "Facebook", EntityType.USERNAME),
    ("P7085", "TikTok", EntityType.USERNAME),
    ("P2397", "YouTube channel", None),
    ("P3185", "VK", EntityType.USERNAME),
    ("P6634", "LinkedIn", None),
    ("P856", "official website", EntityType.DOMAIN),
    ("P496", "ORCID", None),
    ("P214", "VIAF", None),
    ("P1278", "LEI", None),
    ("P5531", "CIK (SEC)", None),
]


@register
class WikidataModule(Module):
    name = "wikidata"
    title = "Wikidata identity and affiliations"
    description = "Name to candidate people/organisations, their roles and identifiers."
    accepts = frozenset({TargetType.PERSON, TargetType.DOMAIN})

    #: How many name candidates to look at. Five is enough to show that a name is
    #: ambiguous without turning one lookup into twenty requests.
    MAX_CANDIDATES = 5

    def run(self, target: str, result: ScanResult) -> None:
        query = target
        if result.subject is not None and result.subject.etype is not EntityType.PERSON:
            # For a domain, search the registrable name rather than the FQDN:
            # "cloudflare.com" finds nothing, "cloudflare" finds the company.
            query = target.split(".")[0]

        found = self.http.get_json(
            f"{WD_API}?action=wbsearchentities&search={urllib.parse.quote(query)}"
            "&language=en&format=json&limit=10", timeout=20)
        if not isinstance(found, dict):
            result.degrade(ModuleStatus.UNAVAILABLE, "wikidata did not answer with JSON")
            return
        hits = [h for h in found.get("search", []) if isinstance(h, dict)]
        if not hits:
            result.add("wikidata", f"no entity called '{query}'", source="wikidata")
            return

        # Ambiguity is the finding. A reader who sees only the first candidate
        # has been told a name is an identification, which it is not.
        result.add("wikidata candidates", [
            f"{h.get('label')} - {h.get('description') or 'no description'} ({h['id']})"
            for h in hits[:self.MAX_CANDIDATES]
        ], source="wikidata", confidence=Confidence.POSSIBLE,
            severity=Severity.NOTABLE if len(hits) > 1 else Severity.INFO,
            url=f"https://www.wikidata.org/w/index.php?search={urllib.parse.quote(query)}")
        if len(hits) > 1:
            result.add("ambiguity", f"{len(hits)} entities share this name; "
                                    "nothing below identifies which one is yours",
                       source="wikidata", confidence=Confidence.POSSIBLE)

        ids = [h["id"] for h in hits[:self.MAX_CANDIDATES] if h.get("id")]
        entities = self.http.get_json(
            f"{WD_API}?action=wbgetentities&ids={'|'.join(ids)}"
            "&props=claims%7Clabels&languages=en&format=json", timeout=25)
        if not isinstance(entities, dict):
            return
        for qid, payload in (entities.get("entities") or {}).items():
            if isinstance(payload, dict):
                self._entity(qid, payload, result)

    # -- one candidate -------------------------------------------------------

    def _entity(self, qid: str, payload: dict, result: ScanResult) -> None:
        claims = payload.get("claims") or {}
        label = (((payload.get("labels") or {}).get("en") or {}).get("value")) or qid
        url = f"https://www.wikidata.org/wiki/{qid}"

        # Keyed by Q-id, not by label. The label is the ambiguous thing: a
        # candidate whose label equals the search term would otherwise *become*
        # the search term's node, and this person's employer, schools and
        # accounts would attach to a name two people share - the precise error
        # this module exists to avoid. The id in the value is also what lets a
        # reader check the entry rather than take it on trust.
        subject = Entity.make(EntityType.PERSON, f"{label} ({qid})", wikidata=qid)
        if subject is None:
            return
        result.nodes.append(subject)
        if result.subject is not None and subject.eid != result.subject.eid:
            result.link(result.subject, subject, "candidate-for", "name-similarity",
                        url=url, detail=f"{label} ({qid}) shares this name")

        for prop, human, etype, relation, evidence in WD_CLAIMS:
            for value in _claim_values(claims.get(prop)):
                if isinstance(value, dict) and "id" in value:
                    other = self._label(value["id"])
                    if not other:
                        continue
                    result.add(f"{label}: {human}", other, source="wikidata", url=url)
                    if etype is None:
                        continue
                    node = Entity.make(etype, other)
                    if node is not None:
                        result.nodes.append(node)
                        # Between the candidate and the other party, not between
                        # the search term and it: this is what makes the graph
                        # answer "who does this person work with".
                        result.link(subject, node, relation, evidence, url=url,
                                    detail=f"Wikidata {human}")
                elif isinstance(value, dict) and "time" in value:
                    result.add(f"{label}: {human}", str(value["time"])[1:11],
                               source="wikidata", url=url)
                elif isinstance(value, str):
                    result.add(f"{label}: {human}", value, source="wikidata", url=url)

        for prop, human, etype in WD_IDENTIFIERS:
            for value in _claim_values(claims.get(prop)):
                if not isinstance(value, str):
                    continue
                result.add(f"{label}: {human}", value, source="wikidata", url=url,
                           severity=Severity.HIGH)
                if etype is None:
                    continue
                if etype is EntityType.DOMAIN:
                    # The official-website claim is a full URL. Taking the last
                    # path segment turned http://x.com/index.html into the
                    # "domain" index.html, which canonicalises happily because
                    # it contains a dot and is entirely wrong.
                    from ..core.http import hostname_of

                    host = hostname_of(value)
                    node = Entity.make(EntityType.DOMAIN, host) if host else None
                else:
                    node = Entity.make(etype, value)
                if node is not None:
                    result.nodes.append(node)
                    result.link(subject, node, "declared-account", "wikidata-claim",
                                url=url, detail=f"{human} on the Wikidata entry")

    def _label(self, qid: str) -> str:
        """Resolve a Q-id to its English label. Cached by the HTTP layer."""
        data = self.http.get_json(
            f"{WD_API}?action=wbgetentities&ids={qid}&props=labels&languages=en"
            "&format=json", timeout=15)
        if not isinstance(data, dict):
            return ""
        entity = (data.get("entities") or {}).get(qid) or {}
        return (((entity.get("labels") or {}).get("en") or {}).get("value")) or ""


def _claim_values(claims: Any) -> list[Any]:
    if not isinstance(claims, list):
        return []
    out = []
    for claim in claims[:6]:
        snak = (claim or {}).get("mainsnak") or {}
        value = (snak.get("datavalue") or {}).get("value")
        if value is not None:
            out.append(value)
    return out


# ---------------------------------------------------------------------------
# bluesky
# ---------------------------------------------------------------------------

BSKY = "https://public.api.bsky.app/xrpc"


@register
class BlueskyModule(Module):
    name = "bluesky"
    title = "Bluesky profile and social graph"
    description = "Search by display name; who an account follows and who follows it."
    accepts = frozenset({TargetType.PERSON, TargetType.USERNAME})

    #: Enough to show the shape of someone's network without pulling thousands
    #: of edges that would swamp the graph and tell you nothing.
    GRAPH_LIMIT = 40

    def run(self, target: str, result: ScanResult) -> None:
        if result.subject is not None and result.subject.etype is EntityType.PERSON:
            self._by_name(target, result)
        else:
            self._by_handle(target, result)

    def _by_name(self, name: str, result: ScanResult) -> None:
        data = self.http.get_json(
            f"{BSKY}/app.bsky.actor.searchActors?q={urllib.parse.quote(name)}&limit=10",
            timeout=20)
        if not isinstance(data, dict):
            result.degrade(ModuleStatus.UNAVAILABLE, "bluesky did not answer with JSON")
            return
        actors = [a for a in data.get("actors", []) if isinstance(a, dict)]
        exact = [a for a in actors
                 if (a.get("displayName") or "").casefold() == name.casefold()]
        if not actors:
            result.add("bluesky", f"no account with a display name like '{name}'",
                       source="bluesky")
            return
        result.add("bluesky candidates", [
            f"@{a.get('handle')} - {a.get('displayName') or 'no display name'}"
            for a in actors[:10]], source="bluesky", confidence=Confidence.POSSIBLE,
            severity=Severity.NOTABLE)
        if len(exact) > 1:
            result.add("ambiguity", f"{len(exact)} Bluesky accounts use exactly this "
                                    "display name; a display name is not unique",
                       source="bluesky", confidence=Confidence.POSSIBLE)
        for actor in (exact or actors)[:5]:
            handle = actor.get("handle")
            if not handle:
                continue
            result.entity(EntityType.USERNAME, handle, relation="possible-account",
                          evidence="name-similarity",
                          url=f"https://bsky.app/profile/{handle}",
                          detail=f"display name '{actor.get('displayName')}'")
            self._stem(handle, actor, result)

    def _stem(self, handle: str, actor: dict, result: ScanResult) -> None:
        """Also emit the bare handle, so independent sources can corroborate.

        A Bluesky handle is a domain - ``eastdakota.com`` or
        ``someone.bsky.social`` - while every other platform uses the bare stem.
        Left alone, a handle Wikidata declares and the same handle found here
        become two unconnected nodes and the corroboration is invisible.

        Emitting the stem lets the two observations land on one node, where the
        log-odds add. That is the whole point of the scoring: the account two
        independent sources agree on should outrank the ones only one saw, and
        it does so arithmetically rather than because anything special-cased it.
        """
        stem = handle.split(".")[0]
        if not stem or stem.casefold() == handle.casefold():
            return
        result.entity(EntityType.USERNAME, stem, relation="handle-stem",
                      evidence="handle-derived",
                      url=f"https://bsky.app/profile/{handle}",
                      detail=f"stem of the Bluesky handle {handle}"
                             f" (display name '{actor.get('displayName')}')")

    def _by_handle(self, handle: str, result: ScanResult) -> None:
        profile = self.http.get_json(
            f"{BSKY}/app.bsky.actor.getProfile?actor={urllib.parse.quote(handle)}",
            timeout=20)
        if not isinstance(profile, dict) or not profile.get("did"):
            result.add("bluesky", "no such account", source="bluesky")
            return
        url = f"https://bsky.app/profile/{profile.get('handle', handle)}"
        for key, label, sev in (("displayName", "display name", Severity.NOTABLE),
                                ("description", "bio", Severity.INFO),
                                ("createdAt", "account created", Severity.NOTABLE)):
            if profile.get(key):
                result.add(f"bluesky {label}", str(profile[key])[:300],
                           source="bluesky", url=url, severity=sev)
        result.add("bluesky counts",
                   f"{profile.get('followersCount', 0)} followers, "
                   f"{profile.get('followsCount', 0)} following, "
                   f"{profile.get('postsCount', 0)} posts", source="bluesky", url=url)
        # The DID is the stable identity; the handle is a rented domain name and
        # changes. Recording both is what lets a renamed account still match.
        result.add("bluesky DID", profile["did"], source="bluesky", url=url,
                   severity=Severity.HIGH, confidence=Confidence.CONFIRMED)
        if name := profile.get("displayName"):
            result.entity(EntityType.PERSON, name, relation="display-name",
                          evidence="name-similarity", url=url)

        follows = self._handles(f"{BSKY}/app.bsky.graph.getFollows"
                                f"?actor={urllib.parse.quote(handle)}"
                                f"&limit={self.GRAPH_LIMIT}", "follows")
        followers = self._handles(f"{BSKY}/app.bsky.graph.getFollowers"
                                  f"?actor={urllib.parse.quote(handle)}"
                                  f"&limit={self.GRAPH_LIMIT}", "followers")
        mutual = follows & followers
        if follows:
            result.add("bluesky follows", sorted(follows)[:40], source="bluesky", url=url)
        if followers:
            result.add("bluesky followers", sorted(followers)[:40], source="bluesky",
                       url=url)
        if mutual:
            # A mutual follow is a relationship; a one-way follow is an interest.
            # Scoring them the same is how a social graph turns into noise.
            result.add("bluesky mutuals", sorted(mutual), source="bluesky", url=url,
                       severity=Severity.NOTABLE, confidence=Confidence.LIKELY)

        me = result.subject
        for other in sorted(follows | followers):
            node = Entity.make(EntityType.USERNAME, other)
            if node is None or me is None:
                continue
            result.nodes.append(node)
            if other in mutual:
                result.link(me, node, "mutual-follow", "mutual-follow", url=url,
                            detail="follow each other on Bluesky")
            elif other in follows:
                result.link(me, node, "follows", "social-follow", url=url,
                            detail="follows on Bluesky")
            else:
                result.link(node, me, "follows", "social-follow", url=url,
                            detail="follows them on Bluesky")

    def _handles(self, url: str, key: str) -> set[str]:
        data = self.http.get_json(url, timeout=20)
        if not isinstance(data, dict):
            return set()
        return {a.get("handle") for a in data.get(key, [])
                if isinstance(a, dict) and a.get("handle")
                and a.get("handle") != "handle.invalid"}


# ---------------------------------------------------------------------------
# github social graph
# ---------------------------------------------------------------------------

GH = "https://api.github.com"


@register
class SocialGraphModule(Module):
    name = "social-graph"
    title = "Account relationships"
    description = "GitHub followers, following and orgs; npm co-maintainers."
    accepts = frozenset({TargetType.USERNAME})
    slow = True

    LIMIT = 60

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github+json"}
        if token := self.config.key("github"):
            h["Authorization"] = f"Bearer {token}"
        return h

    def run(self, target: str, result: ScanResult) -> None:
        me = result.subject
        followers = self._logins(f"{GH}/users/{target}/followers?per_page={self.LIMIT}")
        following = self._logins(f"{GH}/users/{target}/following?per_page={self.LIMIT}")
        if followers is None and following is None:
            result.degrade(ModuleStatus.UNAVAILABLE,
                           "GitHub did not answer - rate limited without GITHUB_TOKEN?")
            return
        followers, following = followers or set(), following or set()
        mutual = followers & following
        url = f"https://github.com/{target}"

        if followers:
            result.add("github followers", sorted(followers)[:40], source="github",
                       url=f"{url}?tab=followers")
        if following:
            result.add("github following", sorted(following)[:40], source="github",
                       url=f"{url}?tab=following")
        if mutual:
            result.add("github mutuals", sorted(mutual), source="github",
                       severity=Severity.NOTABLE, confidence=Confidence.LIKELY,
                       url=url)
        if not (followers or following):
            result.add("github social graph", "no public followers or following",
                       source="github")

        for other in sorted(followers | following):
            node = Entity.make(EntityType.USERNAME, other)
            if node is None or me is None:
                continue
            result.nodes.append(node)
            if other in mutual:
                result.link(me, node, "mutual-follow", "mutual-follow", url=url,
                            detail="follow each other on GitHub")
            elif other in following:
                result.link(me, node, "follows", "social-follow", url=url,
                            detail="follows on GitHub")
            else:
                result.link(node, me, "follows", "social-follow", url=url,
                            detail="follows them on GitHub")

        self._orgs(target, result)
        self._npm(target, result)

    def _orgs(self, user: str, result: ScanResult) -> None:
        orgs = self.http.get_json(f"{GH}/users/{user}/orgs?per_page=100",
                                  headers=self._headers(), timeout=20)
        if not isinstance(orgs, list) or not orgs:
            return
        me = result.subject
        for org in orgs:
            login = (org or {}).get("login")
            if not login:
                continue
            node = Entity.make(EntityType.ORG, login)
            if node is None or me is None:
                continue
            result.nodes.append(node)
            result.link(me, node, "member-of", "org-member",
                        url=f"https://github.com/{login}",
                        detail="public GitHub organisation membership")
            # Fellow public members are colleagues. Public membership is opt-in,
            # so this is a deliberate association, not an inference.
            for peer in self._logins(f"{GH}/orgs/{login}/members?per_page=30") or set():
                if peer.casefold() == user.casefold():
                    continue
                peer_node = Entity.make(EntityType.USERNAME, peer)
                if peer_node is None:
                    continue
                result.nodes.append(peer_node)
                result.link(me, peer_node, "shares-org", "org-member",
                            url=f"https://github.com/orgs/{login}/people",
                            detail=f"both public members of {login}")

    def _npm(self, user: str, result: ScanResult) -> None:
        data = self.http.get_json(
            f"https://registry.npmjs.org/-/v1/search?text=maintainer:{user}&size=20",
            timeout=20)
        if not isinstance(data, dict):
            return
        me = result.subject
        peers: dict[str, str] = {}
        for obj in data.get("objects", []):
            pkg = (obj or {}).get("package") or {}
            for maint in pkg.get("maintainers") or []:
                login = (maint or {}).get("username") or (maint or {}).get("name")
                if login and login.casefold() != user.casefold():
                    peers.setdefault(login, pkg.get("name", "?"))
        if not peers:
            return
        result.add("npm co-maintainers", sorted(peers), source="npm",
                   severity=Severity.NOTABLE,
                   url=f"https://www.npmjs.com/~{user}")
        for peer, pkg in sorted(peers.items()):
            node = Entity.make(EntityType.USERNAME, peer)
            if node is None or me is None:
                continue
            result.nodes.append(node)
            result.link(me, node, "co-maintains", "co-maintainer",
                        url=f"https://www.npmjs.com/package/{pkg}",
                        detail=f"both publish {pkg}")

    def _logins(self, url: str) -> set[str] | None:
        data = self.http.get_json(url, headers=self._headers(), timeout=20)
        if not isinstance(data, list):
            return None
        return {u.get("login") for u in data if isinstance(u, dict) and u.get("login")}
