"""Driving a real browser on the operator's own machine, visibly and politely.

Some public information is only reachable through a browser: a page that
builds itself in JavaScript, a site with no API, a result list that a plain
HTTP client is served a stub of. NOVA's answer is not to imitate a browser
from Python - a spoofed user-agent is a lie the tool has always refused to
tell - but to *use* one, on the operator's machine, under their eye.

What this layer will not do
---------------------------

It will not solve a CAPTCHA, log in, click through a consent wall, defeat a
paywall, or touch a private account. When a page needs a person, the page
object comes back with :attr:`Page.human_action` set, the reason named, and
the URL printed so the operator can finish it themselves in ten seconds. That
is a better outcome than a tool that gets past it, because the operator stays
the one deciding what they are entitled to look at.

It will not read the operator's browsing data. The default profile is a fresh
temporary directory that is deleted afterwards. A persistent profile is
opt-in, and even then nothing here reads cookies, passwords, tokens or
history out of it - the target is publicly visible content.

Optional by construction
------------------------

Nothing heavy is imported at module scope. With no Playwright and no Selenium
installed, :func:`open_browser` returns :class:`NullBrowser`, every call
returns an `unavailable` page naming the URL to open by hand, and the rest of
the investigation continues. That is the same contract every optional
dependency in this project has: absence is a coverage gap, never a traceback.
"""

from __future__ import annotations

import logging
import shutil
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .acquisition import Acquisition, Method, SourceType

log = logging.getLogger(__name__)

__all__ = ["Page", "BrowserProvider", "NullBrowser", "PlaywrightBrowser",
           "SeleniumBrowser", "open_browser", "available_backends",
           "CHALLENGE_MARKERS", "detect_challenge"]


#: Text that means "a person is required here". Detection only - there is no
#: code path in this project that acts on one of these beyond reporting it.
CHALLENGE_MARKERS = (
    "captcha", "recaptcha", "hcaptcha", "are you a robot",
    "verify you are human", "verifying you are human", "unusual traffic",
    "cf-browser-verification", "checking your browser",
    "please enable javascript and cookies", "access denied",
    "sign in to continue", "log in to continue", "create an account to continue",
    "subscribe to read", "you have reached your article limit",
)

#: A marker plus the word that says which *kind* of wall it is, so the report
#: can tell an operator whether the fix is a click or an account.
_KINDS = (
    (("captcha", "recaptcha", "hcaptcha", "are you a robot",
      "verify you are human", "verifying you are human", "unusual traffic",
      "cf-browser-verification", "checking your browser"), "bot check"),
    (("sign in to continue", "log in to continue",
      "create an account to continue"), "login wall"),
    (("subscribe to read", "you have reached your article limit"), "paywall"),
    (("please enable javascript and cookies",), "consent or script wall"),
    (("access denied",), "refusal"),
)


def detect_challenge(text: str, title: str = "") -> str:
    """The kind of wall this page is, or "" if it is an ordinary page.

    Checked against the first few thousand characters only: a page that merely
    *mentions* CAPTCHAs in its body - a security blog, say - is not a
    challenge, and scanning the whole document turns every such article into a
    false refusal.
    """
    low = (title + "\n" + text[:4000]).lower()
    for markers, kind in _KINDS:
        if any(m in low for m in markers):
            return kind
    return ""


@dataclass
class Page:
    """What a browser saw, in the shape the rest of NOVA already understands.

    Deliberately duck-typed like ``http.Response`` - it has ``ok``, ``status``,
    ``access`` and ``describe()`` - so the router, the health manager and the
    evidence store handle a browser page without any of them learning a second
    vocabulary.
    """

    url: str
    final_url: str = ""
    status: int = 0
    title: str = ""
    text: str = ""
    html: str = ""
    canonical: str = ""
    links: list[tuple[str, str]] = field(default_factory=list)
    screenshot: str | None = None
    redirects: list[str] = field(default_factory=list)
    #: Set when the page needs a person. NOVA stops here, every time.
    human_action: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error and not self.human_action and bool(self.text or self.html)

    @property
    def access(self) -> Any:
        from .http import AccessStatus

        if self.human_action:
            return AccessStatus.HUMAN_ACTION_REQUIRED
        if self.error:
            return AccessStatus.UNAVAILABLE
        if self.status and self.status >= 400:
            from .http import classify

            return classify(self.status)
        return AccessStatus.OK

    def describe(self) -> str:
        if self.human_action:
            return f"{self.human_action} - open {self.url} yourself to continue"
        if self.error:
            return f"browser: {self.error}"
        return f"ok (HTTP {self.status})" if self.status else "ok"

    def acquisition(self, provider: str, query: str | None = None,
                    evidence: str | None = None) -> Acquisition:
        return Acquisition(
            method=Method.BROWSER, provider=provider, url=self.url,
            query=query, status=self.status, evidence=evidence,
            source_type=SourceType.WEBSITE,
            detail=(f"redirected to {self.final_url}"
                    if self.final_url and self.final_url != self.url else ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url, "final_url": self.final_url, "status": self.status,
            "title": self.title, "canonical": self.canonical,
            "text_length": len(self.text), "links": len(self.links),
            "screenshot": self.screenshot, "redirects": self.redirects,
            "human_action": self.human_action, "error": self.error,
        }


@dataclass
class BrowserOptions:
    """How the browser should be started."""

    headless: bool = True
    #: A directory to keep between runs. Empty means a temporary profile that
    #: is deleted on close - the default, because a shared profile is how a
    #: tool ends up carrying somebody's logged-in sessions into a scan.
    profile: str = ""
    #: "chrome", "msedge", "chromium" - the operator's installed browser.
    channel: str = "chrome"
    timeout: float = 20.0
    #: Pause and let the operator act when a page needs it, rather than
    #: reporting and moving on. Only meaningful with headless off.
    interactive: bool = False
    screenshots: bool = True
    screenshot_dir: str = ""
    user_agent: str = ""


class BrowserProvider:
    """The six operations every backend implements.

    A base class rather than a Protocol because :class:`NullBrowser` inherits
    most of its behaviour from here: the honest "no browser" answers are the
    same answers a failed backend should give.
    """

    name = "browser"
    available = False

    def __init__(self, options: BrowserOptions | None = None) -> None:
        self.options = options or BrowserOptions()
        self._temp_profile: str | None = None

    # -- lifecycle ----------------------------------------------------------

    def open(self) -> bool:
        """Start the browser. False means it could not be started."""
        return False

    def close(self) -> None:
        self._discard_temp_profile()

    def __enter__(self) -> BrowserProvider:
        self.open()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- the four verbs -----------------------------------------------------

    def navigate(self, url: str) -> Page:
        return self._unavailable(url)

    def search(self, query: str, engine: str = "duckduckgo") -> Page:
        return self.navigate(search_url(query, engine))

    def extract(self, page: Page) -> dict[str, Any]:
        """Structured fields from a page NOVA already has.

        Pure, so it works identically on a stored page during replay. The
        browser backends do not override this - what they differ in is how the
        page was obtained, not what it means.
        """
        return {
            "title": page.title,
            "canonical": page.canonical or page.final_url or page.url,
            "text": page.text,
            "links": page.links,
            "status": page.status,
        }

    def capture(self, page: Page, name: str = "") -> str | None:
        """Path to a screenshot of the current page, if one was taken."""
        return page.screenshot

    # -- helpers ------------------------------------------------------------

    def _unavailable(self, url: str, reason: str = "") -> Page:
        return Page(url=url,
                    error=reason or "no browser backend available "
                                    "(pip install playwright, then: playwright install chromium)")

    def _profile_dir(self) -> str:
        if self.options.profile:
            Path(self.options.profile).mkdir(parents=True, exist_ok=True)
            return self.options.profile
        if self._temp_profile is None:
            self._temp_profile = tempfile.mkdtemp(prefix="nova-browser-")
        return self._temp_profile

    def _discard_temp_profile(self) -> None:
        if self._temp_profile:
            shutil.rmtree(self._temp_profile, ignore_errors=True)
            self._temp_profile = None

    def _shot_path(self, name: str) -> Path:
        base = Path(self.options.screenshot_dir or tempfile.gettempdir())
        base.mkdir(parents=True, exist_ok=True)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:80]
        return base / f"nova-{safe or 'page'}.png"


class NullBrowser(BrowserProvider):
    """Always present. Every call reports the URL a person could open."""

    name = "none"
    available = True   # available as an *answer*, not as a browser

    def open(self) -> bool:
        return False

    def navigate(self, url: str) -> Page:
        return self._unavailable(url)


class PlaywrightBrowser(BrowserProvider):
    """The preferred backend: drives the operator's installed Chromium."""

    name = "playwright"

    def __init__(self, options: BrowserOptions | None = None) -> None:
        super().__init__(options)
        self._pw: Any = None
        self._context: Any = None

    @staticmethod
    def installed() -> bool:
        try:
            import playwright.sync_api  # noqa: F401
        except Exception:  # noqa: BLE001 - any import problem means "no"
            return False
        return True

    def open(self) -> bool:
        if self._context is not None:
            return True
        try:
            from playwright.sync_api import sync_playwright
        except Exception as exc:  # noqa: BLE001
            log.info("playwright not importable: %s", exc)
            return False

        try:
            self._pw = sync_playwright().start()
            kwargs: dict[str, Any] = {"headless": self.options.headless}
            if self.options.channel:
                kwargs["channel"] = self.options.channel
            try:
                self._context = self._pw.chromium.launch_persistent_context(
                    self._profile_dir(), **kwargs)
            except Exception:  # noqa: BLE001 - named channel may not be installed
                kwargs.pop("channel", None)
                self._context = self._pw.chromium.launch_persistent_context(
                    self._profile_dir(), **kwargs)
            # The honest identity rule applies here too: NOVA appends its own
            # name to whatever the real browser reports rather than pretending
            # to be a browser it is not.
            if self.options.user_agent:
                self._context.set_extra_http_headers(
                    {"user-agent": self.options.user_agent})
            self.available = True
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("could not start playwright: %s", exc)
            self.close()
            return False

    def close(self) -> None:
        for obj, what in ((self._context, "context"), (self._pw, "playwright")):
            if obj is None:
                continue
            try:
                obj.close() if what == "context" else obj.stop()
            except Exception:  # noqa: BLE001 - shutdown must not raise
                pass
        self._context = None
        self._pw = None
        self.available = False
        super().close()

    def navigate(self, url: str) -> Page:
        if self._context is None and not self.open():
            return self._unavailable(url)
        page = Page(url=url)
        tab = None
        try:
            tab = self._context.new_page()
            redirects: list[str] = []
            tab.on("response", lambda r: redirects.append(r.url)
                   if 300 <= r.status < 400 else None)
            resp = tab.goto(url, timeout=self.options.timeout * 1000,
                            wait_until="domcontentloaded")
            page.status = int(getattr(resp, "status", 0) or 0)
            page.final_url = tab.url
            page.redirects = redirects
            page.title = tab.title() or ""
            page.html = tab.content()
            page.text = tab.inner_text("body") if tab.query_selector("body") else ""
            page.canonical = _canonical_from(tab)
            page.links = _links_from(tab)

            kind = detect_challenge(page.text, page.title)
            if kind:
                page.human_action = kind
                log.info("%s at %s - stopping, not working around it", kind, url)

            if self.options.screenshots:
                shot = self._shot_path(urllib.parse.urlsplit(url).netloc
                                       + urllib.parse.urlsplit(url).path)
                tab.screenshot(path=str(shot), full_page=False)
                page.screenshot = str(shot)
        except Exception as exc:  # noqa: BLE001 - a page must not end a run
            page.error = f"{type(exc).__name__}: {exc}"
        finally:
            if tab is not None:
                try:
                    tab.close()
                except Exception:  # noqa: BLE001
                    pass
        return page


class SeleniumBrowser(BrowserProvider):
    """Compatibility backend for operators who already run Selenium."""

    name = "selenium"

    def __init__(self, options: BrowserOptions | None = None) -> None:
        super().__init__(options)
        self._driver: Any = None

    @staticmethod
    def installed() -> bool:
        try:
            import selenium.webdriver  # noqa: F401
        except Exception:  # noqa: BLE001
            return False
        return True

    def open(self) -> bool:
        if self._driver is not None:
            return True
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
        except Exception as exc:  # noqa: BLE001
            log.info("selenium not importable: %s", exc)
            return False
        try:
            opts = Options()
            if self.options.headless:
                opts.add_argument("--headless=new")
            opts.add_argument(f"--user-data-dir={self._profile_dir()}")
            self._driver = webdriver.Chrome(options=opts)
            self._driver.set_page_load_timeout(self.options.timeout)
            self.available = True
            return True
        except Exception as exc:  # noqa: BLE001
            log.warning("could not start selenium: %s", exc)
            return False

    def close(self) -> None:
        if self._driver is not None:
            try:
                self._driver.quit()
            except Exception:  # noqa: BLE001
                pass
            self._driver = None
        self.available = False
        super().close()

    def navigate(self, url: str) -> Page:
        if self._driver is None and not self.open():
            return self._unavailable(url)
        page = Page(url=url)
        try:
            self._driver.get(url)
            page.final_url = self._driver.current_url
            page.title = self._driver.title or ""
            page.html = self._driver.page_source or ""
            body = self._driver.find_elements("tag name", "body")
            page.text = body[0].text if body else ""
            page.links = [(a.get_attribute("href") or "", (a.text or "").strip())
                          for a in self._driver.find_elements("tag name", "a")[:300]]
            page.links = [(h, t) for h, t in page.links if h]
            page.status = 200 if page.html else 0
            kind = detect_challenge(page.text, page.title)
            if kind:
                page.human_action = kind
            if self.options.screenshots:
                shot = self._shot_path(urllib.parse.urlsplit(url).netloc)
                self._driver.save_screenshot(str(shot))
                page.screenshot = str(shot)
        except Exception as exc:  # noqa: BLE001
            page.error = f"{type(exc).__name__}: {exc}"
        return page


def _canonical_from(tab: Any) -> str:
    try:
        el = tab.query_selector("link[rel=canonical]")
        return (el.get_attribute("href") or "") if el else ""
    except Exception:  # noqa: BLE001
        return ""


def _links_from(tab: Any, limit: int = 300) -> list[tuple[str, str]]:
    try:
        out = []
        for a in tab.query_selector_all("a[href]")[:limit]:
            href = a.get_attribute("href") or ""
            if href.startswith(("http://", "https://")):
                out.append((href, (a.inner_text() or "").strip()))
        return out
    except Exception:  # noqa: BLE001
        return []


#: Where a browser-driven search goes. These are the ordinary human search
#: pages: this is a person's own browser opening a search box, which is what
#: the operator would do by hand, and NOVA does nothing here that a person
#: sitting at the machine would not.
SEARCH_URLS = {
    "duckduckgo": "https://duckduckgo.com/?q={q}",
    "bing": "https://www.bing.com/search?q={q}",
    "google": "https://www.google.com/search?q={q}",
    "mojeek": "https://www.mojeek.com/search?q={q}",
    "startpage": "https://www.startpage.com/sp/search?query={q}",
    "brave": "https://search.brave.com/search?q={q}",
}


def search_url(query: str, engine: str = "duckduckgo") -> str:
    template = SEARCH_URLS.get(engine, SEARCH_URLS["duckduckgo"])
    return template.format(q=urllib.parse.quote(query))


def available_backends() -> list[str]:
    """Which backends this machine could actually start, best first."""
    found = []
    if PlaywrightBrowser.installed():
        found.append("playwright")
    if SeleniumBrowser.installed():
        found.append("selenium")
    return found


def open_browser(options: BrowserOptions | None = None,
                 prefer: str = "") -> BrowserProvider:
    """The best backend that will actually start, or :class:`NullBrowser`.

    Never raises and never returns None: a caller that has to guard every
    browser call with a try and a None check will eventually forget one, and
    the failure will look like an empty result rather than a missing browser.
    """
    options = options or BrowserOptions()
    order = [prefer] if prefer else []
    order += [b for b in ("playwright", "selenium") if b not in order]
    for name in order:
        cls = {"playwright": PlaywrightBrowser, "selenium": SeleniumBrowser}.get(name)
        if cls is None or not cls.installed():
            continue
        browser = cls(options)
        if browser.open():
            log.info("browser backend: %s", name)
            return browser
        browser.close()
    log.info("no browser backend available; continuing without one")
    return NullBrowser(options)
