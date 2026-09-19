"""Desktop app tests.

These need a display, so the whole module skips where there is none - a
headless CI runner, a bare container, SSH without X. Nothing here makes a
network request: the boot worker is never started, and the console is driven
with synthetic results.
"""

from __future__ import annotations

import tkinter as tk

import pytest

from nova_osint.core.models import (
    Confidence,
    Investigation,
    ScanResult,
    Severity,
    TargetType,
)


@pytest.fixture(scope="module")
def root():
    try:
        r = tk.Tk()
    except tk.TclError:
        pytest.skip("no display available")
    r.withdraw()
    yield r
    try:
        r.destroy()
    except Exception:
        pass


@pytest.fixture
def themed(root):
    from nova_osint.gui import theme

    theme.install(root)
    return root


# ------------------------------------------------------------------------ theme


def test_blend_endpoints_and_midpoint() -> None:
    from nova_osint.gui import theme

    assert theme.blend("#ff0000", "#0000ff", 0.0) == "#ff0000"
    assert theme.blend("#ff0000", "#0000ff", 1.0) == "#0000ff"
    assert theme.blend("#000000", "#ffffff", 0.5) == "#808080"


def test_every_theme_colour_is_a_hex_triplet() -> None:
    from nova_osint.gui import theme

    for name in ("BG", "BG_PANEL", "INK", "CYAN", "MAGENTA", "HIGH", "OK"):
        value = getattr(theme, name)
        assert value.startswith("#") and len(value) == 7
        int(value[1:], 16)


def test_install_returns_usable_fonts(themed) -> None:
    from nova_osint.gui import theme

    fonts = theme.Fonts(themed)
    assert fonts.mono.actual("size") > 0
    assert fonts.title.actual("weight") == "bold"


# ------------------------------------------------------------------------ orbit


def test_orbit_draws_and_stops_cleanly(themed) -> None:
    from nova_osint.gui.orbit import OrbitCanvas

    canvas = OrbitCanvas(themed, width=320, height=200)
    canvas.draw(0.0)
    first = len(canvas.find_all())
    assert first > 50  # starfield + rings + bodies

    canvas.draw(1.0)
    canvas.start()
    themed.update()
    canvas.stop()
    assert canvas._job is None
    canvas.destroy()


def test_every_planet_has_a_draw_style() -> None:
    from nova_osint.core.art import PLANETS
    from nova_osint.gui.orbit import PLANET_STYLE

    # orbit.py keys off core.art's planet table; a new body added there without
    # a style entry would blow up mid-animation rather than at import.
    assert {p[0] for p in PLANETS} == set(PLANET_STYLE)


def test_wordmark_renders(themed) -> None:
    from nova_osint.gui.orbit import WORDMARK, Wordmark

    mark = Wordmark(themed)
    assert len(mark.find_all()) == len(WORDMARK)
    mark.destroy()


# ---------------------------------------------------------------------- console


def _result() -> ScanResult:
    res = ScanResult(module="dns", target="example.com", target_type=TargetType.DOMAIN)
    res.add("A", ["1.2.3.4", "5.6.7.8"], source="doh")
    res.add("SPF", "missing", source="doh", severity=Severity.HIGH)
    res.add("link", "see here", source="x", url="https://example.com",
            confidence=Confidence.POSSIBLE)
    res.error("a source was flaky")
    res.duration = 1.25
    return res


@pytest.fixture
def console(themed):
    from nova_osint.gui.console import ConsoleScreen

    screen = ConsoleScreen(themed, {"config": None})
    themed.update_idletasks()
    yield screen
    screen.destroy()


def test_target_type_drives_the_instrument_list(console, themed) -> None:
    console.entry.delete(0, "end")
    console.entry.insert(0, "example.com")
    themed.update_idletasks()
    assert console.current_type is TargetType.DOMAIN
    assert "dns" in console.module_vars and "whois" in console.module_vars
    assert "phone" not in console.module_vars

    console.entry.delete(0, "end")
    console.entry.insert(0, "+442079460958")
    themed.update_idletasks()
    assert console.current_type is TargetType.PHONE
    assert "phone" in console.module_vars
    assert "dns" not in console.module_vars


def test_placeholder_is_not_treated_as_a_target(console) -> None:
    from nova_osint.gui.console import PLACEHOLDER

    assert console.entry.get() == PLACEHOLDER
    assert console._value() == ""
    # The scan button must stay disabled while only the placeholder is present.
    assert str(console.scan_btn["state"]) == "disabled"


def test_results_populate_the_tree_with_severity_tags(console) -> None:
    console._add_result(_result())
    roots = console.tree.get_children()
    assert len(roots) == 1
    rows = console.tree.get_children(roots[0])
    assert len(rows) == 4  # three findings plus the warning

    tags = [console.tree.item(r, "tags")[0] for r in rows]
    assert "high" in tags and "error" in tags
    # A list value is collapsed to a readable string, not repr'd.
    assert "1.2.3.4, 5.6.7.8" in console.tree.item(rows[0], "values")[0]
    assert console._url_by_item[rows[2]] == "https://example.com"


def test_finishing_a_scan_lists_pivots_and_enables_export(console) -> None:
    inv = Investigation(target="example.com", target_type=TargetType.DOMAIN)
    res = _result()
    res.pivot("1.2.3.4", TargetType.IP, "A record")
    inv.results.append(res)

    console._finish(inv)
    assert len(console.pivot_tree.get_children()) == 1
    assert all(str(b["state"]) == "normal" for b in console.export_btns)
    assert console.investigation is inv
    assert not console.scanning


# ---------------------------------------------------------------------- profile


def _social_investigation():
    """A scan that found two social profiles and one unreachable module."""
    from nova_osint.core.entities import Entity, EntityType
    from nova_osint.core.graph import EntityGraph, Observation
    from nova_osint.core.models import ModuleStatus

    inv = Investigation(target="alice", target_type=TargetType.USERNAME)
    res = ScanResult(module="username", target="alice",
                     target_type=TargetType.USERNAME)
    res.add("Instagram", "https://instagram.com/alice", source="username",
            url="https://instagram.com/alice", severity=Severity.NOTABLE)
    res.add("TikTok", "https://www.tiktok.com/@alice", source="username",
            url="https://www.tiktok.com/@alice", severity=Severity.NOTABLE)
    inv.results.append(res)
    dead = ScanResult(module="keybase", target="alice",
                      target_type=TargetType.USERNAME)
    dead.status = ModuleStatus.UNAVAILABLE
    dead.status_reason = "keybase did not answer"
    inv.results.append(dead)

    seed = Entity.make(EntityType.USERNAME, "alice")
    g = EntityGraph(seed)
    g.connect(seed, Entity.make(EntityType.USERNAME, "bob"), "mutual-follow",
              Observation("mutual-follow", "social-graph"))
    g.rescore()
    inv.graph = g
    return inv.finish()


def test_the_result_tabs_are_in_the_order_a_reader_wants_them(console) -> None:
    """Identity, then Dossier, then Profile.

    "Which of these is them" is the question, "what do we know about them" is
    the answer, and everything in the other tabs is the working.
    """
    tabs = [console.notebook.tab(i, "text").strip()
            for i in range(console.notebook.index("end"))]
    assert tabs == ["Findings", "Pivots", "Identity", "Dossier", "Profile",
                    "Live log"]


def test_finishing_a_scan_fills_the_dossier_tab(console) -> None:
    console._finish(_social_investigation())
    text = console.dossierbox.get("1.0", "end")

    assert "IDENTITY" in text
    assert "ACCOUNTS" in text
    assert "COLLECTION GAPS" in text


def test_the_dossier_tab_reports_gaps_rather_than_implying_none(console) -> None:
    """The panel must not be the one place a dead source stops being reported."""
    console._finish(_social_investigation())
    text = console.dossierbox.get("1.0", "end")

    assert "absence here means unknown, not none" in text
    assert "keybase" in text and "did not answer" in text


def test_a_gap_row_never_runs_its_columns_together(console) -> None:
    """``unavailable`` is 11 characters and the column was 10 wide, so the
    status and the reason printed as one word."""
    console._finish(_social_investigation())
    text = console.dossierbox.get("1.0", "end")

    assert "unavailablekeybase" not in text
    assert "unavailable" in text


def test_a_new_dossier_replaces_the_previous_one(console) -> None:
    """A stale dossier under a new target is worse than an empty one."""
    from nova_osint.core.models import Investigation, TargetType

    console._finish(_social_investigation())
    assert "alice" in console.dossierbox.get("1.0", "end")

    console._finish(Investigation(target="nobody@example.com",
                                  target_type=TargetType.EMAIL).finish())
    assert "alice" not in console.dossierbox.get("1.0", "end")


def test_the_dossier_tab_survives_an_empty_scan(console) -> None:
    from nova_osint.core.models import Investigation, TargetType

    console._finish(Investigation(target="nobody@example.com",
                                  target_type=TargetType.EMAIL).finish())
    text = console.dossierbox.get("1.0", "end")
    assert "not established" in text


def test_finishing_a_scan_fills_the_profile_tab(console) -> None:
    console._finish(_social_investigation())
    text = console.profilebox.get("1.0", "end")
    assert "SOCIAL ACCOUNTS" in text
    assert "Instagram" in text and "TikTok" in text
    assert "RELATIONSHIPS" in text and "bob" in text


def test_the_profile_tab_carries_the_coverage_gaps(console) -> None:
    """The panel must not be the one place a dead source stops being reported."""
    console._finish(_social_investigation())
    text = console.profilebox.get("1.0", "end")
    assert "COVERAGE GAPS" in text
    assert "keybase" in text


def test_facebook_is_shown_as_unchecked_rather_than_omitted(console) -> None:
    console._finish(_social_investigation())
    text = console.profilebox.get("1.0", "end")
    assert "Facebook" in text
    assert "nothing was checked" in text


def test_profile_urls_are_registered_as_clickable_links(console) -> None:
    console._finish(_social_investigation())
    urls = set(console._profile_links.values())
    assert "https://instagram.com/alice" in urls
    assert "https://www.tiktok.com/@alice" in urls
    # The shared tag is what gets the cursor and the click binding.
    assert "link" in console.profilebox.tag_names()


def test_the_profile_tab_is_read_only(console) -> None:
    console._finish(_social_investigation())
    assert str(console.profilebox["state"]) == "disabled"


def test_a_broken_profile_does_not_take_the_scan_with_it(console, monkeypatch) -> None:
    """A panel is a view. It must never be able to lose a completed scan."""
    from nova_osint.core import profile as profile_mod

    def explode(_inv, **_kw):
        raise RuntimeError("profile is broken")

    monkeypatch.setattr(profile_mod, "build", explode)
    inv = _social_investigation()
    console._finish(inv)
    assert console.investigation is inv
    assert "could not build the profile" in console.profilebox.get("1.0", "end")
    assert all(str(b["state"]) == "normal" for b in console.export_btns)


# --------------------------------------------------------------- progress

def test_the_spinner_is_hidden_until_something_runs(console) -> None:
    assert not console.spinner.winfo_ismapped()
    assert console.percent["text"] == ""


def test_progress_reports_a_percentage_and_what_is_in_flight(console) -> None:
    console._total = 4
    console._show_progress(1, "dns, whois")
    assert console.percent["text"].strip() == "25%"
    assert "dns, whois" in console.status["text"]


def test_progress_never_exceeds_a_hundred_percent(console) -> None:
    console._total = 2
    console._show_progress(5, "")
    assert console.percent["text"].strip() == "100%"


def test_a_zero_module_scan_does_not_divide_by_zero(console) -> None:
    console._total = 0
    console._show_progress(0, "")
    assert console.percent["text"].strip().endswith("%")


def test_with_nothing_in_flight_it_says_it_is_waiting_not_that_it_is_idle(console):
    """A long scan with one slow module must not look finished or stuck."""
    console._total = 4
    console._show_progress(3, "")
    assert "waiting" in console.status["text"]


def test_stopping_the_spinner_clears_the_percentage(console) -> None:
    console.spinner.grid()
    console.spinner.start()
    console._stop_spinner()
    assert console.percent["text"] == ""
    assert not console.spinner.winfo_ismapped()


def test_finishing_a_scan_stops_the_spinner(console) -> None:
    console.spinner.grid()
    console.spinner.start()
    console._finish(_social_investigation())
    assert not console.spinner.winfo_ismapped()


def test_the_mini_orbit_is_the_same_widget_the_boot_screen_uses(console) -> None:
    """One animation in the app, so it cannot drift out of step with itself."""
    from nova_osint.gui.orbit import OrbitCanvas

    assert isinstance(console.spinner, OrbitCanvas)
    assert console.spinner.speed > console.mini.speed, "the status one spins faster"


# --------------------------------------------------------------------- settings


@pytest.fixture
def settings(themed, tmp_path, monkeypatch):
    """A settings window pointed at a throwaway config file."""
    from nova_osint.core import config as config_mod
    from nova_osint.gui import settings as settings_mod

    monkeypatch.setattr(config_mod, "DEFAULT_CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(settings_mod, "ConfigManager", config_mod.ConfigManager)
    window = settings_mod.SettingsWindow(themed)
    themed.update_idletasks()
    yield window
    try:
        window.destroy()
    except tk.TclError:
        pass


def test_settings_lists_every_key(settings) -> None:
    from nova_osint.core.config import KEY_ENV

    assert set(settings.key_entries) == set(KEY_ENV)


def test_a_stored_key_is_masked_never_rendered(themed, tmp_path, monkeypatch) -> None:
    import json

    from nova_osint.core import config as config_mod
    from nova_osint.gui import settings as settings_mod

    path = tmp_path / "config.json"
    path.write_text(json.dumps({"api_keys": {"virustotal": "the-real-secret"}}), "utf-8")
    monkeypatch.setattr(config_mod, "DEFAULT_CONFIG_PATH", path)
    monkeypatch.delenv("VT_API_KEY", raising=False)

    window = settings_mod.SettingsWindow(themed)
    themed.update_idletasks()
    try:
        shown = window.key_entries["virustotal"].get()
        assert "the-real-secret" not in shown
        assert shown == settings_mod.MASK

        # Saving without touching the field must not wipe the stored key.
        window._save()
        assert json.loads(path.read_text("utf-8"))["api_keys"]["virustotal"] \
            == "the-real-secret"
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


def test_typing_a_key_replaces_it_and_saves(settings, tmp_path) -> None:
    import json

    entry = settings.key_entries["virustotal"]
    settings._touch("virustotal")          # what a keystroke does
    entry.insert(0, "brand-new-key")
    settings._save()

    saved = json.loads((tmp_path / "config.json").read_text("utf-8"))
    assert saved["api_keys"]["virustotal"] == "brand-new-key"


def test_an_environment_key_disables_the_field(themed, tmp_path, monkeypatch) -> None:
    from nova_osint.core import config as config_mod
    from nova_osint.gui import settings as settings_mod

    monkeypatch.setattr(config_mod, "DEFAULT_CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setenv("GITHUB_TOKEN", "from-the-environment")

    window = settings_mod.SettingsWindow(themed)
    themed.update_idletasks()
    try:
        entry = window.key_entries["github"]
        assert str(entry["state"]) == "disabled"
        assert "from-the-environment" not in entry.get()
    finally:
        try:
            window.destroy()
        except tk.TclError:
            pass


def test_settings_round_trip_network_values(settings, tmp_path) -> None:
    import json

    settings.field_vars["settings.timeout"].set("25")
    settings.field_vars["settings.max_concurrent_tasks"].set("8")
    settings.toggle_vars["settings.cache_enabled"].set(False)
    settings.st_depth.set("full")
    settings._save()

    saved = json.loads((tmp_path / "config.json").read_text("utf-8"))
    assert saved["settings"]["timeout"] == 25.0
    assert saved["settings"]["max_concurrent_tasks"] == 8
    assert saved["settings"]["cache_enabled"] is False
    assert saved["module_options"]["securitytrails_depth"] == "full"


def test_a_non_numeric_setting_is_refused_not_written(settings, tmp_path) -> None:
    import tkinter.messagebox as mb

    warned: list[tuple] = []
    original = mb.showwarning
    mb.showwarning = lambda *a, **kw: warned.append(a)
    try:
        settings.field_vars["settings.timeout"].set("banana")
        settings._save()
    finally:
        mb.showwarning = original

    assert warned, "a bad number must be reported"
    assert not (tmp_path / "config.json").exists() or \
        "banana" not in (tmp_path / "config.json").read_text("utf-8")


def test_disabling_a_module_is_persisted(settings, tmp_path) -> None:
    import json

    settings.module_vars["dorks"].set(False)
    settings._save()
    saved = json.loads((tmp_path / "config.json").read_text("utf-8"))
    assert saved["modules_enabled"]["dorks"] is False
    assert saved["modules_enabled"]["dns"] is True


def test_console_opens_settings_and_reloads(console, themed, tmp_path, monkeypatch) -> None:
    from nova_osint.core import config as config_mod

    monkeypatch.setattr(config_mod, "DEFAULT_CONFIG_PATH", tmp_path / "config.json")
    console.open_settings()
    themed.update_idletasks()

    window = next(w for w in themed.winfo_children()
                  if w.winfo_class() == "Toplevel" and "Settings" in w.title())
    window._save()
    themed.update_idletasks()
    assert "settings saved" in console.status["text"]


def test_the_orbit_label_is_suppressed_when_there_is_no_room_for_it(themed) -> None:
    """At status-bar size the clipped label reads as a rendering fault."""
    from nova_osint.gui.orbit import OrbitCanvas

    small = OrbitCanvas(themed, width=38, height=38)
    big = OrbitCanvas(themed, width=640, height=380)
    try:
        assert not small.show_label
        assert big.show_label
    finally:
        small.destroy()
        big.destroy()


def test_the_profile_tab_shows_the_biographical_block(console) -> None:
    """And keeps two people who share a name apart, as the CLI does."""
    inv = Investigation(target="Matthew Prince", target_type=TargetType.PERSON)
    res = ScanResult(module="wikidata", target="Matthew Prince",
                     target_type=TargetType.PERSON)
    for label, value in (
        ("Matthew Prince: date of birth", "1974-11-13"),
        ("Matthew Prince: occupation", "entrepreneur"),
        ("Matt Prince: date of birth", "1973-07-13"),
        ("Matt Prince: occupation", "professional wrestler"),
    ):
        res.add(label, value, source="wikidata")
    inv.results.append(res)
    console._finish(inv.finish())

    text = console.profilebox.get("1.0", "end")
    assert "WHO" in text
    assert "Date of birth:" in text and "1974-11-13" in text
    assert "if this is Matthew Prince" in text
    assert "if this is Matt Prince" in text
    # The two must not be welded into one subject.
    founder = text.index("if this is Matthew Prince")
    wrestler = text.index("if this is Matt Prince")
    lo, hi = sorted((founder, wrestler))
    assert text.count("Date of birth:") == 2
    assert "entrepreneur" in text and "professional wrestler" in text
    assert lo < hi


# ------------------------------------------------------------------ the brief


def test_adding_a_fact_makes_a_chip_and_a_claim(console, themed) -> None:
    console.brief_kind.set("city")
    console.brief_value.set("Kuala Lumpur")
    console._add_brief_fact()
    themed.update_idletasks()

    assert console.brief_facts == [("city", "Kuala Lumpur", True)]
    # The entry clears, so the next fact can be typed straight away.
    assert console.brief_value.get() == ""
    chips = [c.cget("text") for c in console.brief_chips.winfo_children()]
    assert any("Kuala Lumpur" in text for text in chips)


def test_clicking_a_chip_removes_that_fact(console, themed) -> None:
    for kind, value in (("city", "London"), ("employer", "Acme")):
        console.brief_kind.set(kind)
        console.brief_value.set(value)
        console._add_brief_fact()
    console._drop_brief_fact(0)
    themed.update_idletasks()
    assert [f[1] for f in console.brief_facts] == ["Acme"]


def test_an_uncertain_fact_is_marked_as_one(console, themed) -> None:
    console.brief_kind.set("city")
    console.brief_value.set("KL")
    console.brief_sure.set(False)
    console._add_brief_fact()
    themed.update_idletasks()
    assert console.brief_facts[0][2] is False
    chips = [c.cget("text") for c in console.brief_chips.winfo_children()]
    assert any("?" in text for text in chips)


def test_the_typed_target_is_folded_into_the_brief(console, themed) -> None:
    """Leaving it out means the strongest evidence on screen confirms nothing."""
    console.entry.delete(0, "end")
    console.entry.insert(0, "ada@example.com")
    console.brief_kind.set("city")
    console.brief_value.set("Cambridge")
    console._add_brief_fact()

    brief = console._current_brief()
    kinds = {c.kind.value for c in brief.claims}
    assert "email" in kinds and "city" in kinds


def test_the_identity_tab_shows_the_workings_and_the_contradictions(console, themed) -> None:
    from nova_osint.core.brief import from_pairs
    from nova_osint.core.entities import Entity, EntityType
    from nova_osint.core.graph import EntityGraph
    from nova_osint.core.identity import resolve

    inv = Investigation(target="Ada Lovelace", target_type=TargetType.PERSON)
    res = ScanResult(module="wikidata", target="Ada Lovelace",
                     target_type=TargetType.PERSON)
    graph = EntityGraph(Entity.make(EntityType.PERSON, "Ada Lovelace"))
    for who, facts in (("Ada Lovelace (Q1)", [("date of birth", "1815-12-10")]),
                       ("Ada Lovelace (Q2)", [("date of birth", "1974-03-02")])):
        graph.add(Entity.make(EntityType.PERSON, who))
        for label, value in facts:
            res.add(f"{who}: {label}", value, source="wikidata")
    inv.results = [res]
    inv.graph = graph
    inv.finish()
    inv.resolution = resolve(inv, from_pairs(["name=Ada Lovelace", "born=1815"]))

    console._render_identity(inv)
    themed.update_idletasks()
    text = console.identbox.get("1.0", "end")
    assert "Q1" in text and "Q2" in text
    # The reasoning is on screen, not just the ranking.
    assert "born" in text
    assert "1815" in text


def test_the_identity_tab_stays_empty_without_a_brief(console, themed) -> None:
    """No brief means no ranking to show, and none invented to fill the space."""
    console._render_identity(_social_investigation())
    themed.update_idletasks()
    assert console.identbox.get("1.0", "end").strip() == ""


def test_every_target_type_has_a_chip_colour(console, themed) -> None:
    """Typing a name used to raise KeyError on every keystroke.

    The trace fires per character, so the window died before the user had
    finished typing - and a name is a documented target type.
    """
    for ttype in TargetType:
        console.entry.delete(0, "end")
        console.entry.insert(0, {
            TargetType.PERSON: "Ada Lovelace",
            TargetType.EMAIL: "ada@example.com",
            TargetType.DOMAIN: "example.com",
            TargetType.USERNAME: "adalovelace",
            TargetType.IP: "8.8.8.8",
            TargetType.PHONE: "+14155552671",
            TargetType.URL: "https://example.com/x",
            TargetType.UNKNOWN: "!!",
        }[ttype])
        themed.update_idletasks()
        assert console.chip.cget("text")


def test_every_target_type_maps_to_a_real_claim_kind() -> None:
    """`USERNAME: "handle"` was in this table and there is no `handle` claim
    kind. Assembling the brief therefore raised ValueError for every handle
    typed into the box - inside a Tk callback, before the worker thread was
    created, with pythonw swallowing the traceback. The window sat at
    "0% · starting …" with no instruments running and no error, forever."""
    from nova_osint.core.brief import ClaimKind
    from nova_osint.gui.console import _BRIEF_KIND_FOR_TYPE

    valid = {k.value for k in ClaimKind}
    for ttype, kind in _BRIEF_KIND_FOR_TYPE.items():
        assert kind in valid, f"{ttype.value} maps to {kind!r}, not a claim kind"


def test_a_brief_can_be_built_for_every_target_type(console, themed) -> None:
    """The end-to-end version of the above: whatever the operator types, the
    brief assembles rather than throwing."""
    for value in ("unorf1", "ada@example.org", "example.com", "Ada Lovelace",
                  "8.8.8.8", "https://example.com", "+442079460958"):
        console.entry.delete(0, "end")
        console.entry.insert(0, value)
        themed.update_idletasks()
        brief = console._current_brief()
        assert brief is not None, f"no brief for {value!r}"


def test_a_bad_extra_fact_does_not_stop_the_scan(console, themed, monkeypatch) -> None:
    """The brief is an enrichment. A bad fact should cost the cross-check,
    not the run."""
    def explode():
        raise ValueError("nope")

    monkeypatch.setattr(console, "_current_brief", explode)
    monkeypatch.setattr(console, "_run", lambda *a, **k: None)
    console.entry.delete(0, "end")
    console.entry.insert(0, "unorf1")
    themed.update_idletasks()
    console.start_scan()
    themed.update_idletasks()
    assert console.scanning, "the scan must still have started"


def test_the_console_can_report_an_error_into_its_own_log(console, themed) -> None:
    """pythonw has no stderr, so the window's exception hook needs somewhere
    to put things. This is it."""
    console.report_error("ValueError: something went wrong")
    themed.update_idletasks()
    assert "something went wrong" in console.logbox.get("1.0", "end")


# ------------------------------------------------------- a panel that cannot draw


def _possible_account_investigation():
    """A scan whose social panel holds a ``possible`` account.

    Four basis values exist; the panel's lookup tables listed three. This is
    the shape of scan that hit it - a username sweep finding a handle nobody
    confirmed the ownership of, which is the *normal* result for a common
    handle rather than an exotic one.
    """
    from nova_osint.core.models import Confidence

    inv = Investigation(target="unorfl", target_type=TargetType.USERNAME)
    res = ScanResult(module="username", target="unorfl",
                     target_type=TargetType.USERNAME)
    res.add("Instagram", "https://instagram.com/unorfl", source="username",
            url="https://instagram.com/unorfl", severity=Severity.NOTABLE,
            confidence=Confidence.POSSIBLE)
    inv.results.append(res)
    return inv.finish()


def test_every_basis_a_social_account_can_carry_has_a_mark(console) -> None:
    """The panel's tables must cover the type, not most of it.

    `KeyError: 'possible'` landed *after* a 313-second scan had finished, on
    the render. Every finding was already collected and the window never came
    back.
    """
    from nova_osint.gui.console import SOCIAL_MARK, SOCIAL_TAG

    for basis in ("confirmed", "declared", "possible", "search"):
        assert basis in SOCIAL_MARK, basis
        assert basis in SOCIAL_TAG, basis


def test_a_basis_nobody_has_invented_yet_still_draws(console) -> None:
    """Read with .get, so the worst a new value can do is look plain."""
    from nova_osint.gui.console import SOCIAL_MARK, SOCIAL_TAG

    assert SOCIAL_MARK.get("something-new", "*") == "*"
    assert SOCIAL_TAG.get("something-new", "plain") == "plain"


def test_a_scan_with_an_unconfirmed_account_finishes_and_resets(console) -> None:
    console._finish(_possible_account_investigation())
    assert not console.scanning
    assert str(console.scan_btn["text"]).strip().endswith("SCAN")


def test_a_panel_that_raises_does_not_strand_the_scan_button(console) -> None:
    """The engine's rule, applied to the renderers.

    A module that raises must not take the other fifteen with it; a *panel*
    that raises must not take the findings, the exports, or the operator's
    ability to start another scan.
    """
    def explode(_inv):
        raise KeyError("possible")

    console._render_profile = explode
    console._finish(_social_investigation())

    assert not console.scanning, "the button was left saying SCANNING"
    assert str(console.scan_btn["text"]).strip().endswith("SCAN")
    assert all(str(b["state"]) == "normal" for b in console.export_btns), \
        "the findings were collected; the exports must still work"
    assert "Profile tab could not be drawn" in console.logbox.get("1.0", "end")


def test_the_other_panels_still_draw_when_one_fails(console) -> None:
    def explode(_inv):
        raise RuntimeError("nope")

    console._render_profile = explode
    console._finish(_social_investigation())
    assert "ACCOUNTS" in console.dossierbox.get("1.0", "end")


def test_the_identity_panel_covers_every_verdict(console) -> None:
    """Same class of bug, one tab over. Checked rather than assumed."""
    from nova_osint.core.identity import Verdict
    from nova_osint.gui.console import ConsoleScreen  # noqa: F401
    import inspect

    src = inspect.getsource(ConsoleScreen._render_identity)
    for verdict in Verdict:
        assert f"Verdict.{verdict.name}" in src, verdict.name
