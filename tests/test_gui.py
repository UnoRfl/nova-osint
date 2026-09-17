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
