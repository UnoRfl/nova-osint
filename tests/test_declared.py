"""Offline tests for reading a site's own account and occupation declarations.

No socket: :func:`~nova_osint.core.structured.harvest` takes HTML and a URL and
returns what the page claimed, which is the property that makes the whole
feature arguable on paper.
"""

from __future__ import annotations

from nova_osint.core.structured import harvest, platform_of
from nova_osint.modules.declared import _handle_in

# A page shaped like the ones this was built for: a small business with a
# named owner, several accounts on the platforms no username catalogue can
# check, and a role in a typed field.
SHOP = """<html><head>
<meta property="og:site_name" content="Designs by Racquel">
<meta name="twitter:site" content="@dbracquel">
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
 {"@type":"JewelryStore","name":"Designs by Racquel",
  "telephone":"+65 8123 4567",
  "address":{"@type":"PostalAddress","streetAddress":"12 Orchard Rd",
             "addressLocality":"Singapore","addressCountry":"SG"},
  "sameAs":["https://www.facebook.com/designsbyracquel",
            "https://www.instagram.com/designsbyracquel/",
            "https://www.threads.net/@designsbyracquel",
            "https://x.com/dbracquel"],
  "founder":{"@type":"Person","name":"Racquel Tan","jobTitle":"Goldsmith",
             "email":"mailto:racquel@designsbyracquel.com"}},
 {"@type":"WebSite","url":"https://designsbyracquel.com",
  "sameAs":["https://www.facebook.com/profile.php?id=61551234567890"]}]}
</script>
<link rel="me" href="https://github.com/racqueltan">
</head><body>
<a href="https://wa.me/6580562021?text=Hello%2C%20I%27m%20interested">chat</a>
<a href="https://www.facebook.com/sharer.php?u=https://designsbyracquel.com">share</a>
<div itemscope itemtype="https://schema.org/Person">
  <span itemprop="jobTitle">Bespoke jeweller</span></div>
</body></html>"""


def got():
    return harvest(SHOP, "https://designsbyracquel.com/")


# ---------------------------------------------------------------------------
# the platforms a username sweep cannot reach
# ---------------------------------------------------------------------------


def test_the_walled_platforms_are_found_because_the_subject_published_them():
    """Facebook, Instagram and Threads refuse anonymous checks - and advertise.

    No catalogue can test these, which is why NOVA reported them as *not
    checkable*. The subject listing them in their own markup is the one route
    in, and it needs nobody's permission.
    """
    platforms = got().platforms
    for name in ("Facebook", "Instagram", "Threads", "X / Twitter"):
        assert name in platforms, name


def test_several_accounts_on_one_platform_all_survive():
    """A business has a page *and* a profile; the panel kept one of them."""
    facebook = got().platforms["Facebook"]
    assert len(facebook) == 2
    assert {c.value for c in facebook} == {
        "https://www.facebook.com/designsbyracquel",
        "https://www.facebook.com/profile.php?id=61551234567890",
    }


def test_a_share_button_is_not_an_account():
    """``facebook.com/sharer.php?u=`` points at this site, not at a profile."""
    assert not any("sharer" in c.value for c in got().accounts)


def test_a_declared_account_outranks_a_merely_linked_one():
    out = got()
    declared = {c.value: c.where for c in out.accounts}
    assert declared["https://www.instagram.com/designsbyracquel/"] == "json-ld"
    assert declared["https://github.com/racqueltan"] == "rel-me"
    assert any(w == "link" for w in declared.values())


# ---------------------------------------------------------------------------
# occupation and ownership
# ---------------------------------------------------------------------------


def test_the_owner_of_the_business_is_named_as_its_owner():
    out = got()
    assert [(c.value, c.detail) for c in out.owners] == [
        ("Racquel Tan", "founder of Designs by Racquel")]


def test_a_job_title_keeps_the_person_it_was_said_of():
    """The dossier refuses to pair a role with a company nothing tied it to."""
    roles = {(c.value, c.subject) for c in got().roles}
    assert ("Goldsmith", "Racquel Tan") in roles
    assert ("Bespoke jeweller", "") in roles


def test_a_trading_business_is_a_stronger_claim_than_an_organisation():
    assert got().business_types == ["jewelrystore"]


def test_contact_details_come_off_the_typed_fields():
    out = got()
    assert [c.value for c in out.emails] == ["racquel@designsbyracquel.com"]
    assert "+65 8123 4567" in {c.value for c in out.phones}
    assert any("Orchard" in c.value for c in out.addresses)


# ---------------------------------------------------------------------------
# what most sites actually publish, which is nothing
# ---------------------------------------------------------------------------


def test_a_click_to_chat_link_is_a_phone_number():
    """Measured on the live site: no JSON-LD at all, one footer link.

    Harvesting only the structured formats would have found a site name and
    reported "no accounts", which is the failure this whole module exists to
    stop.
    """
    phones = {c.value for c in got().phones}
    assert "+6580562021" in phones


def test_the_prefilled_message_is_not_part_of_the_number():
    """``?text=Hello%2C%20I%27m`` turned +6580562021 into +658056202122020."""
    for claim in got().phones:
        assert len(claim.value) <= 16, claim.value


def test_a_page_with_no_markup_at_all_reports_nothing_rather_than_guessing():
    empty = harvest("<html><body><p>Hello</p></body></html>", "https://x.test/")
    assert not empty
    assert not empty.formats


def test_malformed_json_in_one_block_does_not_lose_a_good_one():
    """Sites ship three of these from three plugins and one is always broken."""
    page = ('<script type="application/ld+json">{oh no</script>'
            '<script type="application/ld+json">'
            '{"@type":"Person","name":"Ada","jobTitle":"Engineer"}</script>')
    out = harvest(page, "https://x.test/")
    assert [c.value for c in out.people] == ["Ada"]


# ---------------------------------------------------------------------------
# a handle is still not a handle
# ---------------------------------------------------------------------------


def test_a_whatsapp_link_does_not_become_a_username():
    """Caught on the first live run: wa.me/6580562021 became a username entity.

    The 481-site sweep would then have been aimed at a mobile number - the
    same "a name is not a handle" failure in a different costume.
    """
    assert _handle_in("https://wa.me/6580562021?text=hi") == ""


def test_a_numeric_profile_id_does_not_become_a_username():
    assert _handle_in("https://www.facebook.com/profile.php?id=615512345") == ""
    assert _handle_in("https://www.facebook.com/61551234567890") == ""


def test_a_real_handle_still_survives_the_guard():
    assert _handle_in("https://www.instagram.com/designsbyracquel/") == "designsbyracquel"
    assert _handle_in("https://www.linkedin.com/in/racquel-tan") == "racquel-tan"
    assert _handle_in("https://www.threads.net/@dbracquel") == "dbracquel"


def test_platform_furniture_is_not_an_account():
    assert _handle_in("https://x.com/home") == ""
    assert _handle_in("https://www.instagram.com/explore/") == ""
    assert _handle_in("https://www.facebook.com/") == ""


def test_platform_matching_does_not_fall_for_a_lookalike_domain():
    assert platform_of("https://instagram.com.evil.test/someone") == ""
    assert platform_of("https://www.instagram.com/someone") == "Instagram"
