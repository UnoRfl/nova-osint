"""The dossier layer: evidence scoring, the exposure parser, and consolidation.

The tests that matter most here are the *refusals*. A parser that usually
declines to return a password is not a security control, so the credential
tests are written as sweeps over many shapes rather than as one happy path.
"""

from __future__ import annotations

import pytest

from nova_osint.core import biography
from nova_osint.core import target_dossier as td
from nova_osint.core.models import Confidence, Finding, Investigation, ScanResult, TargetType
from nova_osint.core.scoring import SOURCE_WEIGHTS, Evidence, EvidenceSet, normalise, weight_for
from nova_osint.modules.exposure_parser import looks_like_secret, parse_exposure_metadata

# ---------------------------------------------------------------------------
# scoring
# ---------------------------------------------------------------------------


def test_same_value_from_two_sources_merges_and_keeps_both():
    """Corroboration is the point: one row, both names, a higher score."""
    values = EvidenceSet()
    values.add(Evidence("Ada Lovelace", "wikidata", evidence_type="verified_public_record"))
    values.add(Evidence("Ada Lovelace", "github", evidence_type="official_profile"))

    assert len(values) == 1
    assert values.best.corroboration == 2
    assert set(values.best.sources) == {"wikidata", "github"}
    assert values.best.confidence > weight_for("verified_public_record")


def test_competing_values_are_both_kept_and_ranked():
    """The rule this whole layer exists for: never silently overwrite."""
    dob = EvidenceSet()
    dob.add(Evidence("2001-04-17", "official_public_record",
                     evidence_type="verified_public_record"))
    dob.add(Evidence("2001-04-18", "historical_profile",
                     evidence_type="historical_forum"))

    assert len(dob) == 2
    assert dob.best.value == "2001-04-17"
    assert [e.value for e in dob.conflicts] == ["2001-04-17", "2001-04-18"]
    assert dob.disputed


def test_a_multivalued_field_never_reports_a_conflict():
    """Two phone numbers is ordinary, not a disagreement."""
    phones = EvidenceSet(multivalued=True)
    phones.add(Evidence("+15555550100", "record"))
    phones.add(Evidence("+15555550199", "record"))

    assert len(phones) == 2
    assert phones.conflicts == []
    assert not phones.disputed


def test_corporate_suffixes_merge_rather_than_contradict():
    employers = EvidenceSet(corporate=True)
    employers.add(Evidence("Acme Global Solutions, Inc.", "wikidata"))
    employers.add(Evidence("Acme Global Solutions", "github"))

    assert len(employers) == 1, "one employer described two ways is one employer"


def test_a_synthetic_value_never_earns_corroboration():
    """Two fixtures agreeing is one fixture written twice."""
    values = EvidenceSet()
    values.add(Evidence("Jane Doe", "fixture-a", evidence_type="synthetic_fixture"))
    values.add(Evidence("Jane Doe", "fixture-b", evidence_type="synthetic_fixture"))

    assert values.best.confidence == pytest.approx(SOURCE_WEIGHTS["synthetic_fixture"])
    assert values.best.synthetic


def test_confidence_never_reaches_certainty_by_repetition():
    values = EvidenceSet()
    for i in range(50):
        values.add(Evidence("x", f"source-{i}", evidence_type="verified_public_record"))
    assert values.best.confidence < 1.0


def test_normalise_folds_accents_but_display_text_is_untouched():
    assert normalise("Zoë  Müller") == normalise("Zoe Muller")
    values = EvidenceSet()
    values.add(Evidence("Zoë Müller", "wikidata"))
    assert values.best.value == "Zoë Müller", "display keeps the diacritics"


# ---------------------------------------------------------------------------
# the exposure parser: what it must refuse
# ---------------------------------------------------------------------------

CREDENTIAL_LINES = [
    "password: hunter2",
    "Password: correct horse battery staple",
    "pwd=letmein",
    "hash: 5f4dcc3b5aa765d61d8327deb882cf99",
    "md5:5f4dcc3b5aa765d61d8327deb882cf99",
    "sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "bcrypt: $2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    "api_key: AKIAIOSFODNN7EXAMPLE",
    "token: ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "session: abcdef0123456789abcdef0123456789",
    "cookie: sessionid=abc123",
    "private_key: -----BEGIN RSA PRIVATE KEY-----",
    "ssn: 123-45-6789",
    "cvv: 123",
    "seed_phrase: witch collapse practice feed shame open despair",
]


@pytest.mark.parametrize("line", CREDENTIAL_LINES)
def test_credential_lines_are_never_returned(line):
    """No credential field reaches ``fields``, whatever it was called."""
    meta = parse_exposure_metadata(line)

    flat = " ".join(v for values in meta.fields.values() for v in values).casefold()
    secret = line.split(":", 1)[-1].split("=", 1)[-1].strip().casefold()
    assert secret not in flat
    assert meta.contained_credentials, "the refusal must be reported, not silent"


def test_a_credential_hiding_in_a_permitted_field_is_dropped():
    """The second gate: the field was allowed, the value still is not."""
    meta = parse_exposure_metadata(
        "Employer: 5f4dcc3b5aa765d61d8327deb882cf99\n"
        "Company: Example Corporation\n")

    assert meta.fields["employer"] == ["Example Corporation"]
    assert meta.redacted_values == 1


def test_an_unrecognised_field_is_ignored_by_default():
    """The allowlist fails closed: a column nobody predicted is not emitted."""
    meta = parse_exposure_metadata("ntlm_response: 0123456789abcdef\n"
                                   "favourite_colour: blue\n")
    assert "favourite_colour" not in meta.fields
    assert not any("blue" in v for values in meta.fields.values() for v in values)


@pytest.mark.parametrize("value,expected", [
    ("5f4dcc3b5aa765d61d8327deb882cf99", True),           # md5
    ("$2y$10$N9qo8uLOickgx2ZMRZoMye", True),              # bcrypt
    ("AKIAIOSFODNN7EXAMPLE", True),                       # AWS key id
    ("ghp_16C7e42F292c6912E7710c838347Ae178B4a", True),   # GitHub token
    ("sb_secret_abcdefgh12345678", True),                 # Supabase secret
    ("Acme Global Solutions", False),                     # a real employer
    ("Generic State University", False),                  # a real school
    ("2001-04-17", False),                                # a real date
])
def test_looks_like_secret_is_shape_based(value, expected):
    assert looks_like_secret(value) is expected


def test_the_biographical_half_of_a_record_still_comes_through():
    """Refusing credentials must not mean refusing the useful metadata."""
    meta = parse_exposure_metadata(
        "Source: ExampleForum\n"
        "Breach date: 2019-03-04\n"
        "Email: someone@example.com\n"
        "DOB: 2001-04-17\n"
        "Employer: Example Corporation\n"
        "Username: example_user\n"
        "School: Generic State University\n"
        "Class of: 2012\n"
        "password: hunter2\n")

    assert meta.get("date_of_birth") == "2001-04-17"
    assert meta.get("email_domain") == "example.com"
    assert meta.get("graduation_year") == "2012"
    assert meta.fields["employer"] == ["Example Corporation"]
    assert meta.fields["username"] == ["example_user"]
    assert meta.credential_fields_present == ["password"]


def test_the_parser_is_total():
    """A bad fixture must not take the investigation down with it."""
    for junk in ("", "\x00\x01", "no colons here at all", ":::", "a" * 100_000):
        assert parse_exposure_metadata(junk) is not None


def test_an_email_is_reduced_to_its_domain():
    """Other people's addresses in a dump are not the subject's business."""
    meta = parse_exposure_metadata("Email: someone.else@example.com")
    assert meta.fields["email_domain"] == ["example.com"]
    assert not any("someone.else" in v
                   for values in meta.fields.values() for v in values)


# ---------------------------------------------------------------------------
# identifier normalisation
# ---------------------------------------------------------------------------


def test_identifiers_are_sorted_by_shape():
    ids = td.normalize_target_identifiers(
        "Someone@Example.COM", "https://github.com/octocat", "octocat",
        "Ada Lovelace", "+1 555 555 0100")

    assert ids.emails == ["someone@example.com"]
    assert "octocat" in ids.usernames
    assert ids.display_names == ["Ada Lovelace"]
    assert ids.phones == ["+15555550100"]


def test_a_name_is_never_derived_from_an_email():
    """The bug that put Google's DMARC mailbox in a person's Name field."""
    ids = td.normalize_target_identifiers("mailauth-reports@google.com")
    assert ids.display_names == []
    assert ids.usernames == []


# ---------------------------------------------------------------------------
# consolidation
# ---------------------------------------------------------------------------


def _subject(**attributes) -> biography.Subject:
    """Build a biography subject from ``label -> [(text, source, grade)]``."""
    return biography.Subject(
        name=attributes.pop("name", "Test Subject"),
        attributes=[
            biography.Attribute(
                label=label,
                values=[biography.Value(text=t, source=s, grade=g)
                        for t, s, g in values])
            for label, values in attributes.items()])


def test_education_is_split_into_school_year_and_degree():
    records = td._education(_subject(Education=[
        ("BSc Computer Science, Generic State University, 2012", "wikidata", "B2"),
    ]).attributes[0])

    assert len(records) == 1
    assert records[0].graduation_year == "2012"
    assert records[0].degree.casefold().startswith("bsc")
    assert "Generic State University" in records[0].school_name


def test_one_employer_and_one_role_are_paired():
    subject = _subject(
        Employer=[("Acme Global Solutions", "wikidata", "B2")],
        **{"Position held": [("Systems Administrator", "wikidata", "B2")]})
    by_label = {a.label: a for a in subject.attributes}

    records = td._employment(by_label["Employer"], by_label["Position held"], None)

    assert len(records) == 1
    assert records[0].role == "Systems Administrator"
    assert records[0].role_paired


def test_several_employers_and_several_roles_are_never_zipped():
    """Three employers and two titles have six pairings; asserting one is a lie."""
    subject = _subject(
        Employer=[("Acme Global Solutions", "wikidata", "B2"),
                  ("Initech", "wikidata", "B2"),
                  ("Globex", "wikidata", "B2")],
        **{"Position held": [("Systems Administrator", "wikidata", "B2"),
                             ("Engineer", "wikidata", "B2")]})
    by_label = {a.label: a for a in subject.attributes}

    records = td._employment(by_label["Employer"], by_label["Position held"], None)

    assert len(records) == 3
    assert all(r.role is None for r in records)
    assert all(not r.role_paired for r in records)


def test_a_role_carried_with_its_company_by_one_source_is_paired():
    subject = _subject(Employer=[
        ("Systems Administrator at Acme Global Solutions", "wikidata", "B2")])

    records = td._employment(subject.attributes[0], None, None)

    assert records[0].company == "Acme Global Solutions"
    assert records[0].role == "Systems Administrator"
    assert records[0].role_paired


def test_collection_gaps_are_deduplicated():
    """The report printed 'not an email address' three times and 'rate limited' five."""
    inv = Investigation(target="x@example.com", target_type=TargetType.EMAIL)
    for _ in range(3):
        result = ScanResult(module="email", target="x", target_type=TargetType.EMAIL)
        result.errors.append("not an email address")
        inv.results.append(result)

    dossier = td.Dossier()
    td._fold_gaps(dossier, inv)

    assert dossier.collection_errors == [("email", "partial", "not an email address")]


def test_a_dossier_renders_without_any_findings():
    """The empty case is the one a renderer crashes on."""
    inv = Investigation(target="nobody@example.com", target_type=TargetType.EMAIL)
    dossier = td.generate_target_dossier(inv)

    assert td.render_json(dossier)
    markdown = td.render_markdown(dossier)
    assert "Dossier" in markdown
    assert "not established" in markdown


def test_the_spec_shape_is_exactly_as_asked():
    inv = Investigation(target="nobody@example.com", target_type=TargetType.EMAIL)
    data = td.generate_target_dossier(inv).to_dict()

    assert set(data) >= {"identity", "background", "digital_footprint", "confidence"}
    assert set(data["identity"]) == {"full_name", "aliases", "date_of_birth",
                                     "associated_phone_numbers"}
    assert set(data["background"]) == {"education", "employment"}
    assert set(data["digital_footprint"]) == {"linked_accounts", "exposure_records"}
    assert set(data["confidence"]) == {"identity", "education", "employment",
                                       "phones", "dob", "accounts"}


def test_every_evidence_record_carries_the_four_required_keys():
    values = EvidenceSet()
    values.add(Evidence("x", "wikidata", evidence_type="verified_public_record"))
    record = values.to_list()[0]
    assert {"value", "source", "confidence", "evidence_type"} <= set(record)


def test_a_synthetic_dossier_is_flagged_for_the_renderer():
    dossier = td.Dossier(subject="Test")
    dossier.full_name.add(Evidence("Jane Doe", "fixture",
                                   evidence_type="synthetic_fixture"))

    assert dossier.synthetic
    assert "synthetic fixture data" in td.render_markdown(dossier)


def test_exposure_text_folds_biography_in_without_credentials():
    inv = Investigation(target="someone@example.com", target_type=TargetType.EMAIL)
    dossier = td.generate_target_dossier(inv, exposure_text=(
        "Source: ExampleForum\n"
        "DOB: 2001-04-17\n"
        "Employer: Example Corporation\n"
        "password: hunter2\n"))

    assert dossier.date_of_birth.best.value == "2001-04-17"
    assert any(r.company == "Example Corporation" for r in dossier.employment)

    rendered = td.render_json(dossier) + td.render_markdown(dossier)
    assert "hunter2" not in rendered
    assert "password" in rendered, "the refusal is reported, not hidden"


def test_user_provided_claims_outrank_anything_inferred():
    dossier = td.Dossier()
    dossier.full_name.add(td._evidence("Mailauth Reports", "heuristic", grade="D3"))
    td._fold_identifiers(dossier, td.normalize_target_identifiers("Ada Lovelace"))

    assert dossier.full_name.best.value == "Ada Lovelace"
    assert dossier.full_name.best.evidence_type == "user_provided"


def test_a_heuristic_name_is_scored_as_a_guess():
    """'possible real name' from an email local part must never look confirmed."""
    guess = td._evidence("Mailauth Reports", "heuristic", grade="D3")
    assert guess.evidence_type == "derived"
    assert guess.confidence <= 0.3


def test_a_guessed_name_keeps_its_own_source_through_extraction():
    """The 'Mailauth Reports' path, end to end.

    The email module reports a guessed real name with ``source="heuristic"``
    while the *module* is "email". Attributing it to the module lost the only
    word that marked it a guess, and the guess then outranked nothing and
    appeared in the dossier's headline Name field at the same weight as a
    published one.
    """
    inv = Investigation(target="mailauth-reports@google.com",
                        target_type=TargetType.EMAIL)
    result = ScanResult(module="email", target=inv.target,
                        target_type=TargetType.EMAIL)
    result.findings.append(Finding(label="possible real name",
                                   value="Mailauth Reports", source="heuristic",
                                   confidence=Confidence.POSSIBLE))
    inv.results.append(result)

    subject = biography.extract(inv)[0]
    name = next(a for a in subject.attributes if a.label == "Name")
    assert name.values[0].origin == "heuristic"
    assert name.values[0].basis == "heuristic"

    dossier = td.generate_target_dossier(inv)
    best = dossier.full_name.best
    assert best.evidence_type == "derived"
    assert best.confidence <= 0.3, "a guess must never be weighted as a finding"


def test_the_subject_is_never_listed_as_its_own_candidate():
    inv = Investigation(target="Jane Doe", target_type=TargetType.PERSON)
    result = ScanResult(module="wikidata", target="Jane Doe",
                        target_type=TargetType.PERSON)
    result.findings.append(Finding(label="Jane Doe: occupation", value="engineer",
                                   source="wikidata"))
    inv.results.append(result)

    dossier = td.generate_target_dossier(inv)
    assert all(c["name"] != dossier.subject for c in dossier.candidates)


def test_a_school_is_not_confused_with_the_field_of_study():
    assert td._school_name("Computer Science, Generic State University") == \
        "Generic State University"
    assert td._school_name("Generic State University") == "Generic State University"
