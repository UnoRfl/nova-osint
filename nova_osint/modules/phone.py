"""Phone number analysis.

Uses Google's libphonenumber via the ``phonenumbers`` package when it is
installed - that gives carrier, region and line-type from the offline metadata
bundle, with no network call and no third-party seeing the number. Without the
package the module falls back to country-code parsing only and says so.
"""

from __future__ import annotations

import re
import urllib.parse

from ..core.models import Confidence, ScanResult, Severity, TargetType
from ..core.registry import Module, register

try:  # optional dependency
    import phonenumbers
    from phonenumbers import carrier, geocoder
    from phonenumbers import timezone as pn_timezone
    from phonenumbers.phonenumberutil import PhoneNumberType, number_type

    HAVE_PN = True
except Exception:  # pragma: no cover
    HAVE_PN = False

LINE_TYPES = {
    0: "fixed line", 1: "mobile", 2: "fixed line or mobile", 3: "toll free",
    4: "premium rate", 5: "shared cost", 6: "VoIP", 7: "personal number",
    8: "pager", 9: "UAN", 10: "voicemail", 27: "unknown",
}

#: Just enough to say something useful when libphonenumber is absent.
DIALLING = {
    "1": "NANP (US/Canada)", "7": "Russia/Kazakhstan", "20": "Egypt", "27": "South Africa",
    "31": "Netherlands", "32": "Belgium", "33": "France", "34": "Spain", "39": "Italy",
    "40": "Romania", "41": "Switzerland", "43": "Austria", "44": "United Kingdom",
    "45": "Denmark", "46": "Sweden", "47": "Norway", "48": "Poland", "49": "Germany",
    "51": "Peru", "52": "Mexico", "53": "Cuba", "54": "Argentina", "55": "Brazil",
    "56": "Chile", "57": "Colombia", "58": "Venezuela", "60": "Malaysia", "61": "Australia",
    "62": "Indonesia", "63": "Philippines", "64": "New Zealand", "65": "Singapore",
    "66": "Thailand", "81": "Japan", "82": "South Korea", "84": "Vietnam", "86": "China",
    "90": "Turkey", "91": "India", "92": "Pakistan", "93": "Afghanistan", "94": "Sri Lanka",
    "95": "Myanmar", "98": "Iran", "212": "Morocco", "213": "Algeria", "234": "Nigeria",
    "254": "Kenya", "255": "Tanzania", "256": "Uganda", "351": "Portugal", "353": "Ireland",
    "358": "Finland", "359": "Bulgaria", "370": "Lithuania", "371": "Latvia", "372": "Estonia",
    "380": "Ukraine", "420": "Czechia", "421": "Slovakia", "852": "Hong Kong",
    "880": "Bangladesh", "886": "Taiwan", "971": "UAE", "972": "Israel", "974": "Qatar",
    "966": "Saudi Arabia", "countryless": "unknown",
}


@register
class PhoneModule(Module):
    name = "phone"
    title = "Phone number"
    description = "Validity, region, carrier, line type and messaging-app links."
    accepts = frozenset({TargetType.PHONE})

    def run(self, target: str, result: ScanResult) -> None:
        raw = target.strip()
        digits = re.sub(r"\D", "", raw)
        if not raw.startswith("+"):
            result.add(
                "note",
                "no leading '+': assuming an international number, pass +CC... for exact parsing",
                source="parse",
            )

        if not HAVE_PN:
            self._fallback(raw, digits, result)
            return

        region_hint = None if raw.startswith("+") else "US"
        try:
            num = phonenumbers.parse(raw if raw.startswith("+") else "+" + digits, region_hint)
        except Exception as e:
            result.error(f"could not parse: {e}")
            return

        valid = phonenumbers.is_valid_number(num)
        result.add("valid", "yes" if valid else "no - not an allocated number",
                   source="libphonenumber",
                   severity=Severity.INFO if valid else Severity.NOTABLE)
        result.add("possible", "yes" if phonenumbers.is_possible_number(num) else "no",
                   source="libphonenumber")
        result.add("E.164", phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164),
                   source="libphonenumber")
        result.add("international",
                   phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                   source="libphonenumber")
        result.add("country code", f"+{num.country_code}", source="libphonenumber")

        if region := geocoder.description_for_number(num, "en"):
            result.add("region", region, source="libphonenumber", severity=Severity.NOTABLE)
        if name := carrier.name_for_number(num, "en"):
            result.add("carrier at allocation", name, source="libphonenumber",
                       severity=Severity.NOTABLE, confidence=Confidence.LIKELY,
                       extra={"note": "original allocation; number portability may have moved it"})
        if zones := pn_timezone.time_zones_for_number(num):
            result.add("timezone(s)", list(zones), source="libphonenumber")

        ntype = number_type(num)
        result.add("line type", LINE_TYPES.get(ntype, str(ntype)), source="libphonenumber",
                   confidence=Confidence.LIKELY)
        if ntype == PhoneNumberType.VOIP:
            result.add("note", "VoIP numbers are cheap and disposable - weak identity signal",
                       source="analysis", severity=Severity.NOTABLE)

        self._links(phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164), result)

    def _fallback(self, raw: str, digits: str, result: ScanResult) -> None:
        result.add("library", "phonenumbers not installed - limited parsing "
                              "(pip install phonenumbers)", source="local",
                   severity=Severity.NOTABLE)
        country = None
        for length in (3, 2, 1):
            if digits[:length] in DIALLING:
                country = DIALLING[digits[:length]]
                result.add("country code", f"+{digits[:length]} ({country})", source="parse",
                           confidence=Confidence.LIKELY)
                break
        if not country:
            result.add("country code", "unrecognised", source="parse",
                       confidence=Confidence.POSSIBLE)
        result.add("digits", f"{len(digits)} digits", source="parse")
        self._links("+" + digits, result)

    def _links(self, e164: str, result: ScanResult) -> None:
        """Public lookup surfaces. These are links, not automated queries.

        Messaging apps expose "is this number registered" through their own
        clients. Enumerating that programmatically is against their terms and is
        how people get their own accounts banned, so the tool hands you the URL
        and stops there.
        """
        plain = e164.lstrip("+")
        for label, url in (
            ("WhatsApp", f"https://wa.me/{plain}"),
            ("Telegram", f"https://t.me/{e164}"),
            ("Truecaller", f"https://www.truecaller.com/search/x/{plain}"),
            ("Google", f"https://www.google.com/search?q={urllib.parse.quote(e164)}"),
            ("Google (quoted)", f"https://www.google.com/search?q=%22{urllib.parse.quote(e164)}%22"),
        ):
            result.add(f"check manually: {label}", url, source="link", url=url)
