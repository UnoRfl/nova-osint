"""Controlled vocabulary for the parts of a brief that have right answers.

Most of what you know about someone is free text - an employer, a job title, a
street. But a handful of fields have a finite, agreed set of values, and for
those a list beats a text box twice over:

**It stops a silent mismatch.** A user types ``UK``; Wikidata says *United
Kingdom of Great Britain and Ireland*. Those share no whole word, so the
resolver scored them as a **contradiction** and pushed the right candidate
down - the exact opposite of what the user meant. Resolving an alias to a
canonical name before comparison is not a convenience, it is a correctness fix.

**It makes the field answerable.** "Country" as an empty box is a small puzzle:
United States, USA, US, or America? A list removes the question, and the same
list drives the desktop app's dropdown, so what you can pick is exactly what
NOVA can match.

Deliberately not exhaustive where exhaustive would be wrong. There is no city
list: there are millions, any list would be a arbitrary subset, and an
autocomplete that cannot find your town teaches you the tool does not know it.
Cities stay free text and the resolver compares them loosely.
"""

from __future__ import annotations

import re

#: ISO 3166-1 English short names, plus the handful of territories that turn up
#: in profiles often enough to be worth offering. Sorted for the dropdown.
COUNTRIES: tuple[str, ...] = (
    "Afghanistan", "Albania", "Algeria", "Andorra", "Angola",
    "Antigua and Barbuda", "Argentina", "Armenia", "Australia", "Austria",
    "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus",
    "Belgium", "Belize", "Benin", "Bhutan", "Bolivia",
    "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", "Bulgaria",
    "Burkina Faso", "Burundi", "Cambodia", "Cameroon", "Canada", "Cape Verde",
    "Central African Republic", "Chad", "Chile", "China", "Colombia",
    "Comoros", "Congo", "Costa Rica", "Croatia", "Cuba", "Cyprus", "Czechia",
    "Democratic Republic of the Congo", "Denmark", "Djibouti", "Dominica",
    "Dominican Republic", "Ecuador", "Egypt", "El Salvador",
    "Equatorial Guinea", "Eritrea", "Estonia", "Eswatini", "Ethiopia", "Fiji",
    "Finland", "France", "Gabon", "Gambia", "Georgia", "Germany", "Ghana",
    "Greece", "Grenada", "Guatemala", "Guinea", "Guinea-Bissau", "Guyana",
    "Haiti", "Honduras", "Hong Kong", "Hungary", "Iceland", "India",
    "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy", "Ivory Coast",
    "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati", "Kosovo",
    "Kuwait", "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia",
    "Libya", "Liechtenstein", "Lithuania", "Luxembourg", "Macau", "Madagascar",
    "Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands",
    "Mauritania", "Mauritius", "Mexico", "Micronesia", "Moldova", "Monaco",
    "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar", "Namibia",
    "Nauru", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger",
    "Nigeria", "North Korea", "North Macedonia", "Norway", "Oman", "Pakistan",
    "Palau", "Palestine", "Panama", "Papua New Guinea", "Paraguay", "Peru",
    "Philippines", "Poland", "Portugal", "Puerto Rico", "Qatar", "Romania",
    "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia",
    "Saint Vincent and the Grenadines", "Samoa", "San Marino",
    "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles",
    "Sierra Leone", "Singapore", "Slovakia", "Slovenia", "Solomon Islands",
    "Somalia", "South Africa", "South Korea", "South Sudan", "Spain",
    "Sri Lanka", "Sudan", "Suriname", "Sweden", "Switzerland", "Syria",
    "Taiwan", "Tajikistan", "Tanzania", "Thailand", "Timor-Leste", "Togo",
    "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan",
    "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom",
    "United States", "Uruguay", "Uzbekistan", "Vanuatu", "Vatican City",
    "Venezuela", "Vietnam", "Yemen", "Zambia", "Zimbabwe",
)

#: Everything else a person might write, mapped to the name above.
#:
#: The long-form constitutional names matter most: they are what curated
#: sources publish, and they are what a user never types. Without these
#: "United Kingdom" and "United Kingdom of Great Britain and Ireland" share no
#: whole word and read as a disagreement.
COUNTRY_ALIASES: dict[str, str] = {
    "uk": "United Kingdom",
    "u.k.": "United Kingdom",
    "gb": "United Kingdom",
    "great britain": "United Kingdom",
    "britain": "United Kingdom",
    "england": "United Kingdom",
    "scotland": "United Kingdom",
    "wales": "United Kingdom",
    "northern ireland": "United Kingdom",
    "united kingdom of great britain and ireland": "United Kingdom",
    "united kingdom of great britain and northern ireland": "United Kingdom",
    "us": "United States",
    "u.s.": "United States",
    "usa": "United States",
    "u.s.a.": "United States",
    "america": "United States",
    "united states of america": "United States",
    "uae": "United Arab Emirates",
    "holland": "Netherlands",
    "the netherlands": "Netherlands",
    "kingdom of the netherlands": "Netherlands",
    "burma": "Myanmar",
    "czech republic": "Czechia",
    "swaziland": "Eswatini",
    "cote d'ivoire": "Ivory Coast",
    "côte d'ivoire": "Ivory Coast",
    "cape verde islands": "Cape Verde",
    "cabo verde": "Cape Verde",
    "south korea": "South Korea",
    "republic of korea": "South Korea",
    "korea": "South Korea",
    "north korea": "North Korea",
    "democratic people's republic of korea": "North Korea",
    "russian federation": "Russia",
    "macedonia": "North Macedonia",
    "drc": "Democratic Republic of the Congo",
    "dr congo": "Democratic Republic of the Congo",
    "congo-kinshasa": "Democratic Republic of the Congo",
    "congo-brazzaville": "Congo",
    "republic of ireland": "Ireland",
    "eire": "Ireland",
    "vatican": "Vatican City",
    "holy see": "Vatican City",
    "east timor": "Timor-Leste",
    "people's republic of china": "China",
    "prc": "China",
    "mainland china": "China",
    "republic of china": "Taiwan",
    "türkiye": "Turkey",
    "turkiye": "Turkey",
    "persia": "Iran",
    "islamic republic of iran": "Iran",
    "syrian arab republic": "Syria",
    "lao people's democratic republic": "Laos",
    "viet nam": "Vietnam",
    "brunei darussalam": "Brunei",
    "state of palestine": "Palestine",
}

#: Languages worth offering. Not the full ISO 639 list: a dropdown of seven
#: thousand entries is a text box with extra steps.
LANGUAGES: tuple[str, ...] = (
    "Arabic", "Bengali", "Bulgarian", "Burmese", "Cantonese", "Catalan",
    "Czech", "Danish", "Dutch", "English", "Filipino", "Finnish", "French",
    "German", "Greek", "Gujarati", "Hebrew", "Hindi", "Hungarian",
    "Indonesian", "Italian", "Japanese", "Javanese", "Kannada", "Khmer",
    "Korean", "Malay", "Malayalam", "Mandarin", "Marathi", "Nepali",
    "Norwegian", "Persian", "Polish", "Portuguese", "Punjabi", "Romanian",
    "Russian", "Serbian", "Sinhala", "Slovak", "Spanish", "Swahili",
    "Swedish", "Tamil", "Telugu", "Thai", "Turkish", "Ukrainian", "Urdu",
    "Vietnamese", "Welsh",
)

MONTHS: tuple[str, ...] = (
    "January", "February", "March", "April", "May", "June", "July", "August",
    "September", "October", "November", "December",
)

#: Job titles common enough that offering them saves typing. Free text still
#: wins - this is a starting point, not a taxonomy.
ROLES: tuple[str, ...] = (
    "student", "teacher", "lecturer", "professor", "researcher", "engineer",
    "software engineer", "developer", "data scientist", "designer",
    "product manager", "project manager", "analyst", "consultant",
    "accountant", "lawyer", "doctor", "nurse", "pharmacist", "dentist",
    "architect", "journalist", "writer", "editor", "photographer",
    "musician", "artist", "entrepreneur", "founder", "chief executive",
    "director", "manager", "salesperson", "marketer", "recruiter",
    "electrician", "plumber", "carpenter", "chef", "driver", "pilot",
    "police officer", "soldier", "civil servant", "politician", "athlete",
    "mathematician", "scientist", "programmer", "retired",
)

_PUNCT = re.compile(r"[^\w\s']+")


def _key(text: str) -> str:
    return _PUNCT.sub("", str(text or "")).strip().casefold()


#: Built once: every canonical name is also a key for itself, so a value that
#: is already canonical resolves without a special case.
_COUNTRY_INDEX: dict[str, str] = {_key(c): c for c in COUNTRIES}
_COUNTRY_INDEX.update({_key(k): v for k, v in COUNTRY_ALIASES.items()})


def country(text: str) -> str:
    """The canonical country name for *text*, or ``""`` if it is not one.

    Matching is exact-after-normalisation rather than fuzzy. A near-miss on a
    country is far more likely to be a different country than a typo - Niger
    and Nigeria, Austria and Australia - and guessing between them would put a
    fact in the brief that the user never stated.
    """
    return _COUNTRY_INDEX.get(_key(text), "")


def language(text: str) -> str:
    """The canonical language name for *text*, or ``""``."""
    wanted = _key(text)
    for name in LANGUAGES:
        if _key(name) == wanted:
            return name
    return ""


def years(back: int = 110, ahead: int = 0) -> list[str]:
    """Years for a birth-date picker, newest first.

    Newest first because the common case is someone alive now, and a list that
    opens on 1916 makes the user scroll a century before they start.
    """
    import datetime

    now = datetime.date.today().year
    return [str(y) for y in range(now + ahead, now - back, -1)]


__all__ = ["COUNTRIES", "COUNTRY_ALIASES", "LANGUAGES", "MONTHS", "ROLES",
           "country", "language", "years"]
