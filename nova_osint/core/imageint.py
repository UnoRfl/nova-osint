"""Reading a photograph for investigative clues, locally and for free.

An image is one of the richest things an operator can hand a tool and one of
the most dangerous. Rich, because it carries a camera, a date, sometimes a
coordinate, usually some readable text, and a visual fingerprint that finds
the same picture elsewhere. Dangerous, because the obvious thing to do with a
face - decide whose it is - is the one thing a tool must not pretend to do.

So this file extracts, hashes and reads. It never identifies a person.

The four rules
--------------

**Local first, and local is usually enough.** Dimensions, format, EXIF, GPS,
camera, timestamps and a perceptual hash all come from bytes already on the
machine. Nothing here needs a network or an account.

**A visual resemblance is not an identity.** Perceptual hashing answers "is
this the same picture" - which is a real, checkable claim - not "is this the
same person". There is no face matching in this module and there is not meant
to be.

**A clue is a query, not a fact.** Text read out of an image by OCR is a
*hypothesis about what the image says*, with an error rate. It is turned into
searches and carried with its provenance - image, to OCR, to string, to
query, to result - so nothing downstream mistakes it for something a source
asserted.

**Every optional dependency degrades to a named gap.** No Pillow means no
perceptual hash, not a traceback; no Tesseract means the text stage reports
NOT CHECKED. That is the same contract the rest of the project keeps.
"""

from __future__ import annotations

import hashlib
import logging
import re
import shutil
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

__all__ = ["ImageFacts", "analyse", "dimensions", "read_exif", "phash",
           "hamming", "ocr", "clues_to_queries", "have_pillow", "have_ocr"]


@dataclass
class ImageFacts:
    """Everything that could be established about one image file."""

    path: str
    sha256: str = ""
    size_bytes: int = 0
    format: str = ""
    width: int = 0
    height: int = 0
    exif: dict[str, Any] = field(default_factory=dict)
    gps: tuple[float, float] | None = None
    taken_at: str = ""
    camera: str = ""
    software: str = ""
    #: Average- and difference-hash, as 16-character hex. Same picture, same
    #: hash; a re-encode or a resize changes it very little.
    ahash: str = ""
    dhash: str = ""
    text: str = ""
    #: ``[(kind, value)]`` - the things worth searching for.
    clues: list[tuple[str, str]] = field(default_factory=list)
    #: ``[(stage, why)]`` - what could not be done, and what would fix it.
    gaps: list[tuple[str, str]] = field(default_factory=list)

    @property
    def megapixels(self) -> float:
        return round(self.width * self.height / 1_000_000, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "sha256": self.sha256, "size_bytes": self.size_bytes,
            "format": self.format, "width": self.width, "height": self.height,
            "exif": self.exif, "gps": list(self.gps) if self.gps else None,
            "taken_at": self.taken_at, "camera": self.camera,
            "software": self.software, "ahash": self.ahash, "dhash": self.dhash,
            "text": self.text,
            "clues": [{"kind": k, "value": v} for k, v in self.clues],
            "gaps": [{"stage": s, "reason": r} for s, r in self.gaps],
        }


# ----------------------------------------------------------- what is present


def have_pillow() -> bool:
    try:
        import PIL.Image  # noqa: F401
    except Exception:  # noqa: BLE001
        return False
    return True


def have_ocr() -> tuple[bool, str]:
    """``(usable, how)``. Two routes, because either is enough."""
    try:
        import pytesseract  # noqa: F401

        return True, "pytesseract"
    except Exception:  # noqa: BLE001
        pass
    if shutil.which("tesseract"):
        return True, "tesseract binary"
    return False, ""


# -------------------------------------------------------------- header parse


def dimensions(data: bytes) -> tuple[str, int, int]:
    """``(format, width, height)`` from the file header alone.

    Written by hand rather than delegated to Pillow because it is twenty lines
    and it means a scan on a locked-down box still reports what an image *is*.
    """
    if data[:8] == b"\x89PNG\r\n\x1a\n" and len(data) >= 24:
        w, h = struct.unpack(">II", data[16:24])
        return "png", w, h
    if data[:3] == b"\xff\xd8\xff":
        return ("jpeg", *_jpeg_size(data))
    if data[:6] in (b"GIF87a", b"GIF89a") and len(data) >= 10:
        w, h = struct.unpack("<HH", data[6:10])
        return "gif", w, h
    if data[:2] == b"BM" and len(data) >= 26:
        w, h = struct.unpack("<ii", data[18:26])
        return "bmp", abs(w), abs(h)
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ("webp", *_webp_size(data))
    return "", 0, 0


def _jpeg_size(data: bytes) -> tuple[int, int]:
    i = 2
    end = len(data)
    while i + 9 < end:
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        # SOF0..SOF15, excluding the four that are not frame headers.
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            h, w = struct.unpack(">HH", data[i + 5:i + 9])
            return w, h
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        try:
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
        except struct.error:
            break
        i += 2 + length
    return 0, 0


def _webp_size(data: bytes) -> tuple[int, int]:
    chunk = data[12:16]
    try:
        if chunk == b"VP8X":
            w = int.from_bytes(data[24:27], "little") + 1
            h = int.from_bytes(data[27:30], "little") + 1
            return w, h
        if chunk == b"VP8 ":
            w = struct.unpack("<H", data[26:28])[0] & 0x3FFF
            h = struct.unpack("<H", data[28:30])[0] & 0x3FFF
            return w, h
        if chunk == b"VP8L":
            bits = int.from_bytes(data[21:25], "little")
            return (bits & 0x3FFF) + 1, ((bits >> 14) & 0x3FFF) + 1
    except (struct.error, IndexError):
        pass
    return 0, 0


# --------------------------------------------------------------------- EXIF


#: The tags worth naming. Not the whole TIFF dictionary: a report listing two
#: hundred fields buries the four an investigator acts on.
_TAGS = {
    0x010F: "make", 0x0110: "model", 0x0131: "software",
    0x0132: "datetime", 0x013B: "artist", 0x8298: "copyright",
    0x9003: "datetime_original", 0x9004: "datetime_digitized",
    0xA430: "camera_owner", 0xA431: "body_serial", 0xA433: "lens_make",
    0xA434: "lens_model", 0xA435: "lens_serial", 0x001D: "gps_datestamp",
}
_GPS_TAGS = {0x0001: "lat_ref", 0x0002: "lat", 0x0003: "lon_ref", 0x0004: "lon"}


def read_exif(data: bytes) -> dict[str, Any]:
    """EXIF from a JPEG's APP1 segment, plus PNG text chunks.

    A deliberately small TIFF reader: it walks the IFD, keeps the tags in
    :data:`_TAGS`, and follows the EXIF and GPS sub-IFDs. Anything it cannot
    parse is skipped rather than raised on - a malformed header is extremely
    common in images that have been through three social networks, and it is
    not a reason to report nothing about the file.
    """
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return _png_text(data)
    if data[:3] != b"\xff\xd8\xff":
        return {}

    i = 2
    while i + 4 < len(data):
        if data[i] != 0xFF:
            i += 1
            continue
        marker = data[i + 1]
        try:
            length = struct.unpack(">H", data[i + 2:i + 4])[0]
        except struct.error:
            return {}
        if marker == 0xE1 and data[i + 4:i + 10] == b"Exif\x00\x00":
            return _tiff(data[i + 10:i + 2 + length])
        if marker == 0xDA:      # start of scan: no metadata past here
            return {}
        i += 2 + length
    return {}


def _tiff(buf: bytes) -> dict[str, Any]:
    if len(buf) < 8:
        return {}
    order = "<" if buf[:2] == b"II" else ">" if buf[:2] == b"MM" else ""
    if not order:
        return {}
    try:
        offset = struct.unpack(order + "I", buf[4:8])[0]
    except struct.error:
        return {}

    out: dict[str, Any] = {}
    _read_ifd(buf, offset, order, out, _TAGS)
    for sub_tag, reader in ((0x8769, _TAGS), (0x8825, _GPS_TAGS)):
        sub = out.pop(f"_sub_{sub_tag}", None)
        if sub:
            found: dict[str, Any] = {}
            _read_ifd(buf, int(sub), order, found, reader)
            if sub_tag == 0x8825:
                out["gps"] = found
            else:
                out.update(found)
    return out


def _read_ifd(buf: bytes, offset: int, order: str, out: dict[str, Any],
              names: dict[int, str], depth: int = 0) -> None:
    if depth > 2 or offset <= 0 or offset + 2 > len(buf):
        return
    try:
        count = struct.unpack(order + "H", buf[offset:offset + 2])[0]
    except struct.error:
        return
    for n in range(count):
        at = offset + 2 + n * 12
        if at + 12 > len(buf):
            return
        try:
            tag, typ, num = struct.unpack(order + "HHI", buf[at:at + 8])
        except struct.error:
            return
        if tag in (0x8769, 0x8825):
            try:
                out[f"_sub_{tag}"] = struct.unpack(order + "I", buf[at + 8:at + 12])[0]
            except struct.error:
                pass
            continue
        name = names.get(tag)
        if name is None:
            continue
        value = _tag_value(buf, at, order, typ, num)
        if value is not None:
            out[name] = value


_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}


def _tag_value(buf: bytes, at: int, order: str, typ: int, num: int) -> Any:
    size = _TYPE_SIZE.get(typ, 0) * num
    if not size:
        return None
    if size <= 4:
        raw = buf[at + 8:at + 8 + size]
    else:
        try:
            where = struct.unpack(order + "I", buf[at + 8:at + 12])[0]
        except struct.error:
            return None
        raw = buf[where:where + size]
    if len(raw) < size:
        return None
    try:
        if typ == 2:
            return raw.split(b"\x00")[0].decode("utf-8", "replace").strip() or None
        if typ == 3:
            vals = struct.unpack(order + "H" * num, raw)
        elif typ == 4:
            vals = struct.unpack(order + "I" * num, raw)
        elif typ in (5, 10):
            pairs = struct.unpack(order + ("iI" if typ == 10 else "II") * num, raw)
            vals = tuple(
                (pairs[i] / pairs[i + 1]) if pairs[i + 1] else 0.0
                for i in range(0, len(pairs), 2))
        else:
            return None
    except struct.error:
        return None
    return vals[0] if len(vals) == 1 else list(vals)


def _png_text(data: bytes) -> dict[str, Any]:
    """tEXt / iTXt chunks. Editors and generators leave a great deal here."""
    out: dict[str, Any] = {}
    i = 8
    while i + 8 <= len(data):
        try:
            length = struct.unpack(">I", data[i:i + 4])[0]
        except struct.error:
            break
        kind = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + length]
        if kind in (b"tEXt", b"iTXt"):
            parts = body.split(b"\x00", 1)
            if len(parts) == 2:
                key = parts[0].decode("latin-1", "replace").strip().lower()
                val = parts[1].lstrip(b"\x00").decode("utf-8", "replace").strip()
                if key and val:
                    out[key] = val
        if kind == b"IEND":
            break
        i += 12 + length
    return out


def gps_of(exif: dict[str, Any]) -> tuple[float, float] | None:
    """Decimal degrees from the GPS sub-IFD, or None."""
    gps = exif.get("gps") or {}
    lat, lon = gps.get("lat"), gps.get("lon")
    if not (isinstance(lat, list) and isinstance(lon, list)):
        return None
    try:
        dec_lat = float(lat[0]) + float(lat[1]) / 60 + float(lat[2]) / 3600
        dec_lon = float(lon[0]) + float(lon[1]) / 60 + float(lon[2]) / 3600
    except (IndexError, TypeError, ValueError):
        return None
    if str(gps.get("lat_ref", "N")).upper().startswith("S"):
        dec_lat = -dec_lat
    if str(gps.get("lon_ref", "E")).upper().startswith("W"):
        dec_lon = -dec_lon
    return round(dec_lat, 6), round(dec_lon, 6)


# --------------------------------------------------------- perceptual hashes


def phash(data: bytes) -> tuple[str, str]:
    """``(average hash, difference hash)`` as hex, or ``("", "")``.

    Two hashes rather than one because they fail differently: the average hash
    is robust to scaling and weak against contrast changes, the difference
    hash is the other way round. Agreement between them is what makes "this is
    the same picture" worth asserting.

    Needs Pillow. Without it the caller records a gap; it does not guess.
    """
    try:
        import io

        from PIL import Image
    except Exception:  # noqa: BLE001
        return "", ""
    try:
        with Image.open(io.BytesIO(data)) as im:
            grey = im.convert("L")
            a = grey.resize((8, 8))
            pixels = _pixels(a)
            mean = sum(pixels) / len(pixels)
            abits = "".join("1" if p >= mean else "0" for p in pixels)

            d = grey.resize((9, 8))
            dpix = _pixels(d)
            dbits = "".join(
                "1" if dpix[row * 9 + col] > dpix[row * 9 + col + 1] else "0"
                for row in range(8) for col in range(8))
    except Exception as exc:  # noqa: BLE001 - a corrupt image is not a crash
        log.debug("perceptual hash failed: %s", exc)
        return "", ""
    return f"{int(abits, 2):016x}", f"{int(dbits, 2):016x}"


def _pixels(image: Any) -> list[int]:
    """Greyscale pixel values, across Pillow versions.

    ``getdata`` is deprecated for removal in Pillow 14 and
    ``get_flattened_data`` does not exist before Pillow 11, so NOVA asks for
    whichever the installed version has rather than pinning a floor on an
    optional dependency.
    """
    getter = getattr(image, "get_flattened_data", None) or image.getdata
    return list(getter())


def hamming(a: str, b: str) -> int:
    """Bit distance between two hex hashes; 64 when they are not comparable.

    Under about 10 means the same picture re-encoded or resized. Over about 20
    means two different pictures - including two different photographs of the
    same subject, which is exactly the case this must not call a match.
    """
    if not a or not b or len(a) != len(b):
        return 64
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return 64


# ----------------------------------------------------------------------- OCR


def ocr(path: str, data: bytes | None = None) -> tuple[str, str]:
    """``(text, how)``. Empty ``how`` means no OCR engine is installed."""
    usable, how = have_ocr()
    if not usable:
        return "", ""
    if how == "pytesseract":
        try:
            import io

            import pytesseract
            from PIL import Image

            with Image.open(io.BytesIO(data) if data else path) as im:
                return pytesseract.image_to_string(im).strip(), how
        except Exception as exc:  # noqa: BLE001
            log.debug("pytesseract failed: %s", exc)
            return "", ""
    try:
        out = subprocess.run(  # noqa: S603 - fixed argv, path is the operator's own file
            ["tesseract", str(path), "stdout"], capture_output=True,
            timeout=60, check=False)
        return out.stdout.decode("utf-8", "replace").strip(), how
    except Exception as exc:  # noqa: BLE001
        log.debug("tesseract binary failed: %s", exc)
        return "", ""


# ------------------------------------------------------------------- reading


_URL = re.compile(r"https?://[^\s<>\"')]+", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_HANDLE = re.compile(r"(?<![\w@])@([A-Za-z0-9_.]{3,30})\b")
_YEAR = re.compile(r"\b(19[5-9]\d|20[0-4]\d)\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                     r"(?:com|org|net|io|dev|co|ai|edu|gov|uk|de|fr|nl|se|jp)\b", re.I)
#: A capitalised run of two to five words: conference names, company names,
#: venue names. Crude, and that is the right trade - it is a query generator,
#: and a bad query costs one request while a missed one costs the lead.
_PROPER = re.compile(r"\b([A-Z][\w&'-]+(?:\s+[A-Z][\w&'-]+){1,4})\b")

_STOPWORDS = {"The", "And", "For", "With", "From", "This", "That", "All",
              "New", "Not", "You", "Your", "Our"}


def read_clues(text: str) -> list[tuple[str, str]]:
    """``[(kind, value)]`` worth searching for, from text found in an image."""
    clues: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        value = value.strip().strip(".,;:")
        key = (kind, value.casefold())
        if value and key not in seen:
            seen.add(key)
            clues.append((kind, value))

    for m in _URL.finditer(text):
        add("url", m.group(0))
    for m in _EMAIL.finditer(text):
        add("email", m.group(0))
    for m in _HANDLE.finditer(text):
        add("username", m.group(1))
    for m in _DOMAIN.finditer(text):
        add("domain", m.group(0).lower())
    for m in _PROPER.finditer(text):
        phrase = m.group(1)
        if phrase.split()[0] in _STOPWORDS or len(phrase) < 6:
            continue
        add("phrase", phrase)
    for m in _YEAR.finditer(text):
        add("year", m.group(0))
    return clues


def analyse(path: str | Path, *, do_ocr: bool = True) -> ImageFacts:
    """Everything local, in one pass, with the gaps named.

    Never raises: an unreadable file is an :class:`ImageFacts` carrying the
    reason, because an investigation that dies on a bad JPEG is worse than one
    that reports a bad JPEG.
    """
    p = Path(path)
    facts = ImageFacts(path=str(p))
    try:
        data = p.read_bytes()
    except OSError as exc:
        facts.gaps.append(("read", f"cannot read {p}: {exc}"))
        return facts

    facts.size_bytes = len(data)
    facts.sha256 = hashlib.sha256(data).hexdigest()
    facts.format, facts.width, facts.height = dimensions(data)
    if not facts.format:
        facts.gaps.append(("format", "not a format NOVA can read the header of"))

    facts.exif = read_exif(data)
    if not facts.exif:
        # Worth stating: stripped EXIF is itself an observation. Every major
        # social network strips it, so its absence often says where an image
        # has been rather than that the camera wrote nothing.
        facts.gaps.append(("exif", "no metadata present - commonly means the "
                                   "image has been through a platform that "
                                   "strips it"))
    facts.gps = gps_of(facts.exif)
    facts.taken_at = str(facts.exif.get("datetime_original")
                         or facts.exif.get("datetime") or "")
    make = str(facts.exif.get("make", "")).strip()
    model = str(facts.exif.get("model", "")).strip()
    facts.camera = " ".join(x for x in (make, model) if x)
    facts.software = str(facts.exif.get("software", "")).strip()

    facts.ahash, facts.dhash = phash(data)
    if not facts.ahash:
        facts.gaps.append(("perceptual hash",
                           "needs Pillow (pip install pillow)"))

    if do_ocr:
        text, how = ocr(str(p), data)
        facts.text = text
        if not how:
            facts.gaps.append(("text", "no OCR engine installed "
                                       "(pip install pytesseract, plus tesseract)"))
        elif not text:
            facts.gaps.append(("text", f"{how} found no readable text"))

    clues = read_clues(facts.text) if facts.text else []
    for key in ("artist", "camera_owner", "copyright"):
        value = facts.exif.get(key)
        if value:
            clues.append(("name", str(value)))
    if facts.software:
        clues.append(("software", facts.software))
    facts.clues = clues
    return facts


def clues_to_queries(facts: ImageFacts, planner: Any, subject: str = "") -> list[Any]:
    """Turn what the image said into searches, keeping the whole chain.

    Every query's ``origin`` records that it came from this image and which
    stage produced the clue, so a result three hops away can still be traced
    back to "the OCR read a banner in the photograph".
    """
    made: list[Any] = []
    stem = Path(facts.path).name
    for kind, value in facts.clues:
        origin = f"image:{stem}:{'exif' if kind in ('name', 'software') else 'ocr'}"
        if kind in ("email", "username", "domain"):
            made += planner.expand(value, kind, subject=subject, origin=origin)
        elif kind in ("phrase", "name"):
            made += planner.expand(value, "phrase", subject=subject, origin=origin)
        if len(made) >= 8:
            break
    return made[:8]
