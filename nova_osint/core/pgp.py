"""Just enough OpenPGP (RFC 4880 / 9580) to fingerprint a key and read its UIDs.

Why this exists: NOVA used to identify a published GPG key by the SHA-256 of
the whole armoured export. That value changes whenever the owner adds a
signature or a subkey, and it can never equal the same key fetched from a
keyserver - so the one link that should have been the strongest in the graph
(the same key in two places) could not form. A real fingerprint is a hash of
the public-key packet alone, and is identical everywhere the key appears.

Stdlib only. Parses public keys, never secret material, and never verifies
signatures - a UID inside a key is a *claim by the key holder*, which is how
the caller must report it.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field

TAG_PUBLIC_KEY = 6
TAG_USER_ID = 13
TAG_PUBLIC_SUBKEY = 14

_EMAIL_IN_UID = re.compile(r"<([^<>@\s]+@[^<>\s]+)>")


@dataclass
class PublicKey:
    fingerprint: str
    version: int
    subkeys: list[str] = field(default_factory=list)
    uids: list[str] = field(default_factory=list)

    @property
    def emails(self) -> list[str]:
        out = []
        for uid in self.uids:
            m = _EMAIL_IN_UID.search(uid)
            if m:
                out.append(m.group(1).lower())
        return out

    @property
    def key_id(self) -> str:
        return self.fingerprint[-16:]


def dearmor(text: str) -> bytes:
    """Concatenated binary of every armoured block in ``text``."""
    out = b""
    for block in re.findall(
            r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----",
            text, flags=re.S):
        lines = block.strip().splitlines()
        # Armour headers ("Comment: ...") end at the first blank line.
        if any(":" in ln for ln in lines[:4]) and "" in [ln.strip() for ln in lines]:
            blank = [ln.strip() for ln in lines].index("")
            lines = lines[blank + 1:]
        body = "".join(ln.strip() for ln in lines if ln.strip() and not ln.startswith("="))
        try:
            out += base64.b64decode(body, validate=False)
        except (ValueError, TypeError):
            continue
    return out


def _packets(data: bytes):  # type: ignore[no-untyped-def]
    """Yield ``(tag, body)``. Stops quietly at anything malformed."""
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if not b & 0x80:
            return
        if b & 0x40:  # new format
            tag = b & 0x3F
            i += 1
            if i >= n:
                return
            l1 = data[i]
            if l1 < 192:
                length, i = l1, i + 1
            elif l1 < 224:
                if i + 1 >= n:
                    return
                length, i = ((l1 - 192) << 8) + data[i + 1] + 192, i + 2
            elif l1 == 255:
                if i + 4 >= n:
                    return
                length, i = int.from_bytes(data[i + 1:i + 5], "big"), i + 5
            else:
                return  # partial lengths never occur in key packets
        else:  # old format
            tag = (b >> 2) & 0x0F
            ltype = b & 0x03
            i += 1
            size = {0: 1, 1: 2, 2: 4}.get(ltype)
            if size is None:
                length = n - i
            else:
                if i + size > n:
                    return
                length = int.from_bytes(data[i:i + size], "big")
                i += size
        if i + length > n:
            return
        yield tag, data[i:i + length]
        i += length


def fingerprint(body: bytes) -> str:
    """Fingerprint of one public-key (or subkey) packet body."""
    if not body:
        return ""
    version = body[0]
    if version == 4:
        return hashlib.sha1(b"\x99" + len(body).to_bytes(2, "big") + body
                            ).hexdigest().upper()
    if version in (5, 6):
        prefix = b"\x9a" if version == 5 else b"\x9b"
        return hashlib.sha256(prefix + len(body).to_bytes(4, "big") + body
                              ).hexdigest().upper()
    return ""


def parse_keys(text_or_bytes: str | bytes) -> list[PublicKey]:
    """Every primary key in an armoured (or binary) export, with its UIDs."""
    data = (dearmor(text_or_bytes) if isinstance(text_or_bytes, str)
            else text_or_bytes)
    keys: list[PublicKey] = []
    for tag, body in _packets(data):
        if tag == TAG_PUBLIC_KEY:
            fp = fingerprint(body)
            if fp:
                keys.append(PublicKey(fingerprint=fp, version=body[0]))
        elif tag == TAG_PUBLIC_SUBKEY and keys:
            fp = fingerprint(body)
            if fp:
                keys[-1].subkeys.append(fp)
        elif tag == TAG_USER_ID and keys:
            keys[-1].uids.append(body.decode("utf-8", "replace")[:200])
    return keys
