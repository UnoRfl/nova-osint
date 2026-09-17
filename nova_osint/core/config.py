"""Runtime configuration and optional API keys.

Keys are read from the environment only. Nothing here reads a committed file,
and nothing here ever prints a key back out - modules ask
``config.key("shodan")`` and get either a string or ``None``.

To supply keys, export them in your shell or put them in a ``.env`` that is
git-ignored (see ``.env.example``). ``.env`` is loaded only if you pass
``--env-file``, so the default path never touches disk.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

#: Env var name -> short key name used by modules.
KEY_ENV = {
    "shodan": "SHODAN_API_KEY",
    "hibp": "HIBP_API_KEY",
    "hunter": "HUNTER_API_KEY",
    "github": "GITHUB_TOKEN",
    "virustotal": "VT_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "numverify": "NUMVERIFY_API_KEY",
    "emailrep": "EMAILREP_API_KEY",
}

DEFAULT_CACHE = Path.home() / ".cache" / "nova_osint"


@dataclass
class Config:
    timeout: float = 12.0
    concurrency: int = 24
    per_host_delay: float = 0.35
    retries: int = 2
    cache_dir: Path | None = field(default=None)
    cache_ttl: float = 3600.0
    proxy: str | None = None
    verify_tls: bool = True
    user_agent: str | None = None
    #: Passive mode never sends a request to infrastructure the target owns;
    #: it only queries third-party archives and registries.
    passive_only: bool = False
    #: Cap on username sites / subdomain probes, so a scan stays bounded.
    max_sites: int = 0  # 0 = no cap
    keys: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, **overrides: object) -> Config:
        keys = {}
        for short, env in KEY_ENV.items():
            val = os.environ.get(env, "").strip()
            if val:
                keys[short] = val
        cfg = cls(keys=keys)
        for k, v in overrides.items():
            if v is not None and hasattr(cfg, k):
                setattr(cfg, k, v)
        return cfg

    def key(self, name: str) -> str | None:
        return self.keys.get(name)

    def has(self, name: str) -> bool:
        return bool(self.keys.get(name))

    @property
    def available_keys(self) -> list[str]:
        return sorted(self.keys)


def load_env_file(path: Path) -> int:
    """Load ``KEY=value`` lines into ``os.environ``. Returns how many were set.

    Deliberately explicit: nothing auto-loads a ``.env``, because a tool that
    silently picks up credentials from the working directory is a tool that
    leaks them when you run it in the wrong directory.
    """
    if not path.exists():
        raise FileNotFoundError(path)
    count = 0
    for line in path.read_text("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if value:
            os.environ[name.strip()] = value
            count += 1
    return count
