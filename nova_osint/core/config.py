"""Runtime configuration: a JSON file for settings, the environment for secrets.

There are two kinds of configuration and they deserve different treatment.

**Settings** - timeouts, concurrency, delays, which modules to run - are dull,
worth keeping between runs, and harmless in a file. Those live in
``config.json``, managed by :class:`ConfigManager`, created with sane defaults
the first time you ask for it.

**Secrets** - API keys - are read from the environment by default, because a
credential in a file is a credential that gets committed. ``config.json`` *can*
hold keys (the ``api_keys`` block) for people who prefer one file to nine
exports, but the environment always wins, the file is created ``0600`` where
the OS supports it, and nothing here ever prints a key back out: modules ask
``config.key("shodan")`` and get either a string or ``None``.

Precedence, highest first::

    command-line flag  >  environment variable  >  config.json  >  built-in default

Nothing auto-loads a ``.env``; pass ``--env-file`` to opt in (see
``.env.example``). A tool that silently picks up credentials from the working
directory is a tool that leaks them when you run it in the wrong directory.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .logging_config import get_logger, register_secrets

log = get_logger("config")

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

#: What each key actually buys, where to get one, and which modules read it.
#:
#: ``modules`` is the honest part: a key nothing reads is listed with an empty
#: tuple and the UI says so, rather than implying capability the code does not
#: have. ``tests/test_pipeline.py`` asserts every name here is a real module.
KEY_INFO: dict[str, dict[str, Any]] = {
    "github": {
        "label": "GitHub",
        "unlocks": "Raises the API limit from 60/hr to 5,000/hr. Use a token "
                   "(classic) with NO scopes ticked - this tool reads public data "
                   "only. Fine-grained tokens are scoped to a single owner and do "
                   "not cover every endpoint used here.",
        # Deliberately the classic-token page, not /settings/personal-access-tokens.
        "url": "https://github.com/settings/tokens/new",
        "cost": "free",
        "modules": ("github", "gists", "email"),
        "availability": "optional key",
        "required": False,
    },
    "virustotal": {
        "label": "VirusTotal",
        "unlocks": "Blocklist verdicts from ~70 vendors, content categories, "
                   "popularity rank and passive DNS for domains and IPs.",
        "url": "https://www.virustotal.com/gui/my-apikey",
        "cost": "free tier (~4/min, 500/day, non-commercial)",
        "modules": ("virustotal",),
        "availability": "user-provided key",
        "required": True,
    },
    "securitytrails": {
        "label": "SecurityTrails",
        "unlocks": "Historical DNS and pre-privacy WHOIS - the registrant name and "
                   "email a domain had before redaction.",
        "url": "https://securitytrails.com/app/signup",
        # Checked 2026-09-17: the public pricing page lists only Professional
        # ($500/mo), Business ($1500/mo) and Enterprise, and the API page says
        # "the API is paid". The old free tier is no longer documented. Signing
        # up costs nothing and takes no card, so check your dashboard for any
        # remaining allowance before assuming this module can run.
        "cost": "paid - no free tier advertised (checked 2026-09-17)",
        "modules": ("securitytrails",),
        "availability": "paid",
        "required": True,
    },
    "abuseipdb": {
        "label": "AbuseIPDB",
        "unlocks": "Abuse confidence score and recent report categories for an IP.",
        "url": "https://www.abuseipdb.com/account/api",
        "cost": "free tier",
        "modules": ("abuseipdb",),
        "availability": "user-provided key",
        "required": True,
    },
    "hibp": {
        "label": "Have I Been Pwned",
        "unlocks": "Per-address breach lookup. Domain-level breach data (the "
                   "'breaches' module) already works without a key.",
        "url": "https://haveibeenpwned.com/API/Key",
        "cost": "paid subscription",
        "modules": ("pwned",),
        "availability": "paid",
        "required": True,
    },
    "shodan": {
        "label": "Shodan",
        "unlocks": "Nothing yet - the 'ip' module uses the keyless InternetDB "
                   "endpoint. Setting this has no effect until a module reads it.",
        "url": "https://account.shodan.io/",
        "cost": "paid membership",
        "modules": (),
        "availability": "disabled",
        "required": False,
    },
    "hunter": {
        "label": "Hunter.io",
        "unlocks": "Nothing yet - no module reads this key.",
        "url": "https://hunter.io/api-keys",
        "cost": "free tier",
        "modules": (),
        "availability": "disabled",
        "required": False,
    },
    "numverify": {
        "label": "NumVerify",
        "unlocks": "Nothing yet - the 'phone' module parses offline via "
                   "libphonenumber and needs no key.",
        "url": "https://numverify.com/dashboard",
        "cost": "free tier",
        "modules": (),
        "availability": "disabled",
        "required": False,
    },
    "emailrep": {
        "label": "EmailRep",
        "unlocks": "Nothing yet - no module reads this key.",
        "url": "https://emailrep.io/key",
        "cost": "free tier",
        "modules": (),
        "availability": "disabled",
        "required": False,
    },
}


def key_info(name: str) -> dict[str, Any]:
    """Metadata for a key, with safe fallbacks for one nobody documented."""
    return KEY_INFO.get(name, {
        "label": name, "unlocks": "", "url": "", "cost": "",
        "modules": (), "required": False,
    })


#: Names people reasonably write in a config file, mapped to the short names
#: modules actually use. Keeps a hand-written config.json from silently
#: dropping a key because it was spelled the long way.
KEY_ALIASES = {
    "haveibeenpwned": "hibp",
    "have_i_been_pwned": "hibp",
    "hunter_io": "hunter",
    "hunterio": "hunter",
    "vt": "virustotal",
    "github_token": "github",
    "abuse_ipdb": "abuseipdb",
    "security_trails": "securitytrails",
}

DEFAULT_CACHE = Path.home() / ".cache" / "nova_osint"
DEFAULT_CONFIG_PATH = Path.home() / ".config" / "nova-osint" / "config.json"
DEFAULT_OUTPUT_DIR = Path("./output")

#: The file written on first run. Every value here is also the fallback used
#: when the file is missing, unreadable or has that key removed.
DEFAULT_CONFIG: dict[str, Any] = {
    "settings": {
        "timeout": 12.0,
        "max_retries": 2,
        "max_concurrent_tasks": 24,
        "request_delay_min": 0.30,
        "request_delay_max": 0.45,
        "cache_enabled": True,
        "cache_ttl": 3600.0,
        "verify_tls": True,
        "user_agent": "",
        "output_directory": "./output",
        "passive_only": False,
        "max_sites": 0,
    },
    "proxies": {
        "enabled": False,
        "http": "",
        "https": "",
        "socks5": "",
    },
    "api_keys": dict.fromkeys(KEY_ENV, ""),
    "modules_enabled": {},
    #: Free-form switches a single module reads via ``config.option(name)``.
    #: A new module can add one without touching this file's schema.
    "module_options": {
        "securitytrails_depth": "basic",
        #: The optional local model. Off unless asked for, on your own machine
        #: unless explicitly allowed elsewhere, and free either way - see
        #: ``nova assist status``.
        "assist": False,
        "assist_provider": "ollama",
        "assist_url": "http://127.0.0.1:11434",
        "assist_model": "llama3.2:3b",
        "assist_allow_remote": False,
    },
}

#: (minimum, maximum) for the numeric settings. Anything outside is clamped and
#: logged rather than rejected - a silly timeout should not stop a scan.
_BOUNDS: dict[str, tuple[float, float]] = {
    "timeout": (0.5, 300.0),
    "max_retries": (0, 10),
    "max_concurrent_tasks": (1, 128),
    "request_delay_min": (0.0, 60.0),
    "request_delay_max": (0.0, 60.0),
    "cache_ttl": (0.0, 30 * 24 * 3600.0),
    "max_sites": (0, 100_000),
}


@dataclass
class Config:
    """The resolved settings one scan runs with.

    This is what modules see. :class:`ConfigManager` builds it; nothing in a
    module ever reads a file or an environment variable directly.
    """

    timeout: float = 12.0
    concurrency: int = 24
    per_host_delay: float = 0.30
    #: Upper end of the per-host delay range; each wait is drawn from
    #: ``[per_host_delay, per_host_delay_max]``.
    per_host_delay_max: float = 0.45
    retries: int = 2
    cache_dir: Path | None = field(default=None)
    cache_ttl: float = 3600.0
    proxy: str | None = None
    verify_tls: bool = True
    user_agent: str | None = None
    output_dir: Path = field(default_factory=lambda: DEFAULT_OUTPUT_DIR)
    #: Passive mode never sends a request to infrastructure the target owns;
    #: it only queries third-party archives and registries.
    passive_only: bool = False
    #: Cap on username sites / subdomain probes, so a scan stays bounded.
    max_sites: int = 0  # 0 = no cap
    keys: dict[str, str] = field(default_factory=dict)
    #: Module names switched off in config.json (``modules_enabled``).
    disabled_modules: frozenset[str] = frozenset()
    #: Per-module switches that only one module cares about, kept here so the
    #: module signature does not have to widen for every new flag.
    options: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls, **overrides: object) -> Config:
        """Build a config from the environment alone, ignoring config.json.

        Kept for callers that want the old zero-file behaviour (the tests and
        the desktop app's boot screen both do).
        """
        cfg = cls(keys=_keys_from_env())
        register_secrets(cfg.keys.values())
        return cfg.with_overrides(**overrides)

    def with_overrides(self, **overrides: object) -> Config:
        """Return a copy with any non-``None`` override applied."""
        changes = {k: v for k, v in overrides.items()
                   if v is not None and k in self.__dataclass_fields__}
        return replace(self, **changes) if changes else self

    # ------------------------------------------------------------------- keys

    def key(self, name: str) -> str | None:
        return self.keys.get(name)

    def has(self, name: str) -> bool:
        return bool(self.keys.get(name))

    @property
    def available_keys(self) -> list[str]:
        return sorted(self.keys)

    # ---------------------------------------------------------------- options

    def option(self, name: str, default: Any = None) -> Any:
        return self.options.get(name, default)

    def set_option(self, name: str, value: Any) -> None:
        self.options[name] = value


def runtime_config(path: Path | None = None, **overrides: Any) -> Config:
    """The config a scan should run with: file, then environment, then overrides.

    One line so the GUI and any other caller cannot accidentally skip
    ``config.json`` the way an earlier version did by reaching straight for
    :meth:`Config.from_env`.
    """
    return ConfigManager(path).load().to_config(**overrides)


def _keys_from_env() -> dict[str, str]:
    found = {}
    for short, env in KEY_ENV.items():
        value = os.environ.get(env, "").strip()
        if value:
            found[short] = value
    return found


class ConfigManager:
    """Loads, validates and writes ``config.json``.

    Every method is written to keep the application alive: a missing file is
    created, a malformed file falls back to defaults with a warning, an
    out-of-range number is clamped, and an unknown key is reported and ignored.
    One bad setting never stops a scan.

    Problems found along the way are collected in :attr:`problems` so the CLI
    can show them once instead of the loader printing from inside a library.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else DEFAULT_CONFIG_PATH
        self.data: dict[str, Any] = _deep_copy(DEFAULT_CONFIG)
        self.problems: list[str] = []
        self.loaded_from_file = False

    # ------------------------------------------------------------------- load

    def load(self, *, create: bool = True) -> ConfigManager:
        """Read the file, or create it with defaults when it is missing."""
        if not self.path.exists():
            if create:
                self.write_default()
            else:
                log.debug("no config file at %s; using built-in defaults", self.path)
            self._validate()
            return self

        try:
            raw = self.path.read_text("utf-8")
        except OSError as exc:
            self.problems.append(f"could not read {self.path}: {exc}; using defaults")
            self._validate()
            return self

        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            self.problems.append(
                f"{self.path} is not valid JSON (line {exc.lineno}, column {exc.colno}: "
                f"{exc.msg}); using defaults"
            )
            self._validate()
            return self

        if not isinstance(parsed, dict):
            self.problems.append(f"{self.path} must contain a JSON object; using defaults")
            self._validate()
            return self

        self.data = _merge(_deep_copy(DEFAULT_CONFIG), parsed)
        self.loaded_from_file = True
        self._check_permissions()
        self._validate()
        return self

    def write_default(self) -> bool:
        """Create the config file with the defaults. Never raises."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(DEFAULT_CONFIG, indent=4) + "\n", "utf-8")
            _restrict_permissions(self.path)
        except OSError as exc:
            self.problems.append(f"could not create {self.path}: {exc}; using defaults")
            return False
        log.info("wrote default configuration to %s", self.path)
        return True

    def save(self) -> bool:
        """Write the current in-memory configuration back to disk."""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=4) + "\n", "utf-8")
            _restrict_permissions(self.path)
        except OSError as exc:
            self.problems.append(f"could not write {self.path}: {exc}")
            return False
        return True

    # -------------------------------------------------------------- accessors

    def get(self, dotted: str, default: Any = None) -> Any:
        """``get("settings.timeout")`` - safe on any shape of loaded data."""
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[parts[-1]] = value

    def module_enabled(self, name: str) -> bool:
        toggles = self.get("modules_enabled", {})
        if not isinstance(toggles, dict):
            return True
        return bool(toggles.get(name, True))

    @property
    def disabled_modules(self) -> frozenset[str]:
        toggles = self.get("modules_enabled", {})
        if not isinstance(toggles, dict):
            return frozenset()
        return frozenset(name for name, on in toggles.items() if on is False)

    def redacted(self) -> dict[str, Any]:
        """The configuration with every API key masked - safe to print or log."""
        copy = _deep_copy(self.data)
        keys = copy.get("api_keys")
        if isinstance(keys, dict):
            copy["api_keys"] = {
                name: ("set (hidden)" if str(value).strip() else "")
                for name, value in keys.items()
            }
        return copy

    # ------------------------------------------------------------ resolution

    def resolved_keys(self) -> dict[str, str]:
        """Merge file keys with environment keys. The environment wins.

        Not called ``keys`` because this object is not a mapping and reading
        ``manager.keys()`` as "the dict keys" would be a very easy mistake.
        """
        resolved: dict[str, str] = {}
        raw = self.get("api_keys", {})
        if isinstance(raw, dict):
            for name, value in raw.items():
                text = str(value or "").strip()
                if not text:
                    continue
                short = KEY_ALIASES.get(name.lower(), name.lower())
                if short not in KEY_ENV:
                    self.problems.append(
                        f"api_keys.{name} is not a key this tool uses; ignored "
                        f"(known: {', '.join(sorted(KEY_ENV))})"
                    )
                    continue
                resolved[short] = text
        resolved.update(_keys_from_env())
        register_secrets(resolved.values())
        return resolved

    def proxy(self) -> str | None:
        """The proxy URL to use, or ``None``.

        ``urllib`` speaks HTTP proxies only. A SOCKS5 proxy is reported as
        unsupported rather than silently ignored, because "my traffic was not
        going where I thought" is the worst possible surprise in this tool.
        """
        block = self.get("proxies", {})
        if not isinstance(block, dict) or not block.get("enabled"):
            return None
        https = str(block.get("https") or "").strip()
        http = str(block.get("http") or "").strip()
        socks = str(block.get("socks5") or "").strip()
        if socks and not (http or https):
            self.problems.append(
                "proxies.socks5 is set but the stdlib HTTP client cannot use SOCKS "
                "directly; run a local HTTP-to-SOCKS bridge and set proxies.http instead"
            )
            return None
        return https or http or None

    def to_config(self, **overrides: Any) -> Config:
        """Build the :class:`Config` a scan runs with.

        ``overrides`` are the command-line flags; ``None`` means "not given",
        so a flag left off falls through to the file, then to the default.
        """
        settings = self.get("settings", {})
        settings = settings if isinstance(settings, dict) else {}

        cache_enabled = bool(settings.get("cache_enabled", True))
        output_dir = str(settings.get("output_directory") or DEFAULT_OUTPUT_DIR)
        user_agent = str(settings.get("user_agent") or "").strip() or None

        cfg = Config(
            timeout=float(settings.get("timeout", 12.0)),
            concurrency=int(settings.get("max_concurrent_tasks", 24)),
            per_host_delay=float(settings.get("request_delay_min", 0.30)),
            per_host_delay_max=float(settings.get("request_delay_max", 0.45)),
            retries=int(settings.get("max_retries", 2)),
            cache_dir=(DEFAULT_CACHE / "http") if cache_enabled else None,
            cache_ttl=float(settings.get("cache_ttl", 3600.0)),
            proxy=self.proxy(),
            verify_tls=bool(settings.get("verify_tls", True)),
            user_agent=user_agent,
            output_dir=Path(output_dir),
            passive_only=bool(settings.get("passive_only", False)),
            max_sites=int(settings.get("max_sites", 0)),
            keys=self.resolved_keys(),
            disabled_modules=self.disabled_modules,
            options=self.module_options(),
        )
        return cfg.with_overrides(**overrides)

    def module_options(self) -> dict[str, Any]:
        """The ``module_options`` block, as a plain dict for ``Config.options``.

        Command-line switches are applied on top of this by the CLI, so a flag
        still beats the file.
        """
        block = self.get("module_options", {})
        return dict(block) if isinstance(block, dict) else {}

    # ------------------------------------------------------------- validation

    def _validate(self) -> None:
        """Clamp and coerce every setting. Collects problems, never raises."""
        settings = self.data.get("settings")
        if not isinstance(settings, dict):
            self.problems.append("'settings' must be an object; using defaults")
            self.data["settings"] = _deep_copy(DEFAULT_CONFIG["settings"])
            settings = self.data["settings"]

        for name, (low, high) in _BOUNDS.items():
            if name not in settings:
                continue
            default = DEFAULT_CONFIG["settings"][name]
            value = settings[name]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                self.problems.append(
                    f"settings.{name} must be a number, got {value!r}; using {default}"
                )
                settings[name] = default
                continue
            if not low <= value <= high:
                clamped = min(max(value, low), high)
                self.problems.append(
                    f"settings.{name}={value} is outside {low}..{high}; using {clamped}"
                )
                settings[name] = clamped

        for name in ("cache_enabled", "verify_tls", "passive_only"):
            if name in settings and not isinstance(settings[name], bool):
                default = DEFAULT_CONFIG["settings"][name]
                self.problems.append(
                    f"settings.{name} must be true or false; using {default}"
                )
                settings[name] = default

        # Integers that must really be integers, not 24.7 workers.
        for name in ("max_concurrent_tasks", "max_retries", "max_sites"):
            if name in settings:
                settings[name] = int(settings[name])

        lo = float(settings.get("request_delay_min", 0.0))
        hi = float(settings.get("request_delay_max", lo))
        if hi < lo:
            self.problems.append(
                f"settings.request_delay_max ({hi}) is below request_delay_min ({lo}); "
                f"using {lo} for both"
            )
            settings["request_delay_max"] = lo

        toggles = self.data.get("modules_enabled")
        if toggles is not None and not isinstance(toggles, dict):
            self.problems.append("'modules_enabled' must be an object; ignored")
            self.data["modules_enabled"] = {}

        if not self.get("settings.verify_tls", True):
            self.problems.append(
                "settings.verify_tls is false: TLS certificates will NOT be checked"
            )

    def _check_permissions(self) -> None:
        """Warn when a file holding keys is readable by other users."""
        keys = self.get("api_keys", {})
        if not isinstance(keys, dict) or not any(str(v).strip() for v in keys.values()):
            return
        try:
            mode = self.path.stat().st_mode
        except OSError:
            return
        if mode & (stat.S_IRGRP | stat.S_IROTH):
            self.problems.append(
                f"{self.path} contains API keys and is readable by other users; "
                f"run: chmod 600 {self.path}"
            )


# --------------------------------------------------------------------- helpers


def _deep_copy(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _deep_copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_copy(v) for v in value]
    return value


def _merge(base: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Overlay ``incoming`` onto ``base``, recursing into nested objects.

    A user file that only sets ``settings.timeout`` keeps every other default,
    which is what makes a partial config.json safe to hand-write.
    """
    for key, value in incoming.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _merge(base[key], value)
        else:
            base[key] = value
    return base


def _restrict_permissions(path: Path) -> None:
    """Best-effort ``chmod 600``. A no-op on filesystems that do not care."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


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
    register_secrets(_keys_from_env().values())
    return count
