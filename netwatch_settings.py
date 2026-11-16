"""
Saved settings for NetWatch.

NetWatch reads its options from NETWATCH_* environment variables. `sudo` drops
those unless you remember `sudo -E`, so this module keeps a small file,
`settings.env` in the config directory, and loads it into the environment at
start-up. A variable that is already set in the real environment wins.

Only the settings in SETTINGS can be saved. Options that change who may log in
or which program is run (tokens, tier, allow-lists, binary paths) are left out
on purpose: they stay explicit, on the command line.

No NetWatch imports: the module is loaded before anything else is configured.
"""
import os
import re
import stat

MAX_FILE_BYTES = 64 * 1024
MAX_VALUE_CHARS = 2000

# short name -> (environment variable, kind, description)
SETTINGS = {
    "nvd-key":        ("NETWATCH_NVD_API_KEY",   "secret", "NVD API key for the cve command (free, 10x faster)"),
    "ipinfo-token":   ("NETWATCH_IPINFO_TOKEN",  "secret", "IPinfo Lite token: HTTPS geo lookups, commercial use allowed"),
    "ipapi-key":      ("NETWATCH_IPAPI_KEY",     "secret", "ip-api.com paid key: HTTPS, city and proxy detail"),
    "whitelist":      ("NETWATCH_WHITELIST",     "iplist", "Addresses that skip threat scoring (comma list)"),
    "mesh-port":      ("NETWATCH_MESH_PORT",     "device", "Serial device of the Meshtastic radio"),
    "mesh-timeout":   ("NETWATCH_MESH_TIMEOUT",  "int:5:300", "Seconds to wait for the radio's config"),
    "retention-days": ("NETWATCH_RETENTION_DAYS", "int:1:3650", "Days of logs to keep"),
    "http-port":      ("NETWATCH_HTTP_PORT",     "port", "HTTP honeypot port (restart to apply)"),
    "telnet-port":    ("NETWATCH_TELNET_PORT",   "port", "Telnet honeypot port (restart to apply)"),
    "ftp-port":       ("NETWATCH_FTP_PORT",      "port", "FTP honeypot port (restart to apply)"),
    "rtsp-port":      ("NETWATCH_RTSP_PORT",     "port", "RTSP honeypot port (restart to apply)"),
}
_BY_ENV = {env: name for name, (env, _kind, _desc) in SETTINGS.items()}
NEEDS_RESTART = {"NETWATCH_HTTP_PORT", "NETWATCH_TELNET_PORT", "NETWATCH_FTP_PORT",
                 "NETWATCH_RTSP_PORT", "NETWATCH_RETENTION_DAYS"}

_SECRET_RE = re.compile(r"^[A-Za-z0-9._~+/=\-]{8,200}$")
_IPLIST_RE = re.compile(r"^[0-9A-Fa-f:., ]{1,%d}$" % MAX_VALUE_CHARS)
_DEVICE_RE = re.compile(r"^/dev/(tty[A-Za-z]+[0-9]{0,3}|serial/by-(id|path)/[A-Za-z0-9._:\-]{1,120})$")


def resolve(name):
    """Short name or NETWATCH_* name -> environment variable, or None."""
    if not isinstance(name, str):
        return None
    key = name.strip()
    if key.lower() in SETTINGS:
        return SETTINGS[key.lower()][0]
    return key.upper() if key.upper() in _BY_ENV else None


def short_name(env_key):
    return _BY_ENV.get(env_key, env_key)


def kind_of(env_key):
    return SETTINGS[_BY_ENV[env_key]][1]


def validate(env_key, value):
    """(True, cleaned value) or (False, reason)."""
    if env_key not in _BY_ENV:
        return False, "not a setting that can be saved"
    if not isinstance(value, str):
        return False, "value must be text"
    value = value.strip()
    if not value:
        return False, "value is empty"
    if len(value) > MAX_VALUE_CHARS or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return False, "value is too long or has control characters"
    kind = kind_of(env_key)
    if kind == "secret":
        return (True, value) if _SECRET_RE.match(value) else (False, "expected 8-200 letters, digits or . _ - ~ + / =")
    if kind == "iplist":
        return (True, value) if _IPLIST_RE.match(value) else (False, "expected IP addresses separated by commas")
    if kind == "device":
        return (True, value) if _DEVICE_RE.match(value) else (False, "expected a serial device, for example /dev/ttyACM0")
    if kind == "port" or kind.startswith("int:"):
        low, high = (1, 65535) if kind == "port" else map(int, kind.split(":")[1:])
        if not value.isdigit() or not low <= int(value) <= high:
            return False, f"expected a number from {low} to {high}"
        return True, str(int(value))
    return False, "unknown kind"


def read_file(path):
    """Parse settings.env -> (valid {env: value}, rejected [text]).

    The file is ignored as a whole when it is not a plain file owned by this
    user (or root), or when group/others can write it: the process may run as
    root, so nobody else may feed it settings."""
    try:
        st = os.lstat(path)
    except OSError:
        return {}, []
    if not stat.S_ISREG(st.st_mode):
        return {}, [f"{path}: not a regular file, ignored"]
    if st.st_uid not in (os.geteuid(), 0):
        return {}, [f"{path}: owned by another user, ignored"]
    if st.st_mode & 0o022:
        return {}, [f"{path}: writable by group or others, ignored (chmod 600)"]
    if st.st_size > MAX_FILE_BYTES:
        return {}, [f"{path}: too large, ignored"]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read(MAX_FILE_BYTES).splitlines()
    except (OSError, UnicodeDecodeError):
        return {}, [f"{path}: cannot be read, ignored"]
    valid, rejected = {}, []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env_key = resolve(key) if sep else None
        if not env_key:
            rejected.append(f"{key[:40]}: not a setting that can be saved")
            continue
        ok, cleaned = validate(env_key, value)
        if ok:
            valid[env_key] = cleaned
        else:
            rejected.append(f"{short_name(env_key)}: {cleaned}")
    return valid, rejected


def load(path, environ=None):
    """Put saved settings into the environment. Returns (applied, rejected).
    A variable already present in the environment is left as it is."""
    environ = os.environ if environ is None else environ
    valid, rejected = read_file(path)
    applied = {}
    for env_key, value in valid.items():
        if not environ.get(env_key, "").strip():
            environ[env_key] = value
            applied[env_key] = value
    return applied, rejected


def save(path, env_key, value):
    """Set (or, with value None, remove) one setting. Returns (ok, message).
    The file is rewritten in one step, mode 0600."""
    if env_key not in _BY_ENV:
        return False, "not a setting that can be saved"
    if value is not None:
        ok, value = validate(env_key, value)
        if not ok:
            return False, value
    current, _rejected = read_file(path)
    if value is None:
        if env_key not in current:
            return False, "not set in the settings file"
        del current[env_key]
    else:
        current[env_key] = value
    body = "# NetWatch saved settings. Change with: config set <name> <value>\n" + "".join(
        f"{key}={current[key]}\n" for key in sorted(current))
    tmp = f"{path}.tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True, mode=0o700)
        try:
            os.unlink(tmp)       # never write through a file somebody left there
        except FileNotFoundError:
            pass
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, path)
    except OSError as exc:
        return False, f"cannot write {path}: {exc.strerror or type(exc).__name__}"
    return True, value if value is not None else ""


def mask(env_key, value):
    """Value as it may be shown on screen: secrets show the last 4 characters."""
    if not value:
        return ""
    if kind_of(env_key) == "secret":
        return "*" * 8 + value[-4:] if len(value) > 8 else "*" * 8
    return value if len(value) <= 60 else value[:57] + "..."


def describe(path, environ=None):
    """One row per setting: (short name, shown value, source, description).
    source is 'file', 'environment' or '' (not set)."""
    environ = os.environ if environ is None else environ
    saved, _rejected = read_file(path)
    rows = []
    for name, (env_key, _kind, desc) in SETTINGS.items():
        live = environ.get(env_key, "").strip()
        if live and saved.get(env_key) == live:
            source = "file"
        elif live:
            source = "environment"
        else:
            source = ""
        rows.append((name, mask(env_key, live), source, desc))
    return rows
