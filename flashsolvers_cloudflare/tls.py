"""Chrome TLS sessions through bogdanfinn/tls-client's official shared library.

The library is downloaded once per machine from its GitHub release and checked
against a pinned SHA-256 before it is loaded.
"""

import base64
import ctypes
import hashlib
import json
import os
import platform
import sys
import tempfile
import threading
import urllib.request
import uuid

LIB_VERSION = "1.16.0"
TLS_PROFILE = "chrome_152"

_RELEASE_URL = "https://github.com/bogdanfinn/tls-client/releases/download/v{version}/{name}"

# (file name, sha256) per platform.
_ASSETS = {
    "windows-amd64": ("tls-client-windows-64-1.16.0.dll", "53dca636b32d965ee6fe4562f39df959b2063febaa3d740efa925d1873cf11d7"),
    "windows-386": ("tls-client-windows-32-1.16.0.dll", "5203a36f80ea3f9cdfa43bf072a775702d1802acb8e4304e78905210f67dd2af"),
    "linux-amd64": ("tls-client-linux-ubuntu-amd64-1.16.0.so", "2ec853496634545e7a7ea028715763948d55bbdd97aca7ecaa9fea8c2ebb08df"),
    "linux-musl-amd64": ("tls-client-linux-alpine-amd64-1.16.0.so", "83c8702e8e8af2e5629277f422e77384a8780ac63c7f20988269a82d78e835ae"),
    "linux-arm64": ("tls-client-linux-arm64-1.16.0.so", "e398622f99c0ce8fccb50ff6e414f373b5932a0277ece90468a796992f0ae518"),
    "linux-arm": ("tls-client-linux-armv7-1.16.0.so", "22baa029d4ee8cf327d10cda0e66c29cf256b3eb48e1fe9d6a76954b66f77711"),
    "darwin-amd64": ("tls-client-darwin-amd64-1.16.0.dylib", "6463457ea713a96b3b8c94fd9d8746e7bc510cb6784fcf0f4bb64d9c83e3251a"),
    "darwin-arm64": ("tls-client-darwin-arm64-1.16.0.dylib", "99984d013921c753ab29d28720cb099eff6adf63538347e13652cb5cfe5bdc02"),
}

_lib = None
_lib_lock = threading.Lock()


class TLSError(Exception):
    """The TLS library could not be loaded or a request could not be made."""


def _platform_key():
    machine = platform.machine().lower()
    arch = {
        "x86_64": "amd64", "amd64": "amd64", "x64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "i386": "386", "i686": "386", "x86": "386",
        "armv7l": "arm", "armv7": "arm", "armv6l": "arm",
    }.get(machine)
    if sys.platform == "win32":
        arch = "amd64" if sys.maxsize > 2**32 else "386"
        return "windows-" + arch
    if sys.platform == "darwin":
        return "darwin-" + (arch or "")
    if sys.platform.startswith("linux"):
        if arch == "amd64" and not platform.libc_ver()[0] and os.path.exists("/etc/alpine-release"):
            return "linux-musl-amd64"
        return "linux-" + (arch or "")
    return sys.platform + "-" + (arch or machine)


def _cache_dir():
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "flashsolvers", "tls-client")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _library_path():
    override = os.environ.get("FLASH_TLS_LIB")
    if override:
        return override
    key = _platform_key()
    if key not in _ASSETS:
        raise TLSError("no tls-client build for platform %s; set FLASH_TLS_LIB to a library path" % key)
    name, want = _ASSETS[key]
    path = os.path.join(_cache_dir(), name)
    if os.path.exists(path) and _sha256(path) == want:
        return path
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".part")
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(
            _RELEASE_URL.format(version=LIB_VERSION, name=name), timeout=120
        ) as resp:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                out.write(chunk)
        got = _sha256(tmp)
        if got != want:
            raise TLSError("tls-client download checksum mismatch: got %s, want %s" % (got, want))
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return path


def _load():
    global _lib
    with _lib_lock:
        if _lib is None:
            lib = ctypes.cdll.LoadLibrary(_library_path())
            for fn in ("request", "getCookiesFromSession", "addCookiesToSession", "destroySession"):
                getattr(lib, fn).argtypes = [ctypes.c_char_p]
                getattr(lib, fn).restype = ctypes.c_char_p
            lib.freeMemory.argtypes = [ctypes.c_char_p]
            lib.freeMemory.restype = None
            _lib = lib
    return _lib


def _call(fn, payload):
    lib = _load()
    raw = getattr(lib, fn)(json.dumps(payload).encode("utf-8"))
    out = json.loads(raw.decode("utf-8"))
    if out.get("id"):
        lib.freeMemory(out["id"].encode("utf-8"))
    return out


class TLSSession:
    """One browser session: a TLS client, a cookie jar and an optional proxy."""

    def __init__(self, proxy=None):
        self.id = str(uuid.uuid4())
        self.proxy = proxy

    def request(self, method, url, headers, header_order, body=None, host=None, timeout_ms=0):
        """Returns (status, headers, body bytes). Raises TLSError when there is no HTTP response."""
        payload = {
            "sessionId": self.id,
            "tlsClientIdentifier": TLS_PROFILE,
            "withRandomTLSExtensionOrder": True,
            "followRedirects": False,
            "disableHttp3": True,
            "isByteResponse": True,
            "catchPanics": True,
            "requestMethod": method,
            "requestUrl": url,
            "headers": dict(headers),
            "headerOrder": list(header_order),
            "timeoutMilliseconds": timeout_ms or 60000,
        }
        if body:
            payload["requestBody"] = body
        if host:
            payload["requestHostOverride"] = host
        if self.proxy:
            payload["proxyUrl"] = self.proxy
        out = _call("request", payload)
        if out.get("status", 0) == 0:
            raise TLSError(out.get("body") or "request failed")
        data = out.get("body") or ""
        comma = data.find(",")
        content = base64.b64decode(data[comma + 1:]) if data.startswith("data:") and comma >= 0 else b""
        return out["status"], out.get("headers") or {}, content

    def cookies(self, url):
        """Returns the jar's cookies for url as a list of dicts."""
        out = _call("getCookiesFromSession", {"sessionId": self.id, "url": url})
        if "status" in out:
            raise TLSError(out.get("body") or "get cookies failed")
        return out["cookies"] or []

    def add_cookies(self, url, cookies):
        out = _call("addCookiesToSession", {"sessionId": self.id, "url": url, "cookies": cookies})
        if "status" in out:
            raise TLSError(out.get("body") or "add cookies failed")

    def close(self):
        _call("destroySession", {"sessionId": self.id})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
