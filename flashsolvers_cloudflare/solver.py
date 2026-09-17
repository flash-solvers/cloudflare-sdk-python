import base64
import json
import time
import urllib.error
import urllib.request

from .tls import TLSError, TLSSession

DEFAULT_ENDPOINT = "https://cf.flashsolvers.com"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36"
)
DEFAULT_MAX_ATTEMPTS = 3
CLEARANCE_COOKIE = "cf_clearance"
_API_USER_AGENT = "flashsolvers-cloudflare-python/0.1.0"


class CloudflareError(Exception):
    """Base class for every error this package raises."""


class APIError(CloudflareError):
    """A request the Flash Solvers API rejected, such as a bad key or an unsupported host."""

    def __init__(self, status, code, message, retry_safe=False, request_id=None, retry_after=0.0):
        super().__init__("api %s %s: %s (request %s)" % (status, code, message, request_id))
        self.status = status
        self.code = code
        self.message = message
        self.retry_safe = retry_safe
        self.request_id = request_id
        self.retry_after = retry_after


class SolveError(CloudflareError):
    """A solve the API ended with kind "error" or "aborted"."""

    def __init__(self, kind, owner=None, retry_safe=False):
        super().__init__("solve failed: %s (owner %s, retrySafe %s)" % (kind, owner, retry_safe))
        self.kind = kind
        self.owner = owner
        self.retry_safe = retry_safe


class NotClearedError(CloudflareError):
    """Every attempt finished without a cf_clearance cookie."""

    def __init__(self):
        super().__init__("challenge not cleared")


class SolveResult:
    """A cleared challenge. Send cookies with user_agent, through the same proxy."""

    def __init__(self, clearance, cookies, user_agent, attempts):
        self.clearance = clearance
        self.cookies = cookies
        self.user_agent = user_agent
        self.attempts = attempts

    def __repr__(self):
        return "SolveResult(clearance=%r..., attempts=%d)" % (self.clearance[:12], self.attempts)


class CloudflareSolver:
    """Solves the Cloudflare WAF challenge with the Flash Solvers API.

    The API only generates each step. Every request to the protected site is made
    from this process, with a Chrome TLS fingerprint, your proxy and a fresh cookie jar.
    Safe to use from several threads at once.
    """

    def __init__(self, api_key, proxy=None, endpoint=DEFAULT_ENDPOINT, user_agent=DEFAULT_USER_AGENT,
                 max_attempts=DEFAULT_MAX_ATTEMPTS, api_timeout=60):
        if not api_key:
            raise ValueError("api_key is required")
        self.api_key = api_key
        self.proxy = proxy
        self.endpoint = endpoint.rstrip("/")
        self.user_agent = user_agent
        self.max_attempts = max(1, int(max_attempts))
        self.api_timeout = api_timeout

    def solve(self, url):
        """Clears the challenge on url and returns a SolveResult."""
        last = NotClearedError()
        for attempt in range(1, self.max_attempts + 1):
            # A failed attempt taints its session, so every attempt starts a new one.
            session = TLSSession(self.proxy)
            try:
                clearance, wait, err = self._attempt(session, url)
                if clearance:
                    try:
                        cookies = {c["name"]: c["value"] for c in session.cookies(url)}
                    except TLSError:
                        cookies = {}
                    cookies[CLEARANCE_COOKIE] = clearance
                    return SolveResult(clearance, cookies, self.user_agent, attempt)
            finally:
                session.close()
            if err is not None:
                last = err
                if not getattr(err, "retry_safe", True):
                    raise err
            if attempt < self.max_attempts and wait > 0:
                time.sleep(wait)
        raise last

    def _attempt(self, session, url):
        """Runs one solve. Returns (clearance, seconds to wait before retrying, error)."""
        try:
            out = self._call({"start": {
                "url": url, "userAgent": self.user_agent,
                "finishAtForm": True, "clientPacingV1": True, "clientJarWritesV1": True,
            }})
        except APIError as e:
            return None, e.retry_after, e
        while True:
            kind = out.get("kind")
            if kind == "request":
                response = self._perform(session, out)
                try:
                    out = self._call({"context": out["context"], "sequence": out["sequence"], "response": response})
                except APIError as e:
                    return None, e.retry_after, e
            elif kind == "final":
                response = self._perform(session, out)
                if "error" in response:
                    return None, 0, CloudflareError("form POST: " + response["error"])
                if any(h["name"].lower() == "cf-mitigated" for h in response["headers"]):
                    return None, 0, NotClearedError()
                return _clearance(session.cookies(out["payloadUrl"])), 0, None
            elif kind == "complete":
                result = out.get("result") or {}
                if result.get("outcome") == "cleared":
                    return result.get("clearance") or _clearance(session.cookies(url)), 0, None
                return None, _next_wait(out), NotClearedError()
            elif kind in ("error", "aborted"):
                failure = out.get("failure") or {}
                err = SolveError(failure.get("kind", kind), failure.get("owner"),
                                 bool(failure.get("retrySafe")) or bool(out.get("next")))
                return None, _next_wait(out), err
            else:
                return None, 0, CloudflareError("unexpected step kind %r" % kind)

    def _perform(self, session, step):
        """Makes the origin request the API described and returns the step response."""
        pacing_us = 0
        if step.get("pacingMs"):
            started = time.perf_counter()
            time.sleep(step["pacingMs"] / 1000.0)
            pacing_us = int((time.perf_counter() - started) * 1e6)
        if step.get("setCookies"):
            session.add_cookies(step["payloadUrl"], [_jar_cookie(c) for c in step["setCookies"]])
        headers = [(h["name"], h["value"]) for h in step.get("headers") or []]
        started = time.perf_counter()
        try:
            status, resp_headers, body = session.request(
                step["method"], step["payloadUrl"], headers, step.get("headerOrder") or [],
                body=step.get("payload") or None, host=step.get("host"), timeout_ms=step.get("timeoutMs") or 0,
            )
        except TLSError as e:
            return {"error": str(e), "timing": {
                "durationMs": int((time.perf_counter() - started) * 1000), "pacingUs": pacing_us}}
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        response = {
            "status": status,
            "headers": [{"name": k, "value": v} for k, values in resp_headers.items() for v in values],
            "timing": {"requestStartMs": 0, "responseStartMs": elapsed_ms, "durationMs": elapsed_ms,
                       "pacingUs": pacing_us},
        }
        try:
            response["data"] = body.decode("utf-8")
        except UnicodeDecodeError:
            response["dataBin"] = base64.b64encode(body).decode("ascii")
        length = next((v[0] for k, v in resp_headers.items() if k.lower() == "content-length" and v), None)
        if length is not None and length.isdigit():
            response["timing"]["wireBytes"] = int(length)
        return response

    def _call(self, body):
        req = urllib.request.Request(
            self.endpoint + "/v1/step", data=json.dumps(body).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "x-api-key": self.api_key, "User-Agent": _API_USER_AGENT},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.api_timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                data = json.loads(raw)
            except ValueError:
                data = {"error": raw.strip()}
            retry_safe = bool(data.get("retrySafe")) or e.code == 429
            retry_after = 0.0
            if retry_safe:
                header = e.headers.get("Retry-After", "")
                retry_after = float(header) if header.isdigit() and int(header) > 0 else 1.0
            raise APIError(e.code, data.get("code"), data.get("error"), retry_safe,
                           data.get("requestId"), retry_after)
        except urllib.error.URLError as e:
            raise CloudflareError("api: %s" % e.reason)


def _jar_cookie(c):
    cookie = {"name": c["name"], "value": c["value"], "secure": bool(c.get("secure"))}
    if c.get("path"):
        cookie["path"] = c["path"]
    if c.get("expiresUnix", 0) > 0:
        cookie["expires"] = c["expiresUnix"]
    return cookie


def _clearance(cookies):
    return next((c["value"] for c in cookies if c["name"] == CLEARANCE_COOKIE), None)


def _next_wait(out):
    nxt = out.get("next") or {}
    return (nxt.get("retryAfterMs") or 0) / 1000.0
