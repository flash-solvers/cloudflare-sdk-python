# Flash Solvers Cloudflare SDK for Python

Solve the Cloudflare WAF challenge ("Just a moment...") with the [Flash Solvers](https://docs.flashsolvers.com/) API and get a `cf_clearance` cookie.

The API only generates each step of the challenge.
Every request to the protected site is made from your machine, with a Chrome 152 TLS fingerprint, your proxy and your cookie jar.

## Install

```sh
pip install "git+https://github.com/flash-solvers/cloudflare-sdk-python"
```

Requires Python 3.8 or newer. There are no Python dependencies.

On first use the SDK downloads the official [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) v1.16.0 shared library (about 20 MB) into your cache folder and checks its SHA-256.
Supported: Windows x64/x86, Linux x64/arm64/armv7 (glibc and Alpine), macOS x64/arm64.
To use a library you already have, set `FLASH_TLS_LIB` to its path.

## Usage

```python
from flashsolvers_cloudflare import CloudflareSolver

solver = CloudflareSolver(
    api_key="your-api-key",
    proxy="http://user:pass@host:port",
)

result = solver.solve("https://shop.axs.com/")
print("cf_clearance:", result.clearance)
print(result.cookies)     # all cookies for the solved URL
print(result.user_agent)  # send this with the cookies
```

Use the cookies with the same proxy IP and `result.user_agent`, or Cloudflare will challenge you again.
A solver is safe to share between threads.

## Options

| Argument | Default | Description |
|---|---|---|
| `api_key` | required | Your Flash Solvers API key |
| `proxy` | `None` | `http://`, `https://` or `socks5://` proxy for every request to the site |
| `max_attempts` | `3` | Solves to start before giving up |
| `user_agent` | Chrome 152 on macOS | Must match the API's browser profile. Leave it unset |
| `endpoint` | `https://cf.flashsolvers.com` | API base URL |
| `api_timeout` | `60` | Seconds per API call |

## Result

| Attribute | Description |
|---|---|
| `clearance` | The `cf_clearance` cookie value |
| `cookies` | `dict` of all cookies for the solved URL |
| `user_agent` | User agent to send with the cookies |
| `attempts` | How many solves were started |

## Errors

All errors subclass `CloudflareError`.

| Error | Cause | Retried |
|---|---|---|
| `APIError` with `code` `host_not_allowed` | The site is not supported | No |
| `APIError` with `code` `invalid_key`, `key_expired`, `insufficient_balance` | Key or balance problem | No |
| `APIError` with `code` `at_capacity` | Too many solves in flight | Yes, after `Retry-After` |
| `SolveError` | The solve failed. `kind` says why, such as `origin_refused` | When `retry_safe` |
| `NotClearedError` | Cloudflare did not accept any attempt | Each attempt is retried until `max_attempts` |
| `TLSError` | The TLS library could not load or make a request | No |

Each retry uses a fresh session, because Cloudflare keeps rejecting a session that failed once.
A proxy IP that keeps failing is usually flagged; rotate it.

## Supported sites and pricing

See the [Flash Solvers docs](https://docs.flashsolvers.com/#cloudflare-overview).
You are charged once per solve that reaches the final form, never for failures.
