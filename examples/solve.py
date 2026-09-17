"""Solve a Cloudflare challenge and print the cf_clearance cookie.

    FLASH_API_KEY=... python examples/solve.py https://example.com/
"""

import os
import sys

from flashsolvers_cloudflare import CloudflareSolver

solver = CloudflareSolver(
    api_key=os.environ["FLASH_API_KEY"],
    proxy=os.environ.get("PROXY"),
    endpoint=os.environ.get("FLASH_ENDPOINT", "https://cf.flashsolvers.com"),
)
result = solver.solve(sys.argv[1])
print("cf_clearance=%s\nattempts=%d" % (result.clearance, result.attempts))
