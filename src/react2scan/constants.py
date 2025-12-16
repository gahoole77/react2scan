"""Constants used throughout react2scan."""

# =============================================================================
# Default Configuration
# =============================================================================

# Request timeout in seconds.
# 5s provides a reasonable balance between:
# - Allowing slow servers time to respond
# - Not waiting too long for unresponsive targets
DEFAULT_TIMEOUT_SECONDS = 5

# Number of concurrent scan threads.
# 10 threads provides good throughput without overwhelming targets.
# Can be increased via --threads for faster scans (tested up to 50).
DEFAULT_THREADS = 10

# Maximum concurrent API requests to providers.
# Limits parallel API calls to respect rate limits and avoid throttling.
MAX_CONCURRENT_API_REQUESTS = 10

# =============================================================================
# Cloudflare-specific
# =============================================================================

# TTL value that Cloudflare uses to indicate "automatic"
CLOUDFLARE_AUTOMATIC_TTL = 1

# DNS record types we scan
SCANNABLE_RECORD_TYPES = frozenset({"A", "AAAA", "CNAME"})

# Cloudflare Managed WAF Ruleset ID
# https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/
CLOUDFLARE_MANAGED_RULESET_ID = "efb7b8c949ac4650a09736fc376e9aee"

# =============================================================================
# React2Shell Scanner
# =============================================================================

# Multipart form boundary (matches typical browser format)
MULTIPART_BOUNDARY = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad"

# Response snippet length for vulnerability reports
RESPONSE_SNIPPET_MAX_LENGTH = 500

# User agent string
USER_AGENT = "Mozilla/5.0 (compatible; react2scan/1.0)"

# Next.js-specific headers
NEXTJS_ACCEPT_HEADER = "text/x-component"
NEXTJS_ACTION_HEADER = "1"
NEXTJS_ROUTER_STATE_TREE = "%5B%22%22%2C%7B%7D%5D"  # URL-encoded: ["",{}]

# Default paths to test for Next.js RSC endpoints
DEFAULT_SCAN_PATHS = [
    "/",
    "/_next",
]

# Safe-mode vulnerability detection patterns (from Assetnote research)
# Primary check: 500 status with RSC error digest
SAFE_CHECK_ERROR_DIGEST = 'E{"digest"'
# Secondary patterns
SAFE_CHECK_PATTERNS = [
    "Error: Element type is invalid",
    "Cannot read properties of undefined",
]
SAFE_CHECK_REDIRECT_INDICATORS = ("NEXT_REDIRECT", "digest")
