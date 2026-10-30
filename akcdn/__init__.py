"""AKCDN API — Python service (local / VPS)."""

VERSION = "1.0.0"
USER_AGENT = f"akcdn-api/{VERSION}"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)
AKILE_ORIGIN = "https://akile.ai"
AKILE_LOGIN_PAGE = "https://akile.ai/login"
AKILE_API = "https://api.akile.ai/api"
AKCDN_API = "https://cdnapi.akile.ai/api"
APP_ID = "akcdn-prod"
REDIRECT_URL = "https://cdn.akile.ai/oauth/callback"
DEFAULT_NODE_ID = 5  # SH-HK
# Soft expire for SESSION_FILE; expired/invalid → auto password re-login.
SESSION_SOFT_EXPIRE_SEC = 24 * 60 * 60
META_KEYS = frozenset({"dry_run", "delauto"})
