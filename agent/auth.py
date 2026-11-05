"""
Agent Authentication — Issue 4/5
• First run: prompt user to create credentials
• Credentials stored as bcrypt hash in ~/.soc_agent_creds
• On startup: login dialog required before GUI opens
• Generates session token after successful login
• All server requests carry token in Authorization header
"""
import hashlib, json, logging, os, secrets, time
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("agent-auth")

CREDS_FILE = Path(os.path.expanduser("~")) / ".soc_agent_creds"
TOKEN_TTL  = 8 * 3600   # 8 hours


# ── Password hashing (bcrypt preferred, sha256 fallback) ─────────────────────
def _hash_password(password: str) -> str:
    try:
        import bcrypt  # type: ignore
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except ImportError:
        salt = secrets.token_hex(16)
        h    = hashlib.sha256((salt + password).encode()).hexdigest()
        return f"sha256:{salt}:{h}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        import bcrypt  # type: ignore
        return bcrypt.checkpw(password.encode(), stored.encode())
    except ImportError:
        pass
    if stored.startswith("sha256:"):
        _, salt, h = stored.split(":", 2)
        return hashlib.sha256((salt + password).encode()).hexdigest() == h
    return False


# ── Credential store ──────────────────────────────────────────────────────────
def credentials_exist() -> bool:
    return CREDS_FILE.exists()


def save_credentials(username: str, password: str) -> bool:
    try:
        data = {
            "username":      username.strip(),
            "password_hash": _hash_password(password),
            "created_at":    time.time(),
        }
        CREDS_FILE.write_text(json.dumps(data))
        if os.name != "nt":
            os.chmod(CREDS_FILE, 0o600)
        return True
    except Exception as e:
        logger.error("Failed to save credentials: %s", e)
        return False


def verify_credentials(username: str, password: str) -> bool:
    try:
        data  = json.loads(CREDS_FILE.read_text())
        if data.get("username", "").lower() != username.strip().lower():
            return False
        return _verify_password(password, data["password_hash"])
    except Exception as e:
        logger.error("Credential verification error: %s", e)
        return False


def get_stored_username() -> str:
    try:
        return json.loads(CREDS_FILE.read_text()).get("username", "")
    except Exception:
        return ""


# ── Session token ─────────────────────────────────────────────────────────────
_current_token: Optional[str]  = None
_token_expiry:  float          = 0.0


def create_session_token(username: str) -> str:
    global _current_token, _token_expiry
    _current_token = secrets.token_urlsafe(32)
    _token_expiry  = time.time() + TOKEN_TTL
    logger.info("Session token created for %s (TTL %dh)", username, TOKEN_TTL // 3600)
    return _current_token


def get_token() -> Optional[str]:
    if _current_token and time.time() < _token_expiry:
        return _current_token
    return None


def is_authenticated() -> bool:
    return get_token() is not None


def logout():
    global _current_token, _token_expiry
    _current_token = None
    _token_expiry  = 0.0
