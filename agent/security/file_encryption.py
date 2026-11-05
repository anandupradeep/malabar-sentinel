"""
File Encryption — Fix 10: encrypt_file + decrypt_file with stored AES-256 key.
"""
import logging
import os
import secrets
from pathlib import Path

logger = logging.getLogger("file-encryption")

KEY_FILE = Path(os.path.expanduser("~")) / ".soc_agent_enc_key"


def _load_or_create_key() -> bytes:
    if KEY_FILE.exists():
        try:
            data = KEY_FILE.read_bytes()
            if len(data) == 32:
                return data
        except Exception:
            pass
    key = secrets.token_bytes(32)
    try:
        KEY_FILE.write_bytes(key)
        if os.name != "nt":
            os.chmod(KEY_FILE, 0o600)
    except Exception:
        pass
    return key


class FileEncryption:
    def __init__(self):
        self._key = _load_or_create_key()

    def encrypt_file(self, filepath: str):
        """Encrypt filepath → filepath.soc_enc  Returns (ok, detail)."""
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"
        out = filepath + ".soc_enc"
        try:
            return self._aes_encrypt(filepath, out)
        except Exception:
            return self._xor_encrypt(filepath, out)

    def decrypt_file(self, filepath: str):
        """Decrypt filepath (must end .soc_enc) → original.  Returns (ok, detail)."""
        if not filepath.endswith(".soc_enc"):
            return False, "Not an encrypted file (.soc_enc extension required)"
        if not os.path.exists(filepath):
            return False, f"File not found: {filepath}"
        out = filepath[:-8]  # remove .soc_enc
        try:
            return self._aes_decrypt(filepath, out)
        except Exception:
            return self._xor_decrypt(filepath, out)

    # ── AES-256-GCM ───────────────────────────────────────────────────────────
    def _aes_encrypt(self, src, dst):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        nonce = secrets.token_bytes(12)
        data  = Path(src).read_bytes()
        ct    = AESGCM(self._key).encrypt(nonce, data, None)
        Path(dst).write_bytes(nonce + ct)
        os.remove(src)
        return True, f"AES-256-GCM encrypted → {dst}"

    def _aes_decrypt(self, src, dst):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw   = Path(src).read_bytes()
        nonce = raw[:12]; ct = raw[12:]
        pt    = AESGCM(self._key).decrypt(nonce, ct, None)
        Path(dst).write_bytes(pt)
        os.remove(src)
        return True, f"AES-256-GCM decrypted → {dst}"

    # ── XOR fallback ──────────────────────────────────────────────────────────
    def _xor_encrypt(self, src, dst):
        data = Path(src).read_bytes()
        key  = self._key
        enc  = bytes(b ^ key[i % 32] for i, b in enumerate(data))
        Path(dst).write_bytes(enc)
        os.remove(src)
        return True, f"XOR encrypted (fallback) → {dst}"

    def _xor_decrypt(self, src, dst):
        # XOR is symmetric
        data = Path(src).read_bytes()
        key  = self._key
        dec  = bytes(b ^ key[i % 32] for i, b in enumerate(data))
        Path(dst).write_bytes(dec)
        os.remove(src)
        return True, f"XOR decrypted (fallback) → {dst}"
