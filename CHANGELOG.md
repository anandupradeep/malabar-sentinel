# Malabar Sentinel — Changelog

## v2.1.0 — Production Hardening (2026-06)

This release implements the full production-readiness plan. All changes are
backward-compatible with existing endpoint paths and agent behaviour.

---

### Security — Backend Control Paths

**`server/main.py`**

- **`GET /get-commands/{endpoint_id}`** — was unauthenticated; now requires
  `Authorization: Bearer <key>` via `verify_api_key`. Agents must supply their
  `AGENT_KEY`.
- **`POST /command-response`** — was unauthenticated; now requires
  `Authorization: Bearer <key>`.
- **`GET /api/commands/{command_id}/status`** — was unauthenticated; now
  requires auth. DB is queried first (source of truth) and the in-memory cache
  is hydrated on a cache miss so subsequent reads are fast.
- Added `verify_admin_key` dependency for routes that should only be accessible
  to the dashboard operator (not agents).
- **Constant-time key comparison** — `verify_api_key` now uses
  `secrets.compare_digest` to prevent timing-based key enumeration.
- **Separate admin vs agent keys** — `SOC_ADMIN_KEY` is the dashboard key;
  `AGENT_KEY` is the endpoint agent key. The old `SOC_MASTER_KEY` name still
  works as a fallback alias for `SOC_ADMIN_KEY`.
- Startup warnings if either key is not set via environment.

**`server/scan_routes.py`**

All scan routes that were previously unauthenticated now require `verify_api_key`:
`/start`, `/stop`, `/progress/{id}`, `/report/update`, `/report/{id}`,
`/history/{id}`, `/timeline/{id}`, `/timeline/event`, `/download/timeline/{id}`,
`/download/report/{id}`, `/sandbox/result`.

---

### Security — CORS

- `allow_origins=["*"]` replaced with an env-driven list.
- New env var: `SOC_ALLOWED_ORIGINS` (comma-separated origins).
- Defaults to `http://localhost:9001,http://127.0.0.1:9001` when not set.

---

### Security — Secrets

- Hardcoded default API key (`SOC-MASTER-KEY-2024`) removed from:
  - `dashboard/public/index.html` — settings input `value=""` (no default shown)
  - Dashboard JS `S.apiKey` initial value cleared
  - Dashboard Reset button no longer re-fills the key field
  - Dashboard docs example updated to `<your-SOC_ADMIN_KEY>`
- `.env.example` updated with all new env vars and clear comments.

---

### Durability — Command State

- `GET /api/commands/{command_id}/status` now queries the **database first**
  as the authoritative source, then falls back to the in-memory cache and
  result queue. Previously the cache was checked first and DB only as a last
  resort, meaning a server restart lost all command state.
- `_cmd_store` remains a short-lived write-through cache for performance.

---

### Durability — Stale Endpoint Data

- `_process_cache` entries now store `{"processes": [...], "updated_at": "..."}`.
- `GET /api/endpoints/{id}/processes` response includes `updated_at` and
  `stale: true` when the agent hasn't reported in the last 120 seconds.
- `_usb_cache` entries similarly store `updated_at`.
- `GET /api/endpoints/{id}/usb-devices` includes `updated_at` and `stale`.
- Stale data is clearly labelled rather than silently shown as live.

---

### Database — Indexes

**`server/database.py`** — New composite indexes:
- `idx_alerts_ep_time` — `(endpoint_id, created_at DESC)`
- `idx_alerts_ep_severity` — `(endpoint_id, severity, created_at DESC)`
- `idx_commands_ep_time` — `(endpoint_id, created_at DESC)`
- `idx_commands_ep_status_time` — `(endpoint_id, status, created_at DESC)`

**`server/scan_manager.py`** — New composite indexes:
- `idx_scan_ep_status` — `(endpoint_id, status, started_at DESC)`
- `idx_tl_ep_type` — `(endpoint_id, event_type, created_at DESC)`

All indexes use `CREATE INDEX IF NOT EXISTS` so they are added safely to
existing databases on next startup.

---

### Agent — Rule Loader (`agent/rule_loader.py`)

- **Deep copy** — `DEFAULT_RULES` is now deep-copied on every `load()` call.
  Previously a shallow copy meant nested lists (e.g. `process_rules`) were
  shared across instances.
- **Precomputed whitelist sets** — `_wl_processes` (a `set`) and `_wl_paths`
  (a `list`) are built once at load time and rebuilt when `merge_server_policy`
  adds entries. `is_whitelisted_process` is now O(1).
- **External rules validation** — `config/rules.json` is validated with
  `_validate_rules()` before being accepted. Invalid files are rejected with a
  warning and defaults are used instead of silently breaking detection.
- **Deterministic policy merge** — `merge_server_policy` appends new whitelist
  entries in stable order without duplicates (case-insensitive dedup).

---

### Agent — Scan Executor (`agent/scan_executor.py`)

- **Scan exclusions** — The following are always excluded from custom-engine
  walks: quarantine directory, Windows cache/installer dirs, Linux virtual
  filesystems (`/proc`, `/sys`, `/dev`, `/run`), and common vendor/cache
  directories (`node_modules`, `__pycache__`, `site-packages`, `.git`, etc.).
  Additional dirs can be added via `SCAN_EXCLUDED_DIRS` env var.
- **Custom path validation** — `folder_path` for custom scans is validated
  before the thread starts: must be absolute, must exist, must be a directory.
  Path traversal is blocked via `os.path.realpath`.
- **File size limit** — Files larger than `SCAN_MAX_FILE_MB` (default 64 MB)
  are skipped during hashing. Configurable via env var.
- **Stop checks before hashing** — `_sha256` accepts a `stop_event` and returns
  `None` immediately if it is set, preventing large-file stalls after stop is
  requested.
- **Progress throttling** — Progress is pushed every 5 seconds OR when the
  threat batch reaches 10 items, not on every new threat detection. Reduces
  noisy network bursts during large scans.
- **Hash validation** — `KNOWN_HASHES` is filtered at module load through
  `_validate_hash_set`, which keeps only valid 64-char lowercase hex (SHA-256)
  strings and logs a warning for anything else (e.g. the MD5 and SHA-1 entries
  that were previously in the set).
- Auth header fixed: agent POSTs to `/api/scan/report/update` now send
  `Authorization: Bearer <key>` (was `X-API-Key`).

---

### Agent — Hash Scanner (`agent/security/hash_scanner.py`)

- `KNOWN_MALWARE_HASHES` filtered through `_validate_hash_db` at startup.
  Invalid entries (MD5 `44d88612…`, SHA-1 `cf8bd9df…`) are logged and dropped.

---

### Docs / Config

- `README.md` — re-saved as UTF-8; port references updated from 8000 → 9001.
- `README_DEPLOY.md` — port references updated.
- `.env.example` — new vars documented: `SOC_ADMIN_KEY`, `SOC_ALLOWED_ORIGINS`,
  `SOC_RATE_LIMIT_PER_MINUTE`, `SCAN_MAX_FILE_MB`, `SCAN_EXCLUDED_DIRS`.

---

### Tests (`test_platform.py`)

- Port references updated 8000 → 9001.
- Live server tests now read key from `SOC_ADMIN_KEY` env var; no hardcoded
  default in test assertions.
- **New focused tests added:**
  - Auth: all five previously-unauthenticated endpoints return `401` without a key
  - Rule loader: deep-copy isolation, malformed-rule rejection, whitelist lookups,
    policy merge deduplication
  - Scan executor: custom path validation, SHA-256 hash filtering, exclusion logic

---

### New Environment Variables (all optional with safe defaults)

| Variable | Default | Purpose |
|---|---|---|
| `SOC_ADMIN_KEY` | *(required — warns if absent)* | Dashboard / admin API key |
| `AGENT_KEY` | *(required — warns if absent)* | Endpoint agent API key |
| `SOC_ALLOWED_ORIGINS` | `http://localhost:9001,http://127.0.0.1:9001` | CORS allowed origins |
| `SOC_RATE_LIMIT_PER_MINUTE` | `300` | Requests/minute/IP |
| `SCAN_MAX_FILE_MB` | `64` | Max file size to hash during scan |
| `SCAN_EXCLUDED_DIRS` | *(empty)* | Extra dirs to skip during scan (comma-separated) |
