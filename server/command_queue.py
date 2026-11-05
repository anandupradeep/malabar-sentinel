"""
Command Queue — Enterprise Edition
In-memory per-agent command queue with <3s delivery.

FIX: asyncio.Lock() must be created lazily (inside a running event loop),
     not at module import time. A module-level Lock() created before
     uvicorn starts its loop causes "got Future attached to a different loop"
     errors that silently swallow every enqueue/dequeue call.
"""
import asyncio
import logging
import secrets
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("command-queue")

_queue:   Dict[str, List[dict]] = defaultdict(list)
_results: Dict[str, dict]       = {}

# FIX: do NOT create the lock at module level — create it lazily inside the
# running event loop so it always belongs to the correct loop.
_lock: Optional[asyncio.Lock] = None


def _get_lock() -> asyncio.Lock:
    """Return (or create) the asyncio Lock inside the running event loop."""
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


async def enqueue(endpoint_id: str, command: str,
                  parameters: dict = None, source: str = "dashboard") -> str:
    """Add a command to the queue for an endpoint. Returns command_id."""
    command_id = secrets.token_hex(10)
    entry = {
        "command_id":  command_id,
        "endpoint_id": endpoint_id,
        "command":     command,
        "parameters":  parameters or {},
        "source":      source,
        "status":      "pending",
        "created_at":  _utcnow(),
    }
    async with _get_lock():
        _queue[endpoint_id].append(entry)
    logger.info("Queued [%s] for %s (id=%s)", command, endpoint_id, command_id)
    return command_id


async def dequeue(endpoint_id: str) -> List[dict]:
    """Pop and return all pending commands for an endpoint."""
    async with _get_lock():
        cmds = list(_queue[endpoint_id])
        _queue[endpoint_id].clear()
    return cmds


async def peek(endpoint_id: str) -> List[dict]:
    async with _get_lock():
        return list(_queue[endpoint_id])


async def mark_delivered(endpoint_id: str, command_id: str):
    async with _get_lock():
        _queue[endpoint_id] = [
            c for c in _queue[endpoint_id]
            if c["command_id"] != command_id
        ]


async def record_result(command_id: str, result: dict):
    _results[command_id] = {
        **result,
        "command_id":   command_id,
        "completed_at": _utcnow(),
    }


async def get_result(command_id: str) -> Optional[dict]:
    return _results.get(command_id)


def stats() -> dict:
    """Return queue stats (alias: queue_stats)."""
    return {
        "pending_by_endpoint": {k: len(v) for k, v in _queue.items()},
        "total_queued":        sum(len(v) for v in _queue.values()),
        "total_results":       len(_results),
    }


# Alias so both names work
queue_stats = stats
