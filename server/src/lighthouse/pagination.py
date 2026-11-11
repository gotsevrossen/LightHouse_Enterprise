"""Opaque keyset cursors over (created_at, key), newest first.

Keyset rather than offset pagination: stable under concurrent inserts and cheap on the
(tenant_id, created_at desc, id desc) indexes. A cursor carries no authority; a forged one
can only move the window within rows RLS already allows the caller to see.
"""

from __future__ import annotations

import base64
import binascii
from datetime import datetime
from typing import Final

from fastapi import HTTPException, status

MAX_CURSOR_LENGTH: Final = 200
_SEPARATOR: Final = "|"


class InvalidCursorError(ValueError):
    pass


def encode_cursor(created_at: datetime, key: object) -> str:
    raw = f"{created_at.isoformat()}{_SEPARATOR}{key}"
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    if len(cursor) > MAX_CURSOR_LENGTH:
        raise InvalidCursorError
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        created_raw, key = raw.split(_SEPARATOR, 1)
        created_at = datetime.fromisoformat(created_raw)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InvalidCursorError from exc
    if created_at.tzinfo is None or not key:
        raise InvalidCursorError
    return created_at, key


def bad_cursor() -> HTTPException:
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid cursor")
