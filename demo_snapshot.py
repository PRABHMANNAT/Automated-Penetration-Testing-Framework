"""Authenticate browser-owned snapshots before opening them as a demo database."""

import base64
import binascii
import hashlib
import hmac
import secrets
import zlib
from functools import lru_cache
from pathlib import Path


KEY_PATH = Path(__file__).with_name("demo-signing.key")
MAX_DATABASE_BYTES = 2_000_000
MAX_TOKEN_LENGTH = 380_000


class ExpiredSnapshot(Exception):
    pass


class WorkspaceFull(Exception):
    pass


@lru_cache
def signing_key():
    # Vercel packages one build-generated key for all instances of the deployment.
    if KEY_PATH.is_file():
        return KEY_PATH.read_bytes()
    return secrets.token_bytes(32)


def signature(payload):
    return hmac.new(signing_key(), payload.encode("ascii"), hashlib.sha256).hexdigest()


def snapshot(connection):
    data = connection.serialize()
    if len(data) > MAX_DATABASE_BYTES:
        raise WorkspaceFull
    payload = base64.urlsafe_b64encode(zlib.compress(data)).decode("ascii")
    state = f"{payload}.{signature(payload)}"
    if len(state) > MAX_TOKEN_LENGTH:
        raise WorkspaceFull
    return state


def restore(connection, state):
    try:
        payload, presented = state.rsplit(".", 1)
        if len(presented) != 64 or not presented.isascii() or not hmac.compare_digest(signature(payload), presented):
            raise ExpiredSnapshot
        inflater = zlib.decompressobj()
        data = inflater.decompress(base64.urlsafe_b64decode(payload), MAX_DATABASE_BYTES + 1)
        if len(data) > MAX_DATABASE_BYTES or not inflater.eof:
            raise ExpiredSnapshot
    except (ValueError, UnicodeError, binascii.Error, zlib.error) as error:
        raise ExpiredSnapshot from error
    connection.deserialize(data)


if __name__ == "__main__":
    KEY_PATH.write_bytes(secrets.token_bytes(32))
