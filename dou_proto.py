import json
import struct


MAGIC = b"DOU1"
HEADER_FMT = "!4sBIH"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

TYPE_QUERY = 1
TYPE_RESPONSE = 2
TYPE_ERROR = 3
TYPE_PING = 4
TYPE_PONG = 5

MAX_APP_PAYLOAD = 1200 - HEADER_SIZE


def encode_frame(frame_type: int, request_id: int, payload: bytes = b"") -> bytes:
    if len(payload) > MAX_APP_PAYLOAD:
        raise ValueError(f"payload too large {len(payload)} > {MAX_APP_PAYLOAD}")
    return struct.pack(HEADER_FMT, MAGIC, frame_type, request_id, len(payload)) + payload


def decode_frame(raw: bytes) -> dict | None:
    if len(raw) < HEADER_SIZE:
        return None
    magic, frame_type, request_id, length = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
    if magic != MAGIC:
        return None
    payload = raw[HEADER_SIZE:HEADER_SIZE + length]
    if len(payload) != length:
        return None
    return {
        "type": frame_type,
        "request_id": request_id,
        "payload": payload,
    }


def encode_json_frame(frame_type: int, request_id: int, data: dict) -> bytes:
    payload = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return encode_frame(frame_type, request_id, payload)


def decode_json_payload(payload: bytes) -> dict | None:
    try:
        obj = json.loads(payload.decode("utf-8"))
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None

