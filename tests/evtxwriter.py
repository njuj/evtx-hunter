"""Write small but structurally real .evtx files for tests and demos.

Real layout throughout: file header, 64 KiB chunks with valid CRC32s, records whose Binary XML is a
template instance. A template is written inline the first time a record shape appears in a chunk and
referenced by offset afterwards, exactly like Windows does, so both reader paths get exercised.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
CHUNK_SIZE = 0x10000

T_WSTRING, T_UINT8, T_UINT16, T_UINT32, T_UINT64, T_FILETIME, T_SID, T_WSTRING_ARRAY = (
    0x01, 0x04, 0x06, 0x08, 0x0A, 0x11, 0x13, 0x81)


@dataclass
class Ev:
    record_id: int
    time: datetime
    event_id: int
    provider: str = "Microsoft-Windows-Security-Auditing"
    channel: str = "Security"
    computer: str = "WS01.corp.example"
    data: dict = field(default_factory=dict)
    user_sid: str | None = None
    pid: int = 4
    level: int = 0


def filetime(dt: datetime) -> int:
    d = dt - EPOCH
    return (d.days * 86400 + d.seconds) * 10_000_000 + d.microseconds * 10


def sid_bytes(sid: str) -> bytes:
    parts = sid.split("-")
    revision, authority, subs = int(parts[1]), int(parts[2]), [int(p) for p in parts[3:]]
    return bytes([revision, len(subs)]) + authority.to_bytes(6, "big") + struct.pack(f"<{len(subs)}I", *subs)


def _encode(value) -> tuple[int, bytes]:
    if isinstance(value, list):
        return T_WSTRING_ARRAY, "".join(f"{v}\x00" for v in value).encode("utf-16-le")
    if isinstance(value, int):
        return T_UINT32, struct.pack("<I", value)
    return T_WSTRING, str(value).encode("utf-16-le")


def name_hash(text: str) -> int:
    """The 16-bit hash Windows stores with every name (verified against real logs)."""
    h = 0
    for ch in text:
        h = (h * 65599 + ord(ch)) & 0xFFFFFFFF
    return h & 0xFFFF


class _Chunk:
    def __init__(self):
        self.buf = bytearray(0x200)
        self.templates: dict[tuple, int] = {}
        self.ids: list[int] = []
        self.records: list[tuple[int, int, int]] = []   # (record id, offset, size)
        self.last_record = 0
        self.string_buckets = [0] * 64     # chunk header hash table: newest name first, chained via "next"
        self.template_buckets = [0] * 32

    def _name(self, text: str) -> None:
        off, h = len(self.buf), name_hash(text)
        bucket = h % 64
        self.buf += struct.pack("<IHH", self.string_buckets[bucket], h, len(text))
        self.buf += text.encode("utf-16-le") + b"\0\0"
        self.string_buckets[bucket] = off

    def _content(self, item) -> None:
        kind, v = item
        if kind == "lit":
            self.buf += b"\x05\x01" + struct.pack("<H", len(v)) + v.encode("utf-16-le")
        else:                                                    # ("sub", (index, type, optional))
            index, vtype, optional = v
            self.buf += bytes([0x0E if optional else 0x0D]) + struct.pack("<HB", index, vtype)

    def _element(self, name: str, attrs: list, children: list) -> None:
        start = len(self.buf)
        self.buf += bytes([0x41 if attrs else 0x01]) + struct.pack("<HI", 0xFFFF, 0)
        self.buf += struct.pack("<I", len(self.buf) + 4)         # name stored inline, right after
        self._name(name)
        attr_size_at = len(self.buf)
        if attrs:
            self.buf += struct.pack("<I", 0)
        for i, (a_name, value) in enumerate(attrs):
            self.buf += bytes([0x06 | (0x40 if i < len(attrs) - 1 else 0)])
            self.buf += struct.pack("<I", len(self.buf) + 4)
            self._name(a_name)
            self._content(value)
        if attrs:                                                # bytes of the attribute list itself
            struct.pack_into("<I", self.buf, attr_size_at, len(self.buf) - attr_size_at - 4)
        if not children:
            self.buf += b"\x03"
        else:
            self.buf += b"\x02"
            for child in children:
                if child[0] == "E":
                    self._element(*child[1:])
                else:
                    self._content(child)
            self.buf += b"\x04"
        # element size = every byte after the size field, end token included (verified on real logs)
        struct.pack_into("<I", self.buf, start + 3, len(self.buf) - (start + 7))

    def add(self, ev: Ev) -> bool:
        """Append a record; False if it no longer fits in this chunk."""
        data_items = list(ev.data.items())
        encoded = [_encode(v) for _, v in data_items]
        shape = (ev.provider, ev.channel, tuple((k, t) for (k, _), (t, _) in zip(data_items, encoded)))
        values = [(T_UINT16, struct.pack("<H", ev.event_id)), (T_UINT8, bytes([ev.level])),
                  (T_FILETIME, struct.pack("<Q", filetime(ev.time))), (T_UINT64, struct.pack("<Q", ev.record_id)),
                  (T_UINT32, struct.pack("<I", ev.pid)), (T_WSTRING, ev.computer.encode("utf-16-le")),
                  (T_SID, sid_bytes(ev.user_sid)) if ev.user_sid else (0x00, b"")] + encoded

        mark = len(self.buf)
        start = mark
        guid = hashlib.md5(repr(shape).encode()).digest()       # stable per shape; id = its first 4 bytes
        template_id = struct.unpack_from("<I", guid)[0]
        self.buf += b"\x2a\x2a\x00\x00" + b"\0\0\0\0" + struct.pack("<QQ", ev.record_id, filetime(ev.time))
        self.buf += b"\x0f\x01\x01\x00" + b"\x0c\x01" + struct.pack("<I", template_id)
        template_ref = len(self.buf)
        self.buf += b"\0\0\0\0"
        template = self.templates.get(shape)
        if template is None:
            template = len(self.buf)
            bucket = template_id % 32
            self.buf += struct.pack("<I", self.template_buckets[bucket]) + guid + b"\0\0\0\0"
            self.template_buckets[bucket] = template
            body = len(self.buf)
            self.buf += b"\x0f\x01\x01\x00"
            sub = lambda i, t, opt=False: ("sub", (i, t, opt))  # noqa: E731
            system = ["E", "System", [], [
                ["E", "Provider", [("Name", ("lit", ev.provider))], []],
                ["E", "EventID", [], [sub(0, T_UINT16)]],
                ["E", "Level", [], [sub(1, T_UINT8)]],
                ["E", "TimeCreated", [("SystemTime", sub(2, T_FILETIME))], []],
                ["E", "EventRecordID", [], [sub(3, T_UINT64)]],
                ["E", "Execution", [("ProcessID", sub(4, T_UINT32))], []],
                ["E", "Channel", [], [("lit", ev.channel)]],
                ["E", "Computer", [], [sub(5, T_WSTRING)]],
                ["E", "Security", [("UserID", sub(6, T_SID, True))], []],
            ]]
            event_data = ["E", "EventData", [], [
                ["E", "Data", [("Name", ("lit", k))], [sub(7 + i, t)]] for i, (k, t) in enumerate(shape[2])
            ]]
            self._element("Event", [("xmlns", ("lit", "http://schemas.microsoft.com/win/2004/08/events/event"))],
                          [system, event_data])
            self.buf += b"\x00"
            struct.pack_into("<I", self.buf, template + 20, len(self.buf) - body)
            self.templates[shape] = template
        struct.pack_into("<I", self.buf, template_ref, template)
        self.buf += struct.pack("<I", len(values))
        for vtype, raw in values:
            self.buf += struct.pack("<HBB", len(raw), vtype, 0)
        for _, raw in values:
            self.buf += raw
        # records are padded to a multiple of 8 bytes (true of every one of 91,612 records in real logs)
        self.buf += bytes(-(len(self.buf) - start + 4) % 8)
        self.buf += b"\0\0\0\0"
        size = len(self.buf) - start
        if len(self.buf) > CHUNK_SIZE:                           # roll back: start a new chunk instead
            del self.buf[mark:]
            self.templates = {k: v for k, v in self.templates.items() if v < mark}  # drop one defined here
            self.string_buckets = [o if o < mark else 0 for o in self.string_buckets]
            self.template_buckets = [o if o < mark else 0 for o in self.template_buckets]
            return False
        struct.pack_into("<I", self.buf, start + 4, size)
        struct.pack_into("<I", self.buf, start + size - 4, size)
        self.ids.append(ev.record_id)
        self.records.append((ev.record_id, start, size))
        self.last_record = start
        return True

    def hide(self, hidden: set) -> None:
        """eventlogedit-style tampering: grow the previous visible record over each hidden one."""
        visible = None
        for rid, start, size in self.records:
            if rid not in hidden:
                visible = [rid, start, size]
                continue
            if visible is None:
                raise ValueError("the first record of a chunk cannot be hidden")
            visible[2] = start + size - visible[1]
            struct.pack_into("<I", self.buf, visible[1] + 4, visible[2])
            struct.pack_into("<I", self.buf, start + size - 4, visible[2])   # overwrites the hidden trailer
        self.ids = [i for i in self.ids if i not in hidden]
        self.last_record = max(start for rid, start, _ in self.records if rid not in hidden)

    def finish(self, first_number: int) -> bytes:
        free = len(self.buf)
        buf = self.buf + bytes(CHUNK_SIZE - free)
        buf[0:8] = b"ElfChnk\x00"
        # Windows checks that record *numbers* count the records it can walk; record *identifiers* may jump
        last_number = first_number + len(self.ids) - 1
        struct.pack_into("<QQQQ", buf, 8, first_number, last_number, min(self.ids), max(self.ids))
        struct.pack_into("<III", buf, 0x28, 128, self.last_record, free)
        struct.pack_into("<I", buf, 0x34, zlib.crc32(bytes(buf[0x200:free])) & 0xFFFFFFFF)
        struct.pack_into("<64I", buf, 0x80, *self.string_buckets)
        struct.pack_into("<32I", buf, 0x180, *self.template_buckets)
        struct.pack_into("<I", buf, 0x7C, zlib.crc32(bytes(buf[:0x78] + buf[0x80:0x200])) & 0xFFFFFFFF)
        return bytes(buf)


def write_evtx(path, events: list[Ev], hide=()) -> None:
    """Write `events`; ids in `hide` stay in the file but are hidden eventlogedit-style."""
    chunks, current = [], _Chunk()
    for ev in events:
        if not current.add(ev):
            chunks.append(current)
            current = _Chunk()
            if not current.add(ev):
                raise ValueError("event too large for one chunk")
    if current.ids:
        chunks.append(current)
    if hide:
        for c in chunks:
            c.hide(set(hide))
    header = bytearray(0x1000)
    header[0:8] = b"ElfFile\x00"
    next_id = max((max(c.ids) for c in chunks), default=0) + 1
    struct.pack_into("<QQQIHHHH", header, 8, 0, max(len(chunks) - 1, 0), next_id, 128, 2, 3, 0x1000, len(chunks))
    struct.pack_into("<I", header, 0x78, 0)
    struct.pack_into("<I", header, 0x7C, zlib.crc32(bytes(header[:0x78])) & 0xFFFFFFFF)
    with open(path, "wb") as f:
        f.write(header)
        number = 1
        for c in chunks:
            f.write(c.finish(number))
            number += len(c.ids)
