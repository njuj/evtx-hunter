"""A from-scratch, zero-dependency reader for Windows XML Event Log (.evtx) files.

Layout, briefly:

* a 4 KiB file header, then 64 KiB chunks;
* each chunk has a 512-byte header (with a string hash table and template table), then records;
* each record carries its event as *Binary XML*: a token stream where element and attribute names
  live in a per-chunk string table and the XML skeleton lives in a per-chunk *template*. A record
  usually holds only a reference to its template plus an array of typed substitution values.

So the expensive part (the template) is parsed once per chunk and cached; each record only decodes
its values. Every offset is bounds-checked: a truncated or tampered log raises ParseError for that
record instead of crashing the run.
"""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"
FILE_HEADER_SIZE = 0x1000
CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 0x200
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# Binary XML tokens (low nibble; 0x40 marks "has attributes" / "more data").
T_EOF, T_OPEN, T_CLOSE_START, T_CLOSE_EMPTY, T_END, T_VALUE, T_ATTR, T_CDATA = range(8)
T_CHARREF, T_ENTREF, T_PITARGET, T_PIDATA, T_TEMPLATE, T_SUB, T_OPTSUB, T_FRAGMENT = range(8, 16)
ENTITIES = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}

_u8 = struct.Struct("<B").unpack_from
_u16 = struct.Struct("<H").unpack_from
_u32 = struct.Struct("<I").unpack_from
_u64 = struct.Struct("<Q").unpack_from


class ParseError(ValueError):
    pass


def filetime(value: int) -> datetime | None:
    if not value:
        return None
    try:
        return FILETIME_EPOCH + timedelta(microseconds=value // 10)
    except OverflowError:
        return None


# ── node shapes ───────────────────────────────────────────────────────────────
# Element: ["E", name, [(attr_name, [parts])], [children]]  ·  child text: str or Sub
# Sub: ("S", index, optional)  ·  parts are str or Sub


@dataclass
class Event:
    record_id: int
    event_id: int | None
    provider: str
    channel: str
    computer: str
    time: datetime | None
    level: int | None = None
    user_sid: str | None = None
    pid: int | None = None
    data: dict[str, str] = field(default_factory=dict)
    recovered: bool = False          # hidden inside another record; Windows does not show it

    def get(self, key: str, default: str = "") -> str:
        return self.data.get(key, default)


# ── value rendering (matches how Event Viewer / wevtutil print each type) ────


def _guid(b: bytes) -> str:
    d1, d2, d3 = struct.unpack_from("<IHH", b)
    return "{%08x-%04x-%04x-%s-%s}" % (d1, d2, d3, b[8:10].hex(), b[10:16].hex())


def _filetime_str(value: int) -> str:
    """FILETIME at its full 100 ns precision, the way Windows prints it (zero is the 1601 epoch)."""
    seconds, ticks = divmod(value, 10_000_000)
    try:
        dt = FILETIME_EPOCH + timedelta(seconds=seconds)
    except OverflowError:
        return str(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ticks:07d}Z"


def _sid(b: bytes) -> str:
    if len(b) < 8:
        raise ParseError("short SID")
    revision, count = b[0], b[1]
    authority = int.from_bytes(b[2:8], "big")
    subs = struct.unpack_from(f"<{count}I", b, 8)
    return "S-%d-%d" % (revision, authority) + "".join(f"-{s}" for s in subs)


def _systemtime(b: bytes) -> str:
    y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", b)
    return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"


def _iso(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if dt else ""


class _Chunk:
    """One 64 KiB chunk with its string and template caches. All offsets are chunk-relative."""

    def __init__(self, buf: bytes):
        self.buf = buf
        self.names: dict[int, str] = {}
        self.templates: dict[int, list] = {}

    # ── primitives ──
    def need(self, pos: int, n: int) -> None:
        if pos < 0 or pos + n > len(self.buf):
            raise ParseError(f"read past chunk end at 0x{pos:x}")

    def name(self, off: int) -> tuple[str, int]:
        """(name, size of the name structure) for a string-table entry."""
        self.need(off, 8)
        length = _u16(self.buf, off + 6)[0]
        size = 8 + 2 * length + 2
        cached = self.names.get(off)
        if cached is None:
            self.need(off, size)
            cached = self.buf[off + 8:off + 8 + 2 * length].decode("utf-16-le", "replace")
            self.names[off] = cached
        return cached, size

    # ── binary XML ──
    def parse_fragment(self, pos: int, end: int) -> tuple[list, list, int]:
        """Parse a fragment (header + template instance or element). Returns (root nodes, values, end pos)."""
        self.need(pos, 1)
        if self.buf[pos] & 0x0F == T_FRAGMENT:
            pos += 4
        self.need(pos, 1)
        token = self.buf[pos] & 0x0F
        if token == T_TEMPLATE:
            return self._template_instance(pos, end)
        if token == T_OPEN:
            node, pos = self._element(pos, end)
            return [node], [], pos
        raise ParseError(f"unexpected token 0x{self.buf[pos]:02x} at fragment start")

    def _template_instance(self, pos: int, end: int) -> tuple[list, list, int]:
        self.need(pos, 10)
        template_off = _u32(self.buf, pos + 6)[0]
        pos += 10
        if template_off == pos:                                  # definition is stored inline, right here
            self.need(pos, 24)
            pos = template_off + 24 + _u32(self.buf, template_off + 20)[0]
        template = self.templates.get(template_off)
        if template is None:
            template = self._parse_template(template_off)
            self.templates[template_off] = template
        values, pos = self._values(pos, end)
        return template, values, pos

    def _parse_template(self, off: int) -> list:
        self.need(off, 24)
        size = _u32(self.buf, off + 20)[0]
        pos, end = off + 24, off + 24 + size
        self.need(off + 24, size)
        if self.buf[pos] & 0x0F == T_FRAGMENT:
            pos += 4
        nodes = []
        while pos < end:
            token = self.buf[pos] & 0x0F
            if token == T_EOF:
                break
            node, pos = self._content(pos, end)
            nodes.append(node)
        return nodes

    def _values(self, pos: int, end: int) -> tuple[list, int]:
        self.need(pos, 4)
        count = _u32(self.buf, pos)[0]
        pos += 4
        if count > 4096:
            raise ParseError(f"implausible substitution count {count}")
        self.need(pos, 4 * count)
        specs = [(_u16(self.buf, pos + 4 * i)[0], self.buf[pos + 4 * i + 2]) for i in range(count)]
        pos += 4 * count
        values = []
        for size, vtype in specs:
            self.need(pos, size)
            values.append(self._value(pos, size, vtype))
            pos += size
        return values, pos

    def _value(self, pos: int, size: int, vtype: int):
        """Decoded substitution value: a string, None (null), or ('xml', nodes, values) for BinXml."""
        b = self.buf
        if size == 0 or vtype == 0x00:
            return None
        if vtype == 0x01:                                        # strings end at the first NUL, as in Windows
            return b[pos:pos + size].decode("utf-16-le", "replace").split("\x00", 1)[0]
        if vtype == 0x02:
            return b[pos:pos + size].decode("latin-1").split("\x00", 1)[0]
        if vtype == 0x21:                                        # embedded Binary XML
            nodes, values, _ = self.parse_fragment(pos, pos + size)
            return ("xml", nodes, values)
        if vtype & 0x80:                                         # arrays -> list (one <Data> per item)
            base = vtype & 0x7F
            if base in (0x01, 0x02):
                codec = "utf-16-le" if base == 0x01 else "latin-1"
                items = b[pos:pos + size].decode(codec, "replace").split("\x00")
                if items and items[-1] == "":                    # final terminator, not an empty item
                    items.pop()
                return items
            width = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8, 0x0A: 8, 0x0F: 16,
                     0x11: 8, 0x13: 0, 0x14: 4, 0x15: 8}.get(base)
            if width:
                return [self._value(pos + i, width, base) for i in range(0, size - width + 1, width)]
            return [b[pos:pos + size].hex().upper()]
        fixed = {
            0x03: lambda: str(struct.unpack_from("<b", b, pos)[0]),
            0x04: lambda: str(b[pos]),
            0x05: lambda: str(struct.unpack_from("<h", b, pos)[0]),
            0x06: lambda: str(_u16(b, pos)[0]),
            0x07: lambda: str(struct.unpack_from("<i", b, pos)[0]),
            0x08: lambda: str(_u32(b, pos)[0]),
            0x09: lambda: str(struct.unpack_from("<q", b, pos)[0]),
            0x0A: lambda: str(_u64(b, pos)[0]),
            0x0B: lambda: repr(struct.unpack_from("<f", b, pos)[0]),
            0x0C: lambda: repr(struct.unpack_from("<d", b, pos)[0]),
            0x0D: lambda: "true" if _u32(b, pos)[0] else "false",
            0x0E: lambda: b[pos:pos + size].hex().upper(),
            0x0F: lambda: _guid(b[pos:pos + 16]),
            0x10: lambda: "0x%x" % (_u64(b, pos)[0] if size == 8 else _u32(b, pos)[0]),
            0x11: lambda: _filetime_str(_u64(b, pos)[0]),
            0x12: lambda: _systemtime(b[pos:pos + 16]),
            0x13: lambda: _sid(b[pos:pos + size]),
            0x14: lambda: "0x%x" % _u32(b, pos)[0],
            0x15: lambda: "0x%x" % _u64(b, pos)[0],
        }
        render = fixed.get(vtype)
        if render is None:
            return b[pos:pos + size].hex().upper()
        try:
            return render()
        except struct.error as e:
            raise ParseError(f"value type 0x{vtype:02x}: {e}") from None

    def _content(self, pos: int, end: int):
        """One content item: element, text, substitution, char/entity reference or CDATA."""
        self.need(pos, 1)
        raw = self.buf[pos]
        token = raw & 0x0F
        if token == T_OPEN:
            return self._element(pos, end)
        if token == T_VALUE:
            self.need(pos, 4)
            if self.buf[pos + 1] != 0x01:
                raise ParseError(f"value node of type 0x{self.buf[pos + 1]:02x}")
            n = _u16(self.buf, pos + 2)[0]
            self.need(pos + 4, 2 * n)
            return self.buf[pos + 4:pos + 4 + 2 * n].decode("utf-16-le", "replace"), pos + 4 + 2 * n
        if token in (T_SUB, T_OPTSUB):
            self.need(pos, 4)
            return ("S", _u16(self.buf, pos + 1)[0], token == T_OPTSUB), pos + 4
        if token == T_CHARREF:
            self.need(pos, 3)
            return chr(_u16(self.buf, pos + 1)[0]), pos + 3
        if token == T_ENTREF:
            self.need(pos, 5)
            off = _u32(self.buf, pos + 1)[0]
            name, size = self.name(off)
            nxt = pos + 5 + (size if off == pos + 5 else 0)
            return ENTITIES.get(name, f"&{name};"), nxt
        if token == T_CDATA:
            self.need(pos, 3)
            n = _u16(self.buf, pos + 1)[0]
            return self.buf[pos + 3:pos + 3 + 2 * n].decode("utf-16-le", "replace"), pos + 3 + 2 * n
        if token == T_PITARGET:
            off = _u32(self.buf, pos + 1)[0]
            _, size = self.name(off)
            return "", pos + 5 + (size if off == pos + 5 else 0)
        if token == T_PIDATA:
            n = _u16(self.buf, pos + 1)[0]
            return "", pos + 3 + 2 * n
        raise ParseError(f"unexpected token 0x{raw:02x} at 0x{pos:x}")

    def _element(self, pos: int, end: int):
        start = pos
        self.need(pos, 11)
        has_attrs = self.buf[pos] & 0x40
        name_off = _u32(self.buf, pos + 7)[0]
        pos += 11
        attrs_size_read = False
        if name_off > start:                                     # name stored inline in this element
            if name_off != pos and has_attrs:                    # some writers put the attr-list size first
                pos += 4
                attrs_size_read = True
            name, size = self.name(name_off)
            pos = name_off + size
        else:
            name, _ = self.name(name_off)
        if has_attrs and not attrs_size_read:
            pos += 4
        attrs = []
        while True:
            self.need(pos, 1)
            token = self.buf[pos] & 0x0F
            if token != T_ATTR:
                break
            self.need(pos, 5)
            a_off = _u32(self.buf, pos + 1)[0]
            a_name, a_size = self.name(a_off)
            pos += 5
            if a_off == pos:
                pos += a_size
            value, pos = self._content(pos, end)
            attrs.append((a_name, [value]))
        token = self.buf[pos] & 0x0F
        children = []
        if token == T_CLOSE_EMPTY:
            return ["E", name, attrs, children], pos + 1
        if token != T_CLOSE_START:
            raise ParseError(f"element <{name}> not closed (token 0x{self.buf[pos]:02x})")
        pos += 1
        while True:
            self.need(pos, 1)
            token = self.buf[pos] & 0x0F
            if token == T_END:
                return ["E", name, attrs, children], pos + 1
            if token == T_EOF:
                raise ParseError(f"stream ended inside <{name}>")
            child, pos = self._content(pos, end)
            children.append(child)


# ── flattening a template + values into an Event ─────────────────────────────

_SYSTEM_TEXT = {"EventID": "event_id", "Level": "level", "EventRecordID": "record_id", "Channel": "channel",
                "Computer": "computer"}
_SYSTEM_ATTR = {("Provider", "Name"): "provider", ("TimeCreated", "SystemTime"): "time",
                ("Security", "UserID"): "user_sid", ("Execution", "ProcessID"): "pid"}


def _text(parts, values) -> str:
    out = []
    for p in parts:
        if isinstance(p, tuple):
            v = values[p[1]] if p[1] < len(values) else None
            if isinstance(v, tuple):                             # embedded XML used as text: flatten its text
                out.append(_inner_text(v[1], v[2]))
            elif isinstance(v, list):
                out.append(",".join(v))
            elif v is not None:
                out.append(v)
        else:
            out.append(p)
    return "".join(out)


def _array_value(children, values) -> list | None:
    """If an element's whole content is one array substitution, its items (Windows repeats the element)."""
    if len(children) == 1 and isinstance(children[0], tuple):
        v = values[children[0][1]] if children[0][1] < len(values) else None
        if isinstance(v, list):
            return v
    return None


def _store(data: dict, key: str, value: str) -> None:
    if key in data:                                              # repeats: Data, Data_2, Data_3, …
        i = 2
        while f"{key}_{i}" in data:
            i += 1
        key = f"{key}_{i}"
    data[key] = value


def _inner_text(nodes, values) -> str:
    return "".join(_text(n[3], values) if isinstance(n, list) else _text([n], values) for n in nodes)


def _flatten(nodes, values, sysf: dict, data: dict, section: str | None) -> None:
    for node in nodes:
        if not isinstance(node, list):
            if isinstance(node, tuple):
                v = values[node[1]] if node[1] < len(values) else None
                if isinstance(v, tuple):                         # substitution carrying more XML
                    _flatten(v[1], v[2], sysf, data, section)
            continue
        _, name, attrs, children = node
        if section is None:
            if name in ("System", "EventData", "UserData"):
                _flatten(children, values, sysf, data, name)
            elif name == "Event":
                _flatten(children, values, sysf, data, None)
            else:                                                # e.g. RenderingInfo: ignore
                pass
            continue
        if section == "System":
            for a_name, a_parts in attrs:
                key = _SYSTEM_ATTR.get((name, a_name))
                if key:
                    sysf[key] = _text(a_parts, values)
            key = _SYSTEM_TEXT.get(name)
            if key:
                sysf[key] = _text([c for c in children if not isinstance(c, list)], values)
            continue
        # EventData / UserData: Data elements keyed by @Name, other leaves keyed by element name
        element_children = [c for c in children if isinstance(c, list)]
        xml_subs = [c for c in children if isinstance(c, tuple) and c[1] < len(values)
                    and isinstance(values[c[1]], tuple)]
        if element_children or xml_subs:
            _flatten(children, values, sysf, data, section)
            continue
        key = next((_text(p, values) for a, p in attrs if a == "Name"), None) or name
        items = _array_value(children, values)
        if items is not None:
            for item in items:
                _store(data, key, item)
        else:
            _store(data, key, _text(children, values))


def _to_int(s: str | None) -> int | None:
    try:
        return int(s) if s not in (None, "") else None
    except ValueError:
        return None


def _parse_time(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        s = s.rstrip("Z")
        head, _, frac = s.partition(".")
        dt = datetime.strptime(head, "%Y-%m-%dT%H:%M:%S")
        micro = int((frac + "000000")[:6]) if frac else 0
        return dt.replace(microsecond=micro, tzinfo=timezone.utc)
    except ValueError:
        return None


def build_event(nodes, values, record_id: int, written: datetime | None) -> Event:
    sysf: dict[str, str] = {}
    data: dict[str, str] = {}
    _flatten(nodes, values, sysf, data, None)
    return Event(
        record_id=_to_int(sysf.get("record_id")) or record_id,
        event_id=_to_int(sysf.get("event_id")),
        provider=sysf.get("provider", ""),
        channel=sysf.get("channel", ""),
        computer=sysf.get("computer", ""),
        time=_parse_time(sysf.get("time")) or written,
        level=_to_int(sysf.get("level")),
        user_sid=sysf.get("user_sid") or None,
        pid=_to_int(sysf.get("pid")),
        data=data,
    )


# ── file iteration ────────────────────────────────────────────────────────────


@dataclass
class FileInfo:
    path: str
    chunks: int = 0
    records: int = 0
    errors: int = 0
    dirty: bool = False
    bad_checksums: list[str] = field(default_factory=list)
    recovered: list[int] = field(default_factory=list)  # ids of records found hidden inside other records


def _check_chunk(buf: bytes, index: int, info: FileInfo) -> None:
    header_crc = zlib.crc32(buf[:0x78] + buf[0x80:0x200]) & 0xFFFFFFFF
    if header_crc != _u32(buf, 0x7C)[0]:
        info.bad_checksums.append(f"chunk {index} header")
    free = _u32(buf, 0x30)[0]
    if CHUNK_HEADER_SIZE <= free <= CHUNK_SIZE:
        data_crc = zlib.crc32(buf[CHUNK_HEADER_SIZE:free]) & 0xFFFFFFFF
        if data_crc != _u32(buf, 0x34)[0]:
            info.bad_checksums.append(f"chunk {index} records")


def read_events(path: str, info: FileInfo | None = None):
    """Yield every Event in the file. Unreadable records are counted in info.errors, never fatal."""
    info = info if info is not None else FileInfo(path)
    with open(path, "rb") as f:
        header = f.read(FILE_HEADER_SIZE)
        if len(header) < 0x80 or header[:8] != FILE_MAGIC:
            raise ParseError(f"{path}: not an EVTX file")
        if zlib.crc32(header[:0x78]) & 0xFFFFFFFF != _u32(header, 0x7C)[0]:
            info.bad_checksums.append("file header")
        info.dirty = bool(_u32(header, 0x78)[0] & 0x1)
        index = 0
        while True:
            buf = f.read(CHUNK_SIZE)
            if len(buf) < CHUNK_HEADER_SIZE:
                break
            if buf[:8] != CHUNK_MAGIC:                           # unused, zero-filled chunk
                index += 1
                continue
            info.chunks += 1
            _check_chunk(buf, index, info)
            yield from _chunk_events(_Chunk(buf), info)
            index += 1


def _chunk_events(chunk: _Chunk, info: FileInfo):
    buf = chunk.buf
    free = min(_u32(buf, 0x30)[0], len(buf))
    pos = CHUNK_HEADER_SIZE
    while pos + 0x1C <= free:
        if buf[pos:pos + 4] != RECORD_MAGIC:
            break
        size = _u32(buf, pos + 4)[0]
        if size < 0x1C or pos + size > len(buf):
            info.errors += 1
            break
        record_id = _u64(buf, pos + 8)[0]
        written = filetime(_u64(buf, pos + 16)[0])
        try:
            nodes, values, end = chunk.parse_fragment(pos + 0x18, pos + size - 4)
            event = build_event(nodes, values, record_id, written)
        except (ParseError, IndexError, struct.error, UnicodeDecodeError):
            info.errors += 1
        else:
            info.records += 1
            yield event
            yield from _hidden_records(chunk, info, end, pos + size)
        pos += size


def _hidden_records(chunk: _Chunk, info: FileInfo, start: int, stop: int):
    """Records hidden in a record's slack space.

    Between the end of a record's XML and its trailing size there should be under 8 bytes of padding.
    eventlogedit-style tampering hides records by growing the size of the record before them: Windows
    skips straight over them (they vanish from Event Viewer) but every byte is still in the chunk, and
    still parseable because template and string offsets are chunk-relative.
    """
    buf = chunk.buf
    k = start + (-start % 8)                                     # records start on 8-byte boundaries
    while k + 0x1C <= stop:
        if buf[k:k + 4] != RECORD_MAGIC:
            k += 8
            continue
        size = _u32(buf, k + 4)[0]
        if size < 0x1C or size % 8 or k + size > stop:
            k += 8
            continue
        try:
            nodes, values, _ = chunk.parse_fragment(k + 0x18, k + size - 4)
            event = build_event(nodes, values, _u64(buf, k + 8)[0], filetime(_u64(buf, k + 16)[0]))
        except (ParseError, IndexError, struct.error, UnicodeDecodeError):
            k += 8
            continue
        event.recovered = True
        info.recovered.append(event.record_id)
        yield event
        k += size
