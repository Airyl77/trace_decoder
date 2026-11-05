#!/usr/bin/env python3
"""Convert a Polystar OSIX trace XML (traceSchemaV1.0) into a PCAP and a readable JSON.

The trace has no raw hex, only a decoded field tree where every leaf carries
(bit offset, bit size, decoded value). Frames are rebuilt by writing each leaf
back into a bit buffer at its offset.

Usage: polystar_trace_convert.py trace.xml out_prefix [--tz-offset-hours 1]
"""
import json, re, struct, sys, ipaddress
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

NS = {"t": "http://www.polystar.com/OSIX/monitoring/traceSchemaV1.0"}


TEXT_LABELS = {"Subscription-Id-Data", "Called-Station-Id", "Calling-Station-Id"}


def leaf_bytes(label, size):
    """Return (value:int, nbits) to place for a leaf, or None if it carries no data."""
    # Sub-byte fields carry a bit pattern prefix like '-1------ ' (digits = real bits)
    m = re.match(r"^([01-]{2,})\s", label)
    if m and size <= 8:
        pat = m.group(1)
        # keep only the bits that are real; caller ORs them in
        return ("pattern", pat)
    if " = " not in label:
        return None
    val = label.split(" = ", 1)[1].strip()
    if re.fullmatch(r"[0-9a-fA-F]+'H", val.split(" ")[0] if "'H" in val else ""):
        return ("int", int(val.split("'H")[0], 16))
    hx = re.fullmatch(r"([0-9a-fA-F]{2} )+[0-9a-fA-F]{2}", val)
    if hx and len(val.replace(" ", "")) * 4 == size:
        return ("bytes", bytes.fromhex(val.replace(" ", "")))
    mac = re.fullmatch(r"([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", val)
    if mac:
        return ("bytes", bytes.fromhex(val.replace(":", "")))
    try:
        return ("bytes", ipaddress.ip_address(val).packed)
    except ValueError:
        pass
    im = re.fullmatch(r"(-?\d+)(\s+\(.*\))?", val)
    name = label.split(" = ", 1)[0].strip()
    digit_str = (
        size % 8 == 0 and len(val) * 8 == size and im and not im.group(2)
        and (name.startswith("SGSN-M") or name in TEXT_LABELS or val.startswith("0") and len(val) > 1
             or (size > 32 and name in ("Value", "Identity")))
    )
    if im and not digit_str:
        return ("int", int(im.group(1)))
    hm = re.match(r"^([0-9a-fA-F]+)'H", val)
    if hm:
        return ("int", int(hm.group(1), 16))
    return ("bytes", val.encode("utf-8"))


def build_frame(msg):
    tops = msg.findall("t:nodes/t:messageNode", NS)
    total_bits = max(int(t.get("offset")) + abs(int(t.get("size"))) for t in tops)
    # Top-level protocol layers are listed with negative sizes (= "to end"); use the
    # last layer's end offset, which is the frame end.
    total_bits = int(tops[-1].get("offset")) + abs(int(tops[-1].get("size")))
    buf = bytearray((total_bits + 7) // 8)

    def put(off, nbits, value):
        for i in range(nbits):
            bit = (value >> (nbits - 1 - i)) & 1
            p = off + i
            if bit:
                buf[p // 8] |= 0x80 >> (p % 8)
            else:
                buf[p // 8] &= ~(0x80 >> (p % 8))

    pending_mcc = {}

    def walk(n):
        kids = n.findall("t:messageNode", NS)
        if kids:
            for k in kids:
                walk(k)
            return
        label = (n.find("t:value", NS).text or "").strip()
        off, size = int(n.get("offset")), int(n.get("size"))
        # 3GPP PLMN (MCC/MNC) is shown as two 12-bit fields but is encoded as
        # 3 BCD bytes: [MCC2 MCC1][MNC3 MCC3][MNC2 MNC1], MNC3 = F for 2-digit MNCs.
        if label.startswith("Mobile Country Code (MCC) = "):
            pending_mcc[off] = label.split(" = ", 1)[1].strip().split()[0]
            return
        if label.startswith("Mobile Network Code (MNC) = ") and (off - 12) in pending_mcc:
            mcc = pending_mcc.pop(off - 12)
            mnc = label.split(" = ", 1)[1].strip().split()[0]
            d = [int(c) for c in mcc.zfill(3)]
            m = [int(c) for c in mnc.zfill(2)] + ([15] if len(mnc) < 3 else [])
            for i, b in enumerate(((d[1] << 4) | d[0], (m[2] << 4) | d[2], (m[1] << 4) | m[0])):
                put(off - 12 + 8 * i, 8, b)
            return
        r = leaf_bytes(label, size)
        if not r or size <= 0:
            return
        kind, v = r
        if kind == "pattern":
            for i, ch in enumerate(v):
                if ch in "01":
                    put((off // 8) * 8 + i, 1, int(ch))
        elif kind == "int":
            put(off, size, v & ((1 << size) - 1))
        else:
            v = v[: size // 8]
            for i, b in enumerate(v):
                put(off + 8 * i, 8, b)

    for t in tops:
        walk(t)
    return bytes(buf)


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def verify(frame):
    ip = frame[14:34]
    ok_ip = csum(ip) == 0
    tcp = frame[34:]
    pseudo = frame[26:34] + struct.pack("!BBH", 0, 6, len(tcp))
    ok_tcp = csum(pseudo + tcp) == 0
    return ok_ip, ok_tcp


USAGE = """\
Polystar OSIX trace converter: trace XML -> PCAP + readable JSON

Usage:
  python3 polystar_trace_convert.py <trace.xml> <output_prefix> [--tz-offset-hours N]

Arguments:
  trace.xml            Polystar OSIX trace export (traceSchemaV1.0)
  output_prefix        Output path without extension. Writes <prefix>.pcap and <prefix>.json
  --tz-offset-hours N  UTC offset of the trace timestamps (default: 1). The trace
                       timestamps carry no timezone; this sets the PCAP/JSON times.

Example:
  python3 polystar_trace_convert.py trace.xml out/trace --tz-offset-hours 1

Notes:
  - Frames are rebuilt from the decoded field tree (the trace has no raw hex).
  - Each frame is checked with IP and TCP checksums and reported as OK/BAD.
  - Output directory must already exist.
"""


# ------------------------------------------------------------------ JSON view
def _strip_bits(key):
    return re.sub(r"^[01-]{4,}\s", "", key).strip()


def _leaves(node, out):
    """Collect (name, value) for every non-header leaf below node, in order."""
    for k in node.findall("t:messageNode", NS):
        v = k.find("t:value", NS).text.strip()
        if v.startswith(("AVP Code", "Length Field", "Vendor Id")) or v == "Flags":
            continue
        if k.findall("t:messageNode", NS) and v in ("Flags", "Value") or (k.findall("t:messageNode", NS) and " = " not in v):
            _leaves(k, out)
        elif " = " in v and not k.findall("t:messageNode", NS):
            key, val = v.split(" = ", 1)
            out.append((_strip_bits(key), val))
        elif k.findall("t:messageNode", NS):
            _leaves(k, out)


def avp_tree(node):
    """Turn a Diameter AVP messageNode into {avp, code, vendor, value | fields | avps}."""
    title = node.find("t:value", NS).text.strip()
    name = re.sub(r"\s+AVP = (\d+)$", "", title)
    out = {"avp": name}
    m = re.search(r"AVP = (\d+)$", title)
    if m:
        out["code"] = int(m.group(1))
    sub, scalar = [], []
    for k in node.findall("t:messageNode", NS):
        v = k.find("t:value", NS).text.strip()
        if v.startswith(("AVP Code", "Length Field")) or v == "Flags":
            continue
        if v.startswith("Vendor Id"):
            out["vendor"] = v.split("= ", 1)[1]
        elif v == "Grouped-AVPs":
            sub = [avp_tree(g) for g in k.findall("t:messageNode", NS)]
        elif " AVP = " in v:
            sub.append(avp_tree(k))
        else:
            scalar.append(k)
    leaves = []
    for k in scalar:
        v = k.find("t:value", NS).text.strip()
        if k.findall("t:messageNode", NS):
            _leaves(k, leaves)
        elif " = " in v:
            key, val = v.split(" = ", 1)
            leaves.append((_strip_bits(key), val))
    # drop pure padding/spare noise but keep everything else
    if len(leaves) == 1:
        out["value"] = leaves[0][1]
    elif leaves:
        fields = {}
        for key, val in leaves:
            i, k2 = 2, key
            while k2 in fields:
                k2 = f"{key} #{i}"; i += 1
            fields[k2] = val
        out["fields"] = fields
    flat = []
    for x in sub:  # splice codeless wrapper nodes (e.g. "SubscriptionId") into their parent
        if "code" not in x and "avps" in x and set(x) <= {"avp", "avps"}:
            flat += x["avps"]
        else:
            flat.append(x)
    if flat:
        out["avps"] = flat
    return out


def message_json(msg, idx, tz):
    params = {p.get("name"): p.text for p in msg.findall("t:parameters/t:parameter", NS)}
    d = {"index": idx, "timestamp_iso": parse_ts(params.get("Timestamp"), tz).isoformat(), **params}
    for t in msg.findall("t:nodes/t:messageNode", NS):
        title = t.find("t:value", NS).text.strip()
        if title == "DIAMETER":
            hdr, avps = {}, []
            for k in t.findall("t:messageNode", NS):
                v = k.find("t:value", NS).text.strip()
                if " AVP = " in v:
                    avps.append(avp_tree(k))
                elif " = " in v:
                    key, val = v.split(" = ", 1)
                    key = re.sub(r"^[01-]{4,}\s", "", key)
                    hdr[key] = val
            d["diameter"] = {"header": hdr, "avps": avps}
        else:
            fields = {}
            for k in t.findall("t:messageNode", NS):
                v = k.find("t:value", NS).text.strip()
                if " = " in v and not k.findall("t:messageNode", NS):
                    key, val = v.split(" = ", 1)
                    fields[re.sub(r"^[01-]{4,}\s", "", key)] = val
            d[title.lower()] = fields
    return d


def parse_ts(s, tz):
    return datetime.strptime(s, "%a %d %b %Y %H:%M:%S.%f").replace(tzinfo=tz)


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help") or len(args) < 2:
        print(USAGE)
        sys.exit(0 if not args or args[0] in ("-h", "--help") else 1)
    src, prefix = args[0], args[1]
    off = 1.0
    if "--tz-offset-hours" in args:
        try:
            off = float(args[args.index("--tz-offset-hours") + 1])
        except (IndexError, ValueError):
            sys.exit("error: --tz-offset-hours needs a number, e.g. --tz-offset-hours 1\n\n" + USAGE)
    tz = timezone(timedelta(hours=off))
    root = ET.parse(src).getroot()
    msgs = root.findall(".//t:call/t:messages/t:message", NS) + root.findall("t:messages/t:message", NS)

    pcap = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    js = []
    for i, m in enumerate(msgs):
        frame = build_frame(m)
        ts = parse_ts({p.get("name"): p.text for p in m.findall("t:parameters/t:parameter", NS)}["Timestamp"], tz)
        e = ts.timestamp()
        pcap += struct.pack("<IIII", int(e), int((e % 1) * 1e6), len(frame), len(frame)) + frame
        ok_ip, ok_tcp = verify(frame)
        print(f"msg {i}: {len(frame)} bytes  IP checksum {'OK' if ok_ip else 'BAD'}  TCP checksum {'OK' if ok_tcp else 'BAD'}")
        js.append(message_json(m, i, tz))
    open(prefix + ".pcap", "wb").write(pcap)
    json.dump({"source": src.split("/")[-1], "messages": js}, open(prefix + ".json", "w"), indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
