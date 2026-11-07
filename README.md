# Polystar OSIX trace converter

Converts a Polystar OSIX trace export (`traceSchemaV1.0` XML) into:

- a **PCAP** you can open in Wireshark, and
- a **JSON** file with the same messages in a readable, nested form.

The trace XML contains no raw hex, only a decoded field tree where every field has a bit offset, bit size and value. The script writes each field back into a frame buffer at its offset to rebuild the original bytes.

Tested on Diameter Credit-Control (Gx/Ro style) traces over Ethernet / IPv4 with TCP or SCTP, with and without 802.1Q VLAN tags.

## Requirements

Python 3.8+ and the standard library only. No extra packages.

## Usage

```bash
python3 polystar_trace_convert.py <trace.xml> <output_prefix> [--tz-offset-hours N]
```

| Argument | Meaning |
|---|---|
| `trace.xml` | The OSIX trace export |
| `output_prefix` | Output path without extension. Writes `<prefix>.pcap` and `<prefix>.json`. The directory must already exist. |
| `--tz-offset-hours N` | UTC offset of the trace timestamps. Default `1`. The trace carries no timezone. |

Run it with no arguments (or `-h` / `--help`) to print the usage text.

## GUI

```bash
python3 polystar_trace_gui.py
```

Pick the input XML, optionally pick an output folder (default: the input file's folder), set the timezone offset and press Convert. Outputs are named after the input file (`trace.xml` -> `trace.pcap`, `trace.json`). Needs tkinter (`sudo apt install python3-tk` on Debian/Ubuntu; bundled on Windows/macOS).

## Examples

Basic conversion:

```bash
mkdir -p out
python3 polystar_trace_convert.py trace.xml out/trace
```

Trace recorded in UTC:

```bash
python3 polystar_trace_convert.py trace.xml out/trace --tz-offset-hours 0
```

Trace recorded in UTC+2:

```bash
python3 polystar_trace_convert.py trace.xml out/trace --tz-offset-hours 2
```

Open the result in Wireshark, or print the Diameter messages with tshark:

```bash
wireshark out/trace.pcap
tshark -r out/trace.pcap -d tcp.port==3868,diameter -O diameter
```

Query the JSON with `jq`:

```bash
# one line per message: time, type, source, destination
jq -r '.messages[] | [.timestamp_iso, .Type, .["Source Address"], .["Dest Address"]] | @tsv' out/trace.json

# every Subscription-Id-Data value in the file
jq -r '.. | objects | select(.avp? == "Subscription-Id-Data") | .value' out/trace.json
```

## Output

The script prints one line per message with the result of two checks:

```
msg 0: 802 bytes  IP checksum OK  TCP checksum OK
msg 3: 826 bytes  IP checksum OK  SCTP checksum OK
```

Each frame is checked in two steps: the IP header checksum, then the TCP checksum or the SCTP CRC32c (VLAN tags are followed automatically). Both cover the whole packet, so `OK` means the rebuilt frame matches the bytes originally on the wire. `BAD` means some field was encoded wrongly. `n/a` means that layer is absent or not supported by the checker. See Limitations.

### JSON layout

```json
{
  "source": "trace.xml",
  "messages": [
    {
      "index": 0,
      "timestamp_iso": "2026-11-05T03:05:38.108000+01:00",
      "Type": "CreditControlRequest",
      "Source Address": "10.40.232.5",
      "Dest Address": "10.30.50.240; MZF5-BOR-VIP",
      "ethernet": { "...": "..." },
      "ip":       { "...": "..." },
      "tcp":      { "...": "..." },   // or "sctp" for SCTP messages
      "diameter": {
        "header": { "CommandCode": "272 (CreditControl)", "...": "..." },
        "avps": [
          { "avp": "Subscription-Id", "code": 443, "avps": [
              { "avp": "Subscription-Id-Type", "code": 450, "value": "0 (END_USER_E164)" },
              { "avp": "Subscription-Id-Data", "code": 444, "value": "352661324130" }
          ]}
        ]
      }
    }
  ]
}
```

- Simple AVPs have a `value`.
- Grouped AVPs have a nested `avps` list.
- Composite AVPs (for example `3GPP-User-Location-Info`) have a `fields` object with each sub-field.

## Sample and regression check

`samples/sample_voice_trace.xml` is an anonymised Diameter trace (8 messages). Run the check after any change:

```bash
python3 check_samples.py
```

It converts every `samples/*.xml` and exits non-zero if any frame fails its checksum.

## Limitations

- **Only the messages in the trace are written.** There is no TCP handshake or ACK-only traffic, so Wireshark may show TCP sequence gaps.
- **Timestamps are assumed to be UTC+1** unless you pass `--tz-offset-hours`. Compare a message's `Timestamp` with its Diameter `Event-Timestamp` (which states UTC) to confirm the offset.
- **Number vs text is inferred from the decoded value.** A text value made only of digits, whose size is exactly 8 bits per digit, can be mistaken for a number. If you see `BAD` checksums on a new trace, look at such fields first.
- **MCC/MNC pairs are special-cased** to the standard 3-byte BCD encoding used in `3GPP-User-Location-Info`. Other vendor-specific encodings may need new rules in `leaf_bytes()` / `build_frame()`.
- Tested on Ethernet / IPv4 with TCP or SCTP, plain or 802.1Q VLAN-tagged. IPv6, IP tunnels and other transports have not been tested, and the checker reports `n/a` for non-IPv4 frames.
