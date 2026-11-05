# Polystar OSIX trace converter

Single-file tool (`polystar_trace_convert.py`, stdlib only) that turns a Polystar OSIX trace XML
(`traceSchemaV1.0`) into a PCAP and a nested JSON. See `README.md` for usage.

## Things to know
- The trace has **no raw bytes** (`hexData` is absent). Frames are rebuilt by writing every leaf
  `messageNode` (bit `offset`, bit `size`, decoded value) back into a bit buffer in `build_frame()`.
- **There is no unit test suite. The checksum check is the test.** `verify()` validates the IP header
  checksum and the TCP checksum or SCTP CRC32c (following 802.1Q tags). Those cover the whole packet, so
  `OK` means the rebuilt bytes equal the originals. `BAD` means a field was encoded wrongly.
- After any change, run `python3 check_samples.py`. It must report PASS (0 bad, 0 n/a) for every file in `samples/`.
- `leaf_bytes()` decides number vs text from the decoded string (fragile on purpose-less digit strings).
  New `BAD` frames usually mean a new field type needs a rule there or in `build_frame()`.
- Special cases already handled: spaced-hex octet strings (e.g. AVP 901), 12-bit MCC/MNC pairs
  (3-byte BCD PLMN), IPv4/MAC literals, `'H` hex values, bit-pattern prefixes (`-1------`).
- Timestamps carry no timezone; default is UTC+1 (override with `--tz-offset-hours`).

## Samples
- `samples/sample_voice_trace.xml` is anonymised (same-length replacements, checksums recomputed).
  Never commit real operator traces, IPs, MACs, hostnames, MSISDN/IMSI. Anonymising script is kept out of the repo
  on purpose because it contains the original names.

## Conventions
- Standard library only; Python 3.8+.
- Commit to `main` directly (small personal repo).
