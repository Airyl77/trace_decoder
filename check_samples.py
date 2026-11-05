#!/usr/bin/env python3
"""Regression check: convert every samples/*.xml and fail if any frame has a BAD checksum.

Usage: python3 check_samples.py [dir]      (default: samples/)
"""
import glob, os, subprocess, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
folder = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "samples")
files = sorted(glob.glob(os.path.join(folder, "*.xml")))
if not files:
    sys.exit(f"no .xml samples found in {folder}")

failed = False
with tempfile.TemporaryDirectory() as tmp:
    for f in files:
        out = subprocess.run(
            [sys.executable, "-I", os.path.join(here, "polystar_trace_convert.py"), f, os.path.join(tmp, "out")],
            capture_output=True, text=True,
        )
        lines = [l for l in out.stdout.splitlines() if l.startswith("msg ")]
        bad = [l for l in lines if "BAD" in l or " n/a" in l]
        ok = out.returncode == 0 and lines and not bad
        failed |= not ok
        print(f"{'PASS' if ok else 'FAIL'}  {os.path.basename(f)}: {len(lines)} frames, {len(bad)} bad/unchecked")
        for l in bad:
            print("   ", l)
        if out.returncode:
            print(out.stderr)
sys.exit(1 if failed else 0)
