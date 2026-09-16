#!/usr/bin/env python3
"""Repository encoding guard (user-requested hardening after a mojibake
incident where a GBK/cp936 PowerShell code path mangled UTF-8 em-dashes).

Fails on any tracked text file that is:
  - not valid UTF-8,
  - UTF-8 with BOM,
  - containing U+FFFD (replacement char),
  - containing GBK/cp1252 mojibake signatures (e.g. U+9225/U+95B3/U+95C1
    fragments of a mangled em-dash, 'Ã¢â‚¬' cp1252 chains).

Run:  python scripts/check-encoding.py
Exit: 0 clean, 1 violations (listed).
"""
import subprocess
import sys

BAD_CHARS = {
    0xFFFD: "U+FFFD replacement character",
    0x92A5: "U+92A5 (GBK-mangled UTF-8 em-dash fragment)",
    0x9225: "U+9225 (GBK-mangled UTF-8 em-dash fragment)",
    0x95B3: "U+95B3 (GBK-mangled UTF-8 em-dash fragment)",
    0x95C1: "U+95C1 (GBK-mangled UTF-8 em-dash fragment)",
    0x9497: "U+9497 (GBK-mangled UTF-8 fragment)",
    0x00C2: "U+00C2 (cp1252-mangled UTF-8 lead)",
}
BAD_SUBSTR = (
    chr(0xC3) + chr(0xA2) + chr(0xE2) + chr(0x20AC) + chr(0x201A),
    chr(0x9225) + chr(0x3F),
    chr(0x951F) + chr(0x65A4) + chr(0x62F7),
    chr(0x00E5) + chr(0x00A5) + chr(0x00BD),
)


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True,
        encoding="utf-8", errors="replace", check=True,
    ).stdout
    return [l.strip() for l in out.splitlines() if l.strip()]


def is_binary(path):
    try:
        with open(path, "rb") as f:
            return b"\x00" in f.read(8192)
    except OSError:
        return True


def main() -> int:
    violations = []
    for path in tracked_files():
        if is_binary(path):
            continue
        try:
            raw = open(path, "rb").read()
        except OSError as e:
            violations.append(f"{path}: unreadable: {e}")
            continue
        if raw.startswith(b"\xef\xbb\xbf"):
            violations.append(f"{path}: UTF-8 BOM present")
            raw = raw[3:]
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            violations.append(f"{path}: invalid UTF-8 at byte {e.start}")
            continue
        for ch in text:
            if ord(ch) in BAD_CHARS:
                line_no = text.count("\n", 0, text.index(ch)) + 1
                violations.append(f"{path}:{line_no}: {BAD_CHARS[ord(ch)]}")
                break
        for s in BAD_SUBSTR:
            if s in text:
                line_no = text.count("\n", 0, text.index(s)) + 1
                violations.append(f"{path}:{line_no}: mojibake sequence {s!r}")
                break

    if violations:
        print(f"encoding check FAILED: {len(violations)} violation(s)")
        for v in violations:
            print(f"  {v}")
        print("Fix: re-save as UTF-8 without BOM; restore the intended text.")
        print("See .editorconfig and .gitattributes for the repo policy.")
        return 1
    print("encoding check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
