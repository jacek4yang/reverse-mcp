#!/usr/bin/env python3
"""Static-only deep-dive demo on one Tier-B sample through the worker
protocol. Every operation is IDA static analysis (loader + disassembler +
Hex-Rays); the sample is NEVER executed, and no code path loads it into
anything but the analyzer.

Usage: IDADIR=<ida> python sample_demo.py <sample.bin>
"""
import json
import os
import subprocess
import sys

exe = r"D:\AIGC\reverse-mcp\target\release\reverse-mcp.exe"
sample = sys.argv[1]

env = dict(os.environ)
env["REVERSE_MCP_IDA_DIR"] = env.get("IDADIR", r"D:\tool\ida")
env["PATH"] = env["IDADIR"] + ";" + env["PATH"]

p = subprocess.Popen([exe, "worker"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)


def send(o):
    p.stdin.write((json.dumps(o) + "\n").encode())
    p.stdin.flush()


def recv():
    line = p.stdout.readline().decode()
    return json.loads(line) if line.strip() else None


def call(i, method, params):
    send({"id": i, "method": method, "params": params})
    return recv()


recv()  # hello
print("== backend select ==")
print(json.dumps(call(1, "backend.select", {"kind": "idalib"})["result"]))

r = call(2, "db.open", {"path": sample})["result"]
print("\n== open ==")
print(f"functions: {r['function_count']}  bits: {r['bits']}  "
      f"decompiler: {r['decompiler']}")
for seg in r["executable_segments"]:
    print(f"  exec segment {seg['name']}: {seg['size']} bytes")

call(3, "analyze_wait", {})

# imports
r = call(4, "imports.list", {"limit": 400})["result"]
mods = r.get("imports", r).get("modules", [])
print(f"\n== imports: {len(mods)} modules ==")
interesting = []
for m in mods:
    names = [e["name"] for e in m.get("entries", [])]
    interesting += [n for n in names if n in (
        "VirtualAlloc", "VirtualProtect", "CreateProcessA", "CreateProcessW",
        "WriteProcessMemory", "CreateRemoteThread", "InternetConnectA",
        "HttpSendRequestA", "WinExec", "LoadLibraryA", "GetProcAddress",
        "SetWindowsHookExA", "CryptEncrypt", "WSAStartup", "connect",
        "URLDownloadToFileA", "RegSetValueExA", "OpenProcess")]
    print(f"  {m['name']}: {len(names)} entries")
print("  capability-relevant imports:", sorted(set(interesting)) or "(none)")

# strings (bounded probe through search)
r = call(5, "search_text", {"text": "%s", "limit": 5})
txt = json.dumps(r.get("result", ""))[:200]
print(f"\n== string search probe ==\n  {txt}")

# pick the largest function and decompile it
fns = call(6, "functions", {"offset": 0, "limit": 3000})["result"]
fns = fns if isinstance(fns, list) else fns.get("functions", [])
fns = [f for f in fns if f.get("ea_end") and f.get("ea_start")]
big = max(fns, key=lambda f: f["ea_end"] - f["ea_start"])
ea = big["ea_start"]
print(f"\n== largest function {big['name']} @ {ea:#x} "
      f"({big['ea_end'] - big['ea_start']} bytes) ==")

d = call(7, "decompile", {"ea": hex(ea)})
pseudo = d.get("result", {})
text = pseudo.get("text", json.dumps(pseudo)[:300]) if isinstance(pseudo, dict) else str(pseudo)
print("\n-- decompiled (first 1800 chars) --")
print(text if isinstance(text, str) else json.dumps(text)[:1800])

# xrefs to the entry
x = call(8, "xrefs", {"ea": hex(ea), "direction": "to"})
xr = x.get("result", {})
print(f"\n== xrefs to {ea:#x}: {len(xr.get('xrefs', []))} ==")

# microcode maturity probe on the same function
mc = call(9, "hr.microcode", {"ea": hex(ea), "max_insns": 12})
res = mc.get("result", {})
if isinstance(res, dict) and "result" in res:
    res = res["result"]
ins = res.get("insns", [])
print(f"\n== microcode (first {len(ins)} of {res.get('total_insns', '?')}) ==")
for i in ins[:10]:
    print(f"  blk {i['block']:>3} {i['text'][:70]}")

call(99, "shutdown", {})
p.wait(timeout=60)
print(f"\nworker exit: {p.returncode} (clean shutdown, sample never executed)")
