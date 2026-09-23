#!/usr/bin/env python3
"""MCP stdio smoke test against a real IDA 9.4 install (production path).

Drives the exact agent configuration: `reverse-mcp serve` over stdio,
initialize -> tools/list -> installations/capabilities -> ida_db open
(explicit 9.4) -> info/functions/decompile/hr -> close, then verifies clean
worker shutdown and no orphan processes.

Usage: IDADIR=<ida install> python mcp_smoke.py <reverse-mcp.exe> <fixture.exe> [9.4]
"""
import json
import subprocess
import sys
import time

exe = sys.argv[1]
fixture = sys.argv[2]
ver = sys.argv[3] if len(sys.argv) > 3 else "9.4"

import os
env = dict(os.environ)
if not env.get("IDADIR"):
    sys.exit("set IDADIR to the IDA install dir before running the smoke")

p = subprocess.Popen([exe, "serve"], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
failures = []


def send(obj):
    p.stdin.write((json.dumps(obj) + "\n").encode())
    p.stdin.flush()


def recv():
    while True:
        line = p.stdout.readline().decode()
        if not line:
            return None
        line = line.strip()
        if not line.startswith("{"):
            continue
        return json.loads(line)


def call(name, args, note):
    send({"jsonrpc": "2.0", "id": call.n, "method": "tools/call",
          "params": {"name": name, "arguments": args}})
    call.n += 1
    r = recv()
    ok = r is not None and "result" in r
    text = json.dumps(r.get("result", {}))[:200] if r else "NO RESPONSE"
    print(f"[{'OK' if ok else 'FAIL'}] {note}: {text[:160]}")
    if not ok:
        failures.append(note)
    return r


call.n = 1

# --- initialize + tools/list ---
send({"jsonrpc": "2.0", "id": 0, "method": "initialize",
      "params": {"protocolVersion": "2025-06-18",
                 "capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}}})
r = recv()
print("[OK] initialize:", json.dumps(r.get("result", {}).get("serverInfo", {})) if r else "NO RESPONSE")
if r is None or "result" not in r:
    failures.append("initialize")
send({"jsonrpc": "2.0", "method": "notifications/initialized"})
send({"jsonrpc": "2.0", "id": 900, "method": "tools/list"})
r = recv()
tools = [t["name"] for t in r["result"]["tools"]] if r and "result" in r else []
print(f"[{'OK' if tools else 'FAIL'}] tools/list: {len(tools)} tools")
if not tools:
    failures.append("tools/list")

# --- installations + capabilities ---
call("ida_installations", {}, "ida_installations")

# --- open explicitly selecting the version ---
r = call("ida_db", {"action": "open", "path": fixture, "backend": "idalib",
                    "ida_version": ver}, f"ida_db open (ida_version={ver})")
db = (r.get("result", {}).get("db") if r and "result" in r else None)
content = r.get("result", {}).get("content", []) if r else []
if not db and content:
    try:
        db = json.loads(content[0]["text"]).get("db")
    except Exception:
        pass
if not db:
    failures.append("no db handle")
    print("FATAL: no db handle; aborting")
    p.kill()
    sys.exit(2)
print("db handle:", db)

call("ida_db", {"action": "info", "db": db}, "ida_db info")
call("ida_capabilities", {"db": db}, "ida_capabilities")
call("ida_metadata", {"db": db}, "ida_metadata")
call("ida_segments", {"db": db}, "ida_segments")
call("ida_imports", {"db": db}, "ida_imports")
call("ida_functions", {"db": db, "limit": 10}, "ida_functions")

r = call("ida_inspect", {"db": db}, "ida_inspect")
fr = call("ida_functions", {"db": db, "limit": 50}, "functions for ea")
ea = None
if fr and "result" in fr:
    try:
        outer = json.loads(fr["result"]["content"][0]["text"])
        arr = outer.get("functions", outer) if isinstance(outer, dict) else outer
        # pick a real function body (skip 1-insn stubs) for decompile paths
        for f in arr:
            if f.get("ea_end", 0) - f.get("ea_start", 0) >= 16:
                ea = f["ea_start"]
                break
        if ea is None and isinstance(arr, list) and arr:
            ea = arr[0]["ea_start"]
    except Exception:
        pass
if ea:
    call("ida_disassemble", {"db": db, "ea": hex(ea), "max_insns": 4}, "ida_disassemble")
    call("ida_xrefs", {"db": db, "ea": hex(ea)}, "ida_xrefs")
    call("ida_graph", {"db": db, "kind": "cfg", "ea": hex(ea)}, "ida_graph cfg")
    call("ida_decompile", {"db": db, "ea": hex(ea)}, "ida_decompile")
    call("ida_hr", {"db": db, "action": "cfunc", "ea": hex(ea)}, "ida_hr cfunc")
    call("ida_hr", {"db": db, "action": "microcode", "ea": hex(ea)}, "ida_hr microcode")
call("ida_analyze", {"db": db, "workflow": "function_context", "ea": hex(ea)} if ea
     else {"db": db, "workflow": "function_context"}, "ida_analyze function_context")
call("ida_db", {"action": "close", "db": db}, "ida_db close")

# --- shutdown ---
send({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}})
p.stdin.close()
try:
    p.wait(timeout=30)
except subprocess.TimeoutExpired:
    p.kill()
    failures.append("serve did not exit")
print("serve exit:", p.returncode)

time.sleep(2)
import subprocess as sp
out = sp.run(["powershell", "-NoProfile", "-Command",
              "(Get-Process reverse-mcp -ErrorAction SilentlyContinue | Measure-Object).Count"],
             capture_output=True, text=True).stdout.strip()
orphans = int(out) if out.isdigit() else -1
print("orphan reverse-mcp processes:", orphans)
if orphans != 0:
    failures.append("orphan workers")

print("\nSMOKE RESULT:", "PASS" if not failures else f"FAIL ({failures})")
sys.exit(0 if not failures else 1)
