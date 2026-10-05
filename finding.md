# Tasks.md — Unauthenticated Path-Traversal Arbitrary File Write/Read/Delete → RCE as root

## Product
- **Project:** Tasks.md (self-hosted, file-based markdown task/kanban board)
- **Repo:** https://github.com/BaldissaraMatheus/Tasks.md
- **Image tested (shipped default):** `baldissaramatheus/tasks.md:latest`
  (digest `sha256:fd3e212fd5619794598418c049feda17810dae4438a84c00a0fb06fe3621b97a`)
- **Source commit (HEAD):** `8f43374183fb4f1f7bd465b04b85ae4bde834827` (2026-03-08, latest)
- **Language:** Node.js (Koa)
- **Maintainer:** solo (BaldissaraMatheus); ~2.2k stars

## Vulnerability
The Koa backend (`backend/server.js`) mounts **all `/_api/*` routes with no
authentication whatsoever** — the only global middleware are `cors()` and
`bodyParser()`. The resource endpoints construct filesystem paths by directly
concatenating a user-controlled, `decodeURIComponent()`-ed URL segment onto
`TASKS_DIR` with **no path sanitization / normalization**, so `../` (or
`%2e%2e%2f`) escapes the intended directory.

### Sink chain (`backend/server.js`)
- **Arbitrary WRITE** — `createResource`, route `POST /_api/resource/:path*`
  - L126 `const subPath = decodeURIComponent(ctx.request.url.substring("/resources".length));`
  - L130 `await fs.promises.writeFile(`${TASKS_DIR}/${subPath}`, content);`  (`content` = request body)
- **Arbitrary READ** — `getResource`, route `GET /_api/resource/:path*`
  - L65 `const path = ctx.request.url.substring("/resources".length);`
  - L91-95 `fs.promises.readFile(`${TASKS_DIR}/${decodeURIComponent(path)}/${lane}/${fileName}`)` (reads `<path>/<lane>/*.md`)
- **Arbitrary DELETE (recursive)** — `deleteResource`, route `DELETE /_api/resource/:path*`
  - L173 `const subPath = decodeURIComponent(...)`
  - L174 `await fs.promises.rm(`${TASKS_DIR}/${subPath}`, { force: true, recursive: true });`
- **Arbitrary RENAME** — `updateResource`, route `PATCH /_api/resource/:path*` (L149).

No `app.use` auth guard exists; `router` is mounted directly (`app.use(mount(`${BASE_PATH}/_api`, router.routes()))`, L261).

### Escalation to RCE (as root)
- `Dockerfile` final stage: `USER root`; `entrypoint.sh` runs `node /api/server.js` **as root**.
- Runtime `TASKS_DIR=/tasks` (set by `entrypoint.sh`), so `POST /_api/resource/..%2f..%2fapi%2fserver.js`
  resolves to `/api/server.js`, overwriting the application entry point with attacker JS.
- The project README's documented run command uses **`--restart unless-stopped`**; the entry point
  is re-executed on any container restart (host reboot, image update, or crash), running the
  attacker's Node.js code as **uid=0(root)**.

## Shipped-default check (no self-inflicted conditions)
- Verified against the **published Docker Hub image**, run **exactly per the README**
  (`docker run ... --restart unless-stopped baldissaramatheus/tasks.md`). No auth was disabled,
  no secrets blanked — the product **ships with no authentication** on the API. All requests in
  the PoC are fully unauthenticated (no cookies/tokens sent).

## Live proof (verified end-to-end, 2026-10-02)
- **WRITE:** `POST /_api/resource/..%2f..%2f..%2fetc%2fEVID_write.conf` → HTTP 201; file created at
  `/etc/EVID_write.conf` owned by `root` with attacker content. (`evidence/01_write_read_delete.txt`)
- **READ:** `GET /_api/resource/..%2f..%2fopt` → leaked `/opt/secretapp/config.md`
  (`DB_PASSWORD=s3cr3t-admin-token`) from outside `/tasks`.
- **DELETE:** `DELETE /_api/resource/..%2f..%2fopt%2fevid_victim` → HTTP 204; directory recursively removed.
- **RCE:** overwrote `/api/server.js` (HTTP 201) → after restart, attacker code executed as
  `uid=0(root)`, wrote `/RCE_PROOF_TASKSMD.txt` and served `pwned-via-unauth-arbitrary-write`.
  (`evidence/02_rce_transcript.txt`) Write→execute independently confirmed by a deliberate syntax
  error producing `SyntaxError ... at node .../run_main_module` from the attacker-written file.

## CVSS 3.1
- **Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
- **Score: 9.8 (Critical)** — unauthenticated RCE as root; also stands alone as unauth arbitrary
  file write/read/delete.
- Conservative floor (scoring only file write+delete+read, ignoring RCE) is still
  `C:H/I:H/A:H` = 9.8 given all three primitives are unauthenticated.

## CWE
- **CWE-22** Improper Limitation of a Pathname to a Restricted Directory (Path Traversal) — primary
- **CWE-306** Missing Authentication for Critical Function
- Related: CWE-73 (External Control of File Name or Path), CWE-434/CWE-94 (write→execute).

## Dedup / distinctness
- GitHub Security Advisories for the repo: **0**.
- NVD keyword `Tasks.md`: **0 results**; `BaldissaraMatheus`: **0 results**.
- No path-traversal / auth fix in git history (HEAD is the only relevant commit line).
- **Non-duplicate, unpatched at HEAD.**

## Remediation
- Require authentication on all `/_api/*` routes.
- Resolve the requested path and verify it stays within `TASKS_DIR`
  (e.g. `path.resolve(TASKS_DIR, subPath)` must start with `path.resolve(TASKS_DIR)+sep`);
  reject `..`. Drop privileges (run as non-root).

## Reproduce
```
docker run -d --name tasksmd -p 8092:8080 --restart unless-stopped baldissaramatheus/tasks.md
python3 poc.py http://localhost:8092
```
