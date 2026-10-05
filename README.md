# Tasks.md: Unauthenticated Path Traversal to RCE (root)

## Description

Tasks.md is a self-hosted kanban board. The backend mounts all `/_api/*` routes with no
authentication and builds filesystem paths by concatenating a user-controlled URL
segment with no sanitization. An unauthenticated attacker can write, read, and delete
files outside the tasks directory. The container runs as root, so overwriting the server
file gives remote code execution as root on the next restart.

- Endpoint: `/_api/resource/:path*` (POST write, GET read, DELETE)
- Privilege: none

## Exploit

`poc.py` (standard library only) demonstrates arbitrary write, read, and recursive
delete outside the tasks directory, then overwrites the server file for RCE as root.

```
python3 poc.py http://TARGET:8092
```

## Disclaimer

This proof of concept is for authorized security testing and education only.
Test only systems that you own or have explicit permission to test. The author
takes no responsibility for misuse.
