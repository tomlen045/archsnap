# archsnap — Binary Profile & Upgrade Diff

`archsnap` scans every file in a directory into a machine-readable "architecture profile" (ELF / Mach-O / PE / scripts), then diffs two profiles to separate "files that changed" from "old friends whose features changed".

In one line: **cfgdrift watches text config drift; archsnap watches binary feature drift.**

[中文说明](README.md)

## Why

- After a vendor upgrade replaces binaries, PIE flags disappear, dynamic dependencies quietly grow, the interpreter changes — a hash tells you "it changed", but nobody tells you **what it became**.
- Package managers live on symlinks (brew / apt / yum): repointing a symlink = swapping the binary, invisible to `ls`.
- Compliance and incident response: before/after ARM migrations, localization swaps, or canary rollouts, you need a ledger of "what these binaries look like".

## Features

- **Zero-dependency single file**: Python 3 stdlib only, runs offline.
- **Four formats**: ELF (32/64, LE/BE, PIE, PT_INTERP, DT_NEEDED), Mach-O (cpu type / filetype / MH_PIE), PE (machine / subsystem), scripts (shebang).
- **Symlink semantics**: symlinks are resolved to their real target for feature parsing, and the target is recorded — repointing a symlink is a CRIT feature change, not a plain file swap.
- **Three-tier diff**: `FEAT/CRIT` > `CHANGED/WARN` > `ADD|DEL/INFO`.
- **Exit codes are the verdict**: `0` clean, `1` changed, `2` usage/IO error, `3` selftest failed — cron and CI friendly.
- **Skew-immune**: 2 feature changes inside 40k files all surface as CRIT (exercised in selftest).
- **15/15 selftest green**, including synthetic ELF fixtures, an end-to-end symlink-redirect case, and a 400-file skew drill.

## Quick start

```bash
# baseline before upgrade
python3 archsnap.py scan /opt/app -o baseline.json

# after the vendor package lands
python3 archsnap.py scan /opt/app -o after.json --baseline baseline.json

# diff two profiles (only feature-level changes exit 1)
python3 archsnap.py diff baseline.json after.json --fail-on feat --report diff.txt

# built-in selftest
python3 archsnap.py selftest
```

Sample output (real run):

```
[scan] files=44274 binaries=44274 -> cellar.json
  formats: {"RAW": 42407, "Mach-O": 1510, "SCRIPT": 347, "PE": 10}
  pie: {"yes": 560, "no": 0}
```

## Diff semantics

| Level | Trigger | Meaning |
|---|---|---|
| `CRIT / FEAT` | PIE flag, format, arch, interp, DT_NEEDED set, or symlink target changed | behavior features changed, not just the file |
| `WARN / CHANGED` | sha256 differs, features identical | rebuild/patch, features intact |
| `INFO / ADD·DEL` | file appeared/disappeared | roster change |

## Limitations (the honest bit)

- Feature parsing is header + dynamic segment based — **not full reverse engineering**: it answers "did features change", not "what malware was added".
- Packed/obfuscated binaries may parse as `RAW` — hash-level diff still applies.
- Dangling symlinks are skipped: a repoint with a missing target is a deployment accident for the package manager to report.
- Files over 512MB are read truncated — usually data, not programs.

## The sentinel suite

| # | Tool | Watches |
|---|---|---|
| 1 | cronguard | cron job liveness |
| 2 | authguard | login surface |
| 3 | cfgdrift | text config drift |
| 4 | suidhunt | privileged files |
| 5 | callhome | beaconing / call-home traffic |
| **6** | **archsnap** | **binary feature drift (this tool)** |

## License

MIT
