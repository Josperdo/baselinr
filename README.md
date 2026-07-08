# Baselinr

A lightweight, dependency-free Bash utility for auditing security baseline configurations on Linux systems — sudo access, password policy, SSH hardening, file permissions, SUID/SGID binaries, cron, open ports, firewall status, and patch automation.

Most Linux compromises exploit defaults, not zero-days (`PASS_MAX_DAYS=99999`, UFW installed but inactive, SSH permitting root login). Baselinr operationalizes a subset of [CIS Benchmark](https://www.cisecurity.org/cis-benchmarks) controls — the checks that are easy to miss, easy to run, and high-impact when misconfigured — giving a fast, no-tooling-required read on the gap between "installed" and "hardened."

---

## What It Checks

| Check | Looks at | Flags |
|---|---|---|
| Privileged users | `sudo`/`wheel` group membership | Overpermissioned accounts |
| Password policy | `/etc/login.defs` | Weak aging/length/warning thresholds |
| SSH hardening | `/etc/ssh/sshd_config` | Root login, password auth, empty passwords, pubkey auth |
| File permissions | `/etc/passwd`, `shadow`, `group`, `sudoers` | Incorrect mode/ownership |
| Capabilities | `getcap -r /` | Binaries with privileged capabilities (e.g. `cap_setuid`) |
| SUID/SGID binaries | Root filesystem | Binaries outside the common-baseline allowlist ([GTFOBins](https://gtfobins.github.io/) escalation risk) |
| Cron jobs | System cron paths + per-user spool | World-writable or non-root-owned root-run cron files |
| Open ports | `ss -tulnp` | Listening services and their process |
| Firewall | `ufw` / `firewalld` / `iptables` | Inactive firewall or default-allow policy |
| Automatic updates | `unattended-upgrades` / `dnf-automatic` | Installed but not enabled |

Every finding is tagged `OK` / `INFO` / `WARN` / `FAIL` and tallied into a **Baseline Score** (`OK / (OK + WARN + FAIL)`, INFO excluded) printed at the end of the run.

---

## Example Output

```
============================================
  [*] SUID/SGID Binaries
============================================

[INFO] /usr/bin/sudo (rwsr-xr-x root:root) — common baseline SUID/SGID binary.
[WARN] /usr/bin/python3.10 (rwsr-xr-x root:root) — SUID/SGID binary outside the common baseline. Review necessity; check against GTFOBins.

============================================
  [*] Scheduled Tasks (cron)
============================================

[OK]   /etc/crontab (644, owner root).
[FAIL] /etc/cron.d/backup-script is world-writable (666, owner root). Any local user could plant a root-run cron job.

============================================
  [*] Summary
============================================

OK:   6
INFO: 7
WARN: 9
FAIL: 1

Baseline Score: 37%  (6/16 checks passing; INFO findings excluded from scoring)
```

---

## Requirements

- Linux (Debian/Ubuntu or RHEL/CentOS), Bash 4.0+
- No external dependencies beyond standard utilities (`ss`, `stat`, `getcap`, `find`, `grep`, `awk`)
- Root recommended — firewall inspection, capabilities/SUID scan, and cron spool enumeration return partial results without it

## Usage

```bash
git clone https://github.com/Josperdo/Security-Baseline-Checker.git
cd Security-Baseline-Checker
chmod +x security_checker.sh

sudo ./security_checker.sh
sudo ./security_checker.sh | tee audit-$(hostname)-$(date +%F).txt
```

---

## Design Notes

- **Bash, no dependencies** — runs anywhere the target runs, no runtime install required
- **`set -euo pipefail`** — fails fast rather than silently continuing on partial results
- **Explicit config over implicit defaults** — SSH checks distinguish a directive being set from it relying on version-dependent defaults
- **No remediation** — Baselinr reports, it doesn't fix; automated changes to a running system belong behind change control
- **Centralized reporting** — every check funnels through one `report()` helper, which both prints and tallies the summary score

## Known Limitations

- Password checks reflect `/etc/login.defs` only, not PAM (`pam_pwquality`), which can override it
- SSH checks parse `sshd_config` directly rather than `sshd -T`, so `Include`d drop-in configs may be missed
- Sudo enumeration is group membership only — doesn't parse `/etc/sudoers.d/` for direct grants
- SUID/SGID scan stays on the root filesystem (`-xdev`) — separately mounted volumes aren't scanned
- Per-user crontab enumeration requires root to read the spool directory
- Single-node only — no fleet-level aggregation

## Planned Improvements

- [ ] Structured output mode (JSON) for SIEM ingestion or diff-based change detection
- [ ] Exit codes reflecting finding severity for CI/CD pipeline integration
- [ ] Selective check execution via flags (`--ssh-only`, `--skip-firewall`)
- [ ] PAM configuration parsing to complement `/etc/login.defs` checks
- [ ] `sshd -T` effective configuration parsing for SSH checks

---

## License

See [LICENSE](LICENSE) for details.
