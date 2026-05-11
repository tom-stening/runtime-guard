# WSL Memory Stabilization Playbook

This playbook is for recurring early-session memory pressure in WSL with VS Code.

## What We Observed

- Guest pressure is the primary issue.
- Host memory has substantial headroom.
- Hidden consumers are mostly VS Code remote Node processes and Python language tooling.
- Multiple WSL distros running at once can amplify host + guest memory churn.
- Some ext4 disks in the WSL VM report prior filesystem errors and need explicit repair workflows.

## Primary Root Causes

1. VS Code remote extension host fan-out
- Multiple extension host processes plus language servers can consume several GB quickly.
- Pylance language servers can stack when many repo windows are active.

2. Guest swap saturation
- Swap usage can exceed 90% while MemAvailable still looks moderate.
- This creates lag, heavy reclaim, and instability long before host RAM is exhausted.

3. Multi-distro background load
- Extra distros and docker-desktop can remain running and consume memory.

4. Filesystem warning signals in non-root mounted ext4 disks
- dmesg warnings suggest some attached WSL ext4 filesystems should be fsck-checked.

## Mandatory Guard Policy Across Repos

All repositories under /home/thomas_stening should continuously satisfy:

- RuntimeGuard autostart present (sitecustomize-managed)
- Included in enforcement report
- Included in runtime status report

Use:

```bash
cd /home/thomas_stening/runtime-guard
source .venv/bin/activate
python scripts/enforce_runtime_guard_all_repos.py \
  --root /home/thomas_stening \
  --enforce-all-repos \
  --report-path reports/repo_guard_enforcement.json \
  --stage repo-autostart \
  --posture wsl_dev

python scripts/repo_guard_fleet_report.py \
  --enforcement-report reports/repo_guard_enforcement.json \
  --output reports/repo_guard_runtime_status.json \
  --include-wsl-diagnosis
```

Success criteria:

- enforced_repos == total_repos
- unenforced_repos == 0

## Host-Side Guardrails (.wslconfig)

Current recommended baseline:

```ini
[wsl2]
memory=16GB
swap=16GB
processors=4
nestedVirtualization=false
vmIdleTimeout=3600000
localhostForwarding=true

[experimental]
autoMemoryReclaim=gradual
pageReporting=true
```

After any .wslconfig change, apply from PowerShell:

```powershell
wsl --shutdown
```

Then reopen the WSL session.

## Immediate Triage Sequence (When Pressure Returns)

1. Check hidden process classes:

```bash
ps -eo pid,ppid,comm,rss,%mem,etime,args --sort=-rss | head -n 50
```

2. Check pressure and swap:

```bash
free -m
cat /proc/pressure/memory
python -m runtime_guard --diagnose-wsl-crash --json
```

3. If multiple distros are running, terminate non-primary distros from PowerShell:

```powershell
wsl -l -v
wsl --terminate Ubuntu
wsl --terminate Ubuntu-20.04
wsl --terminate Ubuntu-22.04
wsl --terminate Ubuntu-Fixed
```

4. If VS Code remote processes are excessive, close unused VS Code windows/workspaces and reconnect only required repos.

## Corruption / Filesystem Repair Workflow

If dmesg shows ext4 warnings like:
- "mounting fs with errors"
- "error count since last fsck"

Do not ignore. Repair workflow:

1. Backup critical distro data.
2. Shutdown WSL:

```powershell
wsl --shutdown
```

3. For affected distros, use export/import or VHD-based repair workflow.
4. Re-run diagnostics and confirm warnings stop recurring.

## Repo Environment Hygiene Mandate

Per repo:

- Keep only needed VS Code extensions enabled for that workspace.
- Avoid opening many heavy Python workspaces simultaneously in one WSL session.
- Prefer one active Python analysis server per active repo window.
- Keep RuntimeGuard posture at wsl_dev for local development.

## Monitoring Cadence

- On login/restart: run fleet enforcement + runtime report once.
- During active work: check runtime report if lag starts.
- After crashes: run diagnose-wsl-crash and compare with prior reports.
