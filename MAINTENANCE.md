# Maintenance Runbook — runtime-guard

> Repeating tasks that must be completed at fixed release cadences.  
> These are **non-negotiable hygiene checks** — they should be completed before a release is tagged, not after.

---

## Cadence Overview

| Trigger | Scope | Est. effort | Owner |
|---|---|---|---|
| Every **5 minor releases** (0.5.0, 0.10.0, 1.5.0 …) | Security, deps, community | 2–4 hours | Maintainer |
| Every **1 major release** (1.0.0, 2.0.0 …) | Architecture, API, compliance | 1–2 days | Maintainer + contributors |

---

## Every 5 Minor Releases

Run this checklist before tagging the qualifying minor version.

### M5-01 — Dependency Audit

```bash
# From the project root, with .venv active:
pip install pip-audit safety
pip-audit --requirement <(pip freeze)
safety check --full-report
```

- Review all findings against CVSS score.
- **CVSS ≥ 7.0:** Must be resolved before the release is tagged.
- **CVSS < 7.0:** Log in [KNOWN_ISSUES.md](KNOWN_ISSUES.md) with a fix target.
- Update all unpinned dev dependencies in `pyproject.toml [project.optional-dependencies.dev]`.
- Run the full test suite after any update: `pytest -q`.

**Pass criterion:** `pip-audit` exits 0, or all remaining findings are logged with accepted-risk justification.

---

### M5-02 — OWASP / CWE Security Review

Walk through each item in this checklist manually:

| Check | Guidance |
|---|---|
| **A01 Broken Access Control** | Confirm `apply_kernel_params()` refuses to run without explicit `dry_run=False` confirmation. Review any new file-write paths. |
| **A02 Cryptographic Failures** | Confirm no secrets, tokens, or passwords are logged. Confirm any hash operations use SHA-256+. |
| **A03 Injection** | Audit all `subprocess.run()` calls. Confirm every call uses a list (not a shell string). Confirm no user-supplied strings are passed to shell. |
| **A05 Security Misconfiguration** | Confirm generated `.wslconfig` and `conftest.py` templates do not introduce insecure defaults. |
| **A09 Security Logging & Monitoring Failures** | Confirm structured events (KI-001 area) do not include process args, env vars, or file contents. |
| **CWE-532 Sensitive Info in Log** | Confirm `PressureReport.guidance` does not include command output that could expose credentials. |

**Pass criterion:** No new OWASP Top 10 / CWE Top 25 findings. Any findings raise a P0 issue and block the release.

---

### M5-03 — Community Feedback Synthesis

1. Review all GitHub issues opened since the last synthesis.
2. Tag each with a priority label (P0–P3) and a milestone.
3. Identify the top 3 most-requested features or pain points. Add them to [ROADMAP.md](ROADMAP.md) if not already present.
4. Close or respond to any issue open > 60 days with no activity.
5. Update [KNOWN_ISSUES.md](KNOWN_ISSUES.md): close any fixed issues, add any new confirmed bugs.

**Pass criterion:** No open issue is untagged or unassigned.

---

### M5-04 — Documentation Currency Check

| Item | Check |
|---|---|
| README.md | Configuration table matches current `_PRESETS` and env var defaults. |
| ROADMAP.md | All `✅ DONE` items reflect actual merged code. No ghost items. |
| KNOWN_ISSUES.md | All `Fixed in` versions correspond to released tags. |
| RESEARCH.md | All `📅 Planned` research tasks have a target version still on the roadmap. |
| Docstrings | All public symbols (`__all__`) have a current docstring. Run `pydoc -w runtime_guard` and inspect. |
| CHANGELOG | A `## Unreleased` section exists and lists all changes since last tag. |

**Pass criterion:** No documentation lag older than 1 minor release.

---

### M5-05 — Test Coverage and Quality Gate

```bash
pytest --cov=runtime_guard --cov-report=term-missing -q
```

- **Line coverage must be ≥ 90 %.**
- **Branch coverage must be ≥ 80 %.**
- Review any uncovered branches — add tests or mark `# pragma: no cover` with justification.
- Run `ruff check src/ tests/` and `ruff format --check src/ tests/`. Zero warnings.
- Run `bandit -r src/`. No HIGH severity findings.

**Pass criterion:** All thresholds met, no lint errors, no bandit HIGH findings.

---

## Every Major Release

Run the full minor-release checklist above **plus** all of the following before tagging the major version.

### MA-01 — Architecture Review

1. Re-read the full [ROADMAP.md](ROADMAP.md) top to bottom.
2. Assess whether the current module structure (single `__init__.py`) still serves the project's scope, or whether splitting into sub-modules is warranted.
3. Review the public API surface (`__all__`). Document every symbol:
   - Is it still used?
   - Does its signature need to change?
   - Should it be deprecated?
4. Update or create an architecture decision record (ADR) in `docs/adr/` for each structural decision made.

**Pass criterion:** At least one ADR is written or updated. `__all__` is intentional and documented.

---

### MA-02 — API Stability Review

| Action | Detail |
|---|---|
| List all breaking changes since last major | Capture in `CHANGELOG.md` under `## Breaking Changes`. |
| Verify deprecation warnings | Any symbol deprecated in the previous major must be removed in this one. Any symbol deprecated now must emit `DeprecationWarning` with guidance. |
| Update semver rationale | Confirm the major bump is warranted (breaking API change, not just a large feature). |
| Publish migration guide | For each breaking change, write a "Before / After" code snippet in `docs/migration/vN.0.md`. |

**Pass criterion:** `CHANGELOG.md` has a populated `## Breaking Changes` section. Migration guide exists.

---

### MA-03 — Compliance Gap Assessment

Repeat the M5-02 security review, plus:

1. Re-run `pip-audit` and `safety check` with `--full-report`. Resolve all findings before tagging.
2. Review any new regulation changes relevant to the project's deployment contexts:
   - EU: GDPR updates, ENISA threat landscape
   - US: HIPAA OCR guidance, NIST framework updates
   - Asia-Pacific: PIPL (China), PDPA (Singapore/Thailand), APPI (Japan)
   - Brazil: LGPD
3. Update [RESEARCH.md](RESEARCH.md) Area 5 with any new compliance sources.
4. If the project is deployed in regulated sectors, confirm a responsible-disclosure policy exists in `SECURITY.md`.

**Pass criterion:** No unresolved CVSS ≥ 7.0 findings. SECURITY.md exists and is current.

---

### MA-04 — Performance Regression Baseline

1. Run the performance benchmarks defined in [RESEARCH.md](RESEARCH.md) Area 6 research tasks.
2. Compare results against the baseline captured at the previous major release.
3. If any metric regresses by > 20 %, file a P1 issue and do not tag until resolved.
4. Update the baseline record below.

#### Performance baseline record

| Metric | v0.2.0 baseline | Current (pre-tag) | Delta | Status |
|---|---|---|---|---|
| `check()` cold-path (no pressure) P99 | TBD | — | — | Not yet measured |
| `/proc/meminfo` parse P99 | TBD | — | — | Not yet measured |
| `vm_stat` subprocess P99 (macOS) | TBD | — | — | Not yet measured |
| Background thread CPU @ 5 s interval | TBD | — | — | Not yet measured |

**Pass criterion:** No metric regresses > 20 % vs. previous major baseline.

---

### MA-05 — Capabilities & Platform (CAP) Document Update

Update (or create) `docs/CAP.md` to reflect the current release:

| Section | Content |
|---|---|
| Supported platforms | Linux (kernels tested), macOS (versions tested), Windows (builds tested), WSL 2 |
| Python versions | Tested matrix (CI matrix from `pyproject.toml`) |
| Optional dependencies | List all optional extras and what they unlock |
| Known incompatibilities | Platforms/versions with known issues (link to KNOWN_ISSUES.md) |
| Deployment models | Library, CLI, daemon thread, pytest plugin, pre-commit hook |

**Pass criterion:** `docs/CAP.md` exists and is accurate as of the tagged version.

---

## Release Tagging Checklist

Run this final check immediately before `git tag`:

```bash
# 1. All tests pass
pytest -q

# 2. No lint errors
ruff check src/ tests/ && ruff format --check src/ tests/

# 3. No security findings (HIGH)
bandit -r src/ -ll

# 4. Version bump is applied
grep 'version' pyproject.toml

# 5. CHANGELOG.md has a section for this version (not just "Unreleased")
head -20 CHANGELOG.md

# 6. Git working tree is clean
git status
```

Then tag and push:

```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push origin vX.Y.Z
```

---

## Ad-hoc Maintenance

These tasks are not cadence-bound but should be performed promptly when triggered.

| Trigger | Action |
|---|---|
| New CVE affecting a dependency | Run M5-01. Patch within 72 hours for CVSS ≥ 7.0. |
| New Linux kernel changes `/proc/meminfo` field semantics | Re-validate `_read_snapshot()` against kernel changelog. File issue if broken. |
| macOS or Windows removes a shell command we call | Implement alternative before next minor release (see KI-002 pattern). |
| `wmic` / `vm_stat` / PowerShell deprecation notices | Escalate to P1 immediately. Do not wait for the next cadence. |
| Contributor submits first PR | Review `CONTRIBUTING.md` exists and is current. |
