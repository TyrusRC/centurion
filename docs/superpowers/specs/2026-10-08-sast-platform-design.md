# Centurion Full SAST Platform — Design Spec

**Date:** 2026-10-08
**Status:** Approved (brainstorming) — pending spec review → implementation plan
**Author:** TyrusRC

## Goal

Expand Centurion from a mobile QA + pentest toolkit (26 OWASP MASTG tool wrappers,
CLI + MCP server) into a **full static-security platform** covering **SAST + SCA +
secrets + IaC** across **web, desktop, generic, and the existing mobile** targets —
over **both source trees and built artifacts** — while keeping Centurion's
**wrap-don't-reimplement** philosophy. Output is a **unified, SARIF-compatible
findings model** with **merged SARIF export**, **policy/severity gating with CI exit
codes**, and co-equal **MCP / CLI / CI** drivers. Centurion becomes a **required
(main) dependency of chimera**, which wraps its scan like its other tool wrappers.

## Context

Centurion already provides the foundation this builds on (do not rebuild it):

- `adapters/base.py::Adapter` — ABC: `name`/`binary`/`mastg_id`/`platform`/`category`
  class attrs, `detect() -> ToolStatus`, `install_hint()`, shells out via a `Runner`
  (`RealRunner`/`FakeRunner`).
- `models.py` — `Platform{ANDROID,IOS,GENERIC,NETWORK}`,
  `Category{DEVICE_QA,STATIC,DYNAMIC,NETWORK,RECON}`,
  `Severity{INFO,LOW,MEDIUM,HIGH,CRITICAL}`, `Finding`, `ToolStatus`, `Artifact`.
- `Finding` today: `id, title, severity, tool, detail="", location=None,
  mastg_refs=[], masvs_refs=[]`.
- `registry.py::Registry` + `default_registry()` (`.doctor()`), `session.Workspace`
  (per-target workspace), `report/` (`generate(workspace, fmt)`, markdown/html from a
  dict model), `mcp/server.py` (FastMCP `@mcp.tool()`), `masvs`, `ScriptLibrary`.
- Existing SAST footholds: `adapters/generic/opengrep.py` (Semgrep fork),
  `adapters/generic/gitleaks.py` (secrets, returns `Finding[]` from JSON).

## Constraints (global; every task inherits these)

- **Wrap, don't reimplement.** Each tool is an `Adapter` subclass that shells out and
  parses output. No tool is auto-installed; a missing tool yields `ToolStatus(installed
  =False)` + an `install_hint()`, and the scan **skips it, never hard-fails**.
- **Hybrid aggregation (Approach C).** `Finding` stays canonical, extended to be
  SARIF-compatible. Each scanner **prefers the tool's native SARIF output**
  (`sarif_to_findings`) and falls back to native-JSON parsing only when the tool can't
  emit SARIF. Centurion **exports one merged SARIF 2.1.0 log** plus the existing
  MD/HTML/JSON.
- **Both source trees and built artifacts.** A built artifact is unpacked to a source/
  code tree first (delegating to chimera's extractors), then the same source scanners
  run on the tree.
- **Co-equal drivers:** CLI (`centurion scan`), MCP tools, and a programmatic API
  (`centurion.sast.scan(...)`) that chimera imports. CI = SARIF + policy exit code.
- **Centurion is a required (main) dependency of chimera**, not an optional extra.
- Python ≥ 3.11, `hatchling`, Apache-2.0, deps kept minimal (`typer`, `rich`, `mcp`;
  add `jsonschema`/nothing-heavier only if strictly needed — SARIF is plain JSON).

## Scope

In: SAST (code), SCA (dependencies/SBOM), secrets, IaC — over source trees and built
artifacts (web/desktop/mobile/generic). Merged SARIF, unified findings, policy gating,
CI exit codes, MCP + CLI + API, chimera integration, and a cleanup pass (dedup/unused/
legacy).

Out (future, not this spec): DAST/running-app analysis, a hosted dashboard/server,
auto-remediation/fix suggestions, custom rule authoring UIs, non-SARIF CI integrations
beyond exit codes + SARIF upload.

## Architecture

A new `src/centurion/sast/` orchestration layer sits on top of the existing adapter/
findings/report machinery. `scan(target)`:

1. **Resolve** the target to a code tree (`sast/target.py`). Source dir/repo → used
   as-is. Built artifact → unpacked to a tree (via a pluggable unpacker that calls
   chimera's extractors; see "Artifact unpacking").
2. **Detect** languages/ecosystems present in the tree (`sast/languages.py`).
3. **Select** the available scanners for those languages × requested categories
   (`sast/registry.py`), skipping missing tools (recorded with install hints).
4. **Run** each scanner (`sast/scanner.py`), SARIF-preferred, → `Finding[]`.
5. **Aggregate**: merge + dedup (`sast/aggregate.py`).
6. **Emit**: merged SARIF + MD/HTML/JSON report (reuse `report/`).
7. **Gate**: `sast/policy.py` maps findings → CI exit code.

### New data-model changes (`models.py`)

- `Platform`: add `WEB = "web"`, `DESKTOP = "desktop"`.
- `Category`: add `SCA = "sca"`, `SECRET = "secret"`, `IAC = "iac"`. (SAST maps to the
  existing `STATIC`.)
- `Finding`: add optional, defaulted (backward-compatible) fields:
  - `rule_id: str | None = None`
  - `category: str | None = None` (static|sca|secret|iac)
  - `file: str | None = None`, `line: int | None = None`, `end_line: int | None = None`
  - `cwe: list[str] = []`, `references: list[str] = []`
  - `fingerprint: str | None = None` (stable dedup key)
  - `ecosystem: str | None = None` (for SCA: pypi/npm/go/…)
  `location` stays the human string; `file`/`line` are the structured form.

### Scanner interface (`sast/scanner.py`)

`class Scanner(Adapter)` adds:
- `languages: tuple[str, ...]` — ecosystems/languages it applies to (e.g. `("python",)`,
  `("javascript","typescript")`, `("*",)` for language-agnostic like trivy/gitleaks).
- `supports_sarif: bool` — whether the tool emits SARIF natively.
- `scan_command(tree: str, out: str) -> list[str]` — argv producing SARIF (or native).
- `parse_native(text: str) -> list[Finding]` — fallback parser (only if not SARIF).
- `scan(tree: str, workdir: str) -> ScanResult` — run, then
  `sarif_to_findings(out)` if `supports_sarif` else `parse_native(...)`; returns
  `ScanResult{scanner, findings, skipped: bool, error: str|None, duration_s}`.

### Aggregation (`sast/aggregate.py`)

- `sarif_to_findings(sarif: dict, tool: str) -> list[Finding]` — map one SARIF log:
  `result.ruleId→rule_id`; `message.text→detail` (+ rule name→title);
  `level(error|warning|note)→severity(high|medium|low)` (tools that set
  `properties.security-severity` override to critical/high/…);
  `locations[0].physicalLocation{artifactLocation.uri→file, region.startLine→line}`;
  `partialFingerprints`/`fingerprints`→`fingerprint`; `properties.cwe`/`tags`→`cwe`;
  `properties.references`/`helpUri`→`references`.
- `findings_to_sarif(findings: list[Finding]) -> dict` — one SARIF 2.1.0 log, one `run`
  per contributing tool (driver name = tool), rules deduped by `rule_id`, results with
  level (reverse severity map) + physicalLocation + partialFingerprints.
- `merge(results: list[ScanResult]) -> list[Finding]` — concatenate, then **dedup** by
  `fingerprint` (computed when absent = `sha1(tool|rule_id|file|line|normalized_snippet)
  [:16]`). Deterministic order (severity desc, then file, line, rule_id).
- `severity_level` / `level_severity` mapping tables live here.

### Policy / gating (`sast/policy.py`)

- `Policy{ fail_on: Severity, ignore_rules: set[str], ignore_paths: list[glob],
  category_filter: set[Category] }`, loaded from `.centurion-sast.toml` (stdlib
  `tomllib`) or `.centurion-sast.json`, or from MCP/CLI args. No new dependency (no
  YAML).
- `gate(findings, policy) -> int` — exit code 0 (pass) / 1 (findings ≥ `fail_on`) / 2
  (scan error). `apply(findings, policy)` filters ignores first.

### Artifact unpacking (`sast/target.py`)

- `TargetResolver.resolve(target) -> ResolvedTarget{kind, tree, meta, cleanup}`.
- `kind` ∈ `source | apk | ipa | pe | elf | electron | tauri | dotnet | python | jar |
  archive`. Detection by extension + magic + manifest.
- An `Unpacker` protocol with a default implementation that calls **chimera's
  extractors** when chimera is importable (asar/node→`node_extract`, tauri→
  `tauri_extract`, dotnet→`dotnet_extract`, python→`pyextract`, apk→apktool/jadx
  already wrapped by Centurion, …). When chimera is absent, fall back to Centurion's own
  mobile unpackers / plain archive extraction, and record which artifact kinds are
  unsupported. (chimera importing Centurion, not vice-versa, is the hard dependency
  direction; Centurion's use of chimera here is best-effort/optional to avoid a cycle.)

> **Dependency direction:** chimera → requires → Centurion (hard). Centurion → uses →
> chimera for artifact unpacking **only if present** (soft, import-guarded), so there is
> no hard cycle. A built-artifact scan without chimera degrades to the kinds Centurion
> can already unpack.

## Initial scanner set (`src/centurion/adapters/sast/`)

| Scanner | Tool | Category | Languages | Output |
|---|---|---|---|---|
| `semgrep` | semgrep **or** opengrep | static | multi (`*`) | SARIF (`--sarif`) |
| `bandit` | bandit | static | python | SARIF (`-f sarif`) |
| `gosec` | gosec | static | go | SARIF (`-fmt sarif`) |
| `njsscan` | njsscan | static | javascript, typescript | SARIF (`--sarif`) |
| `eslint_security` | eslint + eslint-plugin-security | static | javascript, typescript | SARIF (formatter) |
| `trivy` | trivy fs | sca, iac, secret | `*` | SARIF (`--format sarif`) |
| `grype` | grype | sca | `*` (SBOM/deps) | SARIF (template) |
| `checkov` | checkov | iac | terraform, cfn, k8s, … | SARIF (`-o sarif`) |
| `gitleaks` | gitleaks (existing) | secret | `*` | JSON→Finding (keep) |

- **Dedup opengrep↔semgrep:** they are the same engine. Keep ONE scanner module with a
  `binary` that resolves `semgrep` then `opengrep` (alias); the legacy
  `adapters/generic/opengrep.py` is folded into it (see Cleanup).
- **Secrets:** gitleaks is the secret scanner; trivy's secret mode is **off by default**
  to avoid double-reporting (configurable).
- Each scanner declares `platform` as `GENERIC`/`WEB`/`DESKTOP` as appropriate; selection
  is primarily by `languages` × `category`, not platform.

## chimera integration

- **Dependency:** add `centurion>=0.2` (the version that ships this platform) to
  chimera's **main** `[project].dependencies` (not an extra).
- **Adapter:** `chimera/adapters/centurion_adapter.py` — thin wrapper calling
  `centurion.sast.scan(path, categories=..., policy=...)` programmatically, returning
  the merged findings + SARIF path.
- **MCP tools** (new `src/chimera/mcp_schemas/sast.py` module + a handler block):
  - `sast_scan` — run the platform on a path or built artifact; args: `path`,
    `categories` (default all), `fail_on` (default none), `out_dir`. Returns a summary
    (counts by severity/category), the top-N findings, and the merged-SARIF path.
  - `sast_tools` — Centurion SAST tool inventory (name, installed, version, install
    hint) = `doctor()` filtered to SAST/SCA/secret/IaC.
- **Pipeline:** SAST is a **separate tool**, NOT auto-run inside `analyze` (keeps
  `analyze` fast). Optional opt-in hook is future work.

## CLI

```
centurion scan <target> [--category sast,sca,secret,iac] [--lang py,js,go,…]
                        [--fail-on {info,low,medium,high,critical}]
                        [--sarif out.sarif] [--format md,html,json,sarif]
                        [--ignore-rule R] [--ignore-path GLOB] [--policy FILE]
centurion scan-tools      # SAST tool inventory (doctor filtered to sast/sca/secret/iac)
```

Exit code from `policy.gate`. `centurion doctor` continues to show ALL tools; the new
SAST tools register in the existing `Registry`.

## Error handling

- Missing tool → skipped, `ToolStatus.installed=False` + hint, recorded in the run's
  `skipped[]`; scan continues and never hard-fails for a missing tool.
- Tool crash / non-zero / timeout → per-`ScanResult.error`, others continue; a scan with
  ≥1 scanner error returns gate exit 2 unless `--allow-scan-errors`.
- SARIF present but unparseable → fall back to `parse_native`; if that fails, record the
  scanner error.
- Artifact unpack failure → clear error, no scan, non-zero.
- Empty tree / no detected languages → zero findings, exit 0, note in report.

## Testing

Mirror the existing `FakeRunner` + canned-output pattern (`tests/`):

- **Per-scanner** (`tests/sast/test_<tool>.py`): feed a canned **SARIF** (and, for
  gitleaks, native JSON) fixture through the scanner's parse path → assert `Finding[]`
  fields (rule_id, severity, file, line, cwe). No real tool required.
- **TargetResolver** (`test_target.py`): source-tree vs each artifact-kind detection; an
  artifact resolves via a **mocked** unpacker; chimera-absent degradation.
- **languages.detect** (`test_languages.py`): per-ecosystem fixtures (a dir with
  `requirements.txt`→python, `package.json`→js, `go.mod`→go, `*.tf`→terraform).
- **Aggregate** (`test_aggregate.py`): `sarif_to_findings` on a multi-result SARIF;
  `merge` dedups two identical findings from different runs; **SARIF round-trip**
  (findings→SARIF→findings is stable); deterministic ordering.
- **Policy** (`test_policy.py`): `fail_on` threshold → exit code; ignore-rule/ignore-path
  filtering; category filter.
- **End-to-end (gated)** (`test_e2e_bandit.py`, `@skipif` bandit absent): run real bandit
  on a vulnerable Python fixture → ≥1 high finding, valid merged SARIF.
- **chimera side**: `test_centurion_adapter.py` (mock `centurion.sast.scan`),
  `sast_scan`/`sast_tools` added to chimera's `test_mcp_surface` pins + dispatch test.

## Review Focus (inputs the tasks' own tests must also cover)

1. **A tool emits SARIF with 0 results** → scanner returns `[]`, not an error.
2. **A tool emits SARIF at a schema version/shape we don't expect** (missing
   `locations`, no `ruleId`) → `sarif_to_findings` tolerates it (best-effort fields), no
   crash.
3. **Two scanners report the same vuln** (e.g. semgrep + njsscan on one JS line) → dedup
   collapses them by fingerprint, severity = max.
4. **A built artifact chimera can't unpack** → clear "unsupported artifact kind" error,
   not a stack trace; source-tree scans unaffected.
5. **Huge finding volume** (thousands) → report/SARIF stream to disk; MCP `sast_scan`
   returns a summary + top-N + file path, never inlines the whole set.

## Cleanup workstream (remove duplicate / unused / legacy)

Applied surgically as each area is touched; remove only what the new layer orphans or
what is genuinely dead:

- **Dedup opengrep↔semgrep** into one `adapters/sast/semgrep.py` (binary resolves
  semgrep→opengrep); delete `adapters/generic/opengrep.py` and repoint references.
- **Secrets single-source:** gitleaks owns secrets; trivy secret mode off by default (no
  double scanner).
- **`mantis` adapter** (guarded/not-live per README): if still inert after this work,
  either wire it as a first-class SARIF/JSON findings source via the new aggregator or
  remove it; do not leave a half-wired adapter.
- Audit `adapters/generic/` + `scripts/` + `report/` for dead code and superseded
  helpers once the `sast/` layer lands; delete unused symbols/imports the change
  orphans. Each removal is justified in its task.

## Success criteria

- `centurion scan <source-tree>` and `centurion scan <artifact>` both produce a merged
  SARIF + MD/HTML/JSON report and a correct policy exit code, using only the tools that
  are installed (missing tools skipped with hints).
- The initial scanner set (above) each parse SARIF→`Finding` correctly (unit-tested with
  fixtures); gitleaks keeps working.
- `findings_to_sarif(sarif_to_findings(x)) ≈ x` (round-trip stable) and cross-tool
  duplicates dedup.
- chimera imports `centurion` as a main dep; `sast_scan`/`sast_tools` MCP tools run the
  platform and return a summary + SARIF path; `test_mcp_surface` pins updated.
- No duplicate SAST engines; no dead/half-wired adapters left behind.
- All new code has focused tests; the suite is green; ruff-F clean.
```
