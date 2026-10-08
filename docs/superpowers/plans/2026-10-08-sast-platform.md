# Centurion Full SAST Platform — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand Centurion into a full static-security platform (SAST + SCA + secrets + IaC) over source trees and built artifacts, with a SARIF-compatible unified findings model, merged SARIF export, policy/CI gating, MCP/CLI/API drivers; make chimera take Centurion as a required dependency and wrap its scan.

**Architecture:** A new `src/centurion/sast/` orchestration layer (target resolve/unpack → language detect → scanner select → run → aggregate → report → policy gate) on top of the existing `Adapter`/`Finding`/`Registry`/`report` machinery. Each tool is a `Scanner(Adapter)` that prefers the tool's native SARIF and falls back to native JSON. chimera requires Centurion (hard dep) and wraps `centurion.sast.scan(...)`; Centurion uses chimera for artifact unpacking only if importable (soft, no cycle).

**Tech Stack:** Python ≥3.11, hatchling, `typer`/`rich`/`mcp` (existing). SARIF 2.1.0 (plain JSON, no new dep). Policy via stdlib `tomllib`/JSON. Tests: pytest + the existing `FakeRunner`.

**Spec:** `docs/superpowers/specs/2026-10-08-sast-platform-design.md`

## Global Constraints

- Wrap, don't reimplement: every tool is an `Adapter`/`Scanner` subclass; missing tool → `ToolStatus(installed=False)` + `install_hint()`, scan **skips it, never hard-fails**.
- Hybrid aggregation: `Finding` is canonical and SARIF-compatible; scanners **prefer native SARIF** (`sarif_to_findings`), fall back to native JSON. Centurion exports one merged **SARIF 2.1.0** log plus the existing MD/HTML/JSON.
- Both source trees AND built artifacts (artifact → unpack to tree, then scan).
- Co-equal drivers: CLI (`centurion scan`), MCP tools, programmatic `centurion.sast.scan(...)`.
- chimera requires `centurion>=0.2` as a **main** dependency (not an extra). Dependency direction: chimera→centurion hard; centurion→chimera (unpacking) soft/import-guarded — no cycle.
- No new heavy deps: SARIF is plain JSON; policy via stdlib `tomllib`/JSON (no YAML).
- Severity maps: `critical/high→error`, `medium→warning`, `low/info→note`; reverse `error→high, warning→medium, note→low, none→info`; a SARIF `properties.security-severity` number overrides (≥9 critical, ≥7 high, ≥4 medium, >0 low, else info).
- Python ≥3.11, hatchling, Apache-2.0. ruff-F clean; every new module has focused tests.

## Review Focus

1. **A tool emits SARIF with 0 results** → scanner returns `[]`, not an error (Task 3).
2. **SARIF missing `locations`/`ruleId`/unexpected shape** → `sarif_to_findings` best-effort, no crash (Task 2).
3. **Two scanners report the same vuln on one line** → `merge` dedups by fingerprint, keeps max severity (Task 6).
4. **A built artifact chimera can't unpack** → clear "unsupported artifact kind" error, source scans unaffected (Task 8).
5. **Thousands of findings** → report/SARIF stream to disk; MCP `sast_scan` returns summary + top-N + path, never inlines all (Task 14 / Task 17).

---

## File Structure

Centurion (new unless noted):
- `src/centurion/models.py` — **modify**: add `Platform.WEB/DESKTOP`, `Category.SCA/SECRET/IAC`, extend `Finding`.
- `src/centurion/sast/__init__.py` — `scan()` API + `ScanReport`.
- `src/centurion/sast/sarif.py` — severity/level maps, `sarif_to_findings`, `findings_to_sarif`.
- `src/centurion/sast/scanner.py` — `Scanner(Adapter)` base + `ScanResult`.
- `src/centurion/sast/languages.py` — `detect(tree)`.
- `src/centurion/sast/registry.py` — `SCANNER_CLASSES`, `select()`.
- `src/centurion/sast/aggregate.py` — `fingerprint()`, `merge()`.
- `src/centurion/sast/policy.py` — `Policy`, `load_policy`, `apply`, `gate`.
- `src/centurion/sast/target.py` — `ResolvedTarget`, `detect_kind`, `Unpacker`, `ChimeraUnpacker`, `TargetResolver`.
- `src/centurion/adapters/sast/{__init__,semgrep,bandit,gosec,njsscan,eslint_security,trivy,grype,checkov}.py`.
- `src/centurion/cli/` — add `scan` + `scan-tools` commands.
- `src/centurion/mcp/server.py` — **modify**: add `sast_scan`, `sast_tools`.
- `src/centurion/registry.py` — **modify**: register SAST scanners in `default_registry`.
- **remove**: `src/centurion/adapters/generic/opengrep.py` (folded into `adapters/sast/semgrep.py`).
- tests: `tests/sast/test_{sarif,scanner,languages,registry,aggregate,policy,target,scan}.py`, `tests/sast/test_adapters.py`, `tests/test_cli_scan.py`, `tests/test_mcp_sast.py`.

chimera:
- `pyproject.toml` — **modify**: add `centurion>=0.2` to main deps.
- `src/chimera/adapters/centurion_adapter.py` — wrap `centurion.sast.scan`.
- `src/chimera/mcp_schemas/sast.py` — `sast_scan`, `sast_tools` Tool schemas; wire into `mcp_schemas/__init__.py`.
- `src/chimera/mcp_handlers/analysis.py` — **modify**: dispatch `sast_scan`/`sast_tools`.
- tests: `tests/unit/test_centurion_adapter.py`; **modify** `tests/unit/test_mcp_surface.py` pins.

---

## Task 1: Data-model extensions

**Files:** Modify `src/centurion/models.py`. Test `tests/sast/test_models_sast.py`.

**Produces:** `Platform.WEB="web"`, `Platform.DESKTOP="desktop"`; `Category.SCA="sca"`, `Category.SECRET="secret"`, `Category.IAC="iac"`; `Finding` fields `rule_id, category, file, line, end_line, cwe:list, references:list, fingerprint, ecosystem` (all optional, defaulted).

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_models_sast.py
from centurion.models import Platform, Category, Finding

def test_new_enums():
    assert Platform.WEB.value == "web" and Platform.DESKTOP.value == "desktop"
    assert Category.SCA.value == "sca" and Category.SECRET.value == "secret" and Category.IAC.value == "iac"

def test_finding_sarif_fields_default():
    f = Finding(id="x", title="t", severity="high", tool="semgrep")
    d = f.to_dict()
    assert d["rule_id"] is None and d["cwe"] == [] and d["references"] == []
    assert d["file"] is None and d["line"] is None and d["fingerprint"] is None

def test_finding_sarif_fields_roundtrip():
    f = Finding(id="x", title="t", severity="high", tool="semgrep",
                rule_id="py.sqli", category="static", file="a.py", line=12,
                cwe=["CWE-89"], references=["https://x"], fingerprint="abc", ecosystem="pypi")
    assert f.to_dict()["rule_id"] == "py.sqli" and f.to_dict()["cwe"] == ["CWE-89"]
```
- [ ] **Step 2: Run — expect FAIL** (`pytest tests/sast/test_models_sast.py -v` → AttributeError/TypeError).
- [ ] **Step 3: Implement** — add the enum members; add the fields to `Finding` after `masvs_refs`:
```python
    rule_id: str | None = None
    category: str | None = None
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    cwe: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    fingerprint: str | None = None
    ecosystem: str | None = None
```
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): extend models with WEB/DESKTOP, SCA/SECRET/IAC, SARIF-compatible Finding fields`.

## Task 2: SARIF conversion

**Files:** Create `src/centurion/sast/__init__.py` (empty for now), `src/centurion/sast/sarif.py`. Test `tests/sast/test_sarif.py`.

**Consumes:** `Finding` (Task 1).
**Produces:** `SEV_TO_LEVEL`, `LEVEL_TO_SEV`, `security_severity_to_sev(num)->str`, `sarif_to_findings(sarif: dict, tool: str) -> list[Finding]`, `findings_to_sarif(findings: list[Finding]) -> dict`.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_sarif.py
from centurion.sast.sarif import sarif_to_findings, findings_to_sarif
from centurion.models import Finding

SARIF = {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep","rules":[
  {"id":"py.sqli","name":"SQL injection","properties":{"cwe":["CWE-89"],"security-severity":"8.5"}}]}},
  "results":[{"ruleId":"py.sqli","level":"warning","message":{"text":"tainted sql"},
    "locations":[{"physicalLocation":{"artifactLocation":{"uri":"app/db.py"},"region":{"startLine":12}}}],
    "partialFingerprints":{"primaryLocationLineHash":"deadbeef"}}]}]}

def test_sarif_to_findings_maps_fields():
    fs = sarif_to_findings(SARIF, "semgrep")
    assert len(fs) == 1
    f = fs[0]
    assert f.rule_id == "py.sqli" and f.tool == "semgrep" and f.file == "app/db.py" and f.line == 12
    assert f.severity == "high"            # security-severity 8.5 -> high
    assert f.cwe == ["CWE-89"] and f.fingerprint == "deadbeef"

def test_sarif_tolerates_missing_fields():
    fs = sarif_to_findings({"runs":[{"results":[{"message":{"text":"x"}}]}]}, "t")
    assert len(fs) == 1 and fs[0].file is None and fs[0].rule_id is None

def test_zero_results():
    assert sarif_to_findings({"runs":[{"results":[]}]}, "t") == []

def test_roundtrip_stable():
    fs = sarif_to_findings(SARIF, "semgrep")
    again = sarif_to_findings(findings_to_sarif(fs), "semgrep")
    assert [(f.rule_id, f.file, f.line, f.severity) for f in again] == \
           [(f.rule_id, f.file, f.line, f.severity) for f in fs]
```
- [ ] **Step 2: Run — expect FAIL** (module missing).
- [ ] **Step 3: Implement `sarif.py`.** Maps per Global Constraints. `sarif_to_findings`: iterate `runs[].results[]`; pull rule metadata from `run.tool.driver.rules` (by `ruleId`) for cwe/security-severity/name; severity = `security_severity_to_sev` if a numeric `security-severity` is present (on result `properties` or the rule), else `LEVEL_TO_SEV[result.level or "warning"]`; file/line from `locations[0].physicalLocation`; fingerprint from `partialFingerprints` (first value) or `fingerprints`. Build `Finding(id=f"{tool}:{rule_id}:{file}:{line}", title=rule_name or rule_id or message, severity, tool, detail=message.text, location=f"{file}:{line}", rule_id, file, line, cwe, references=[helpUri] if present, fingerprint)`. `findings_to_sarif`: one run per distinct tool; `rules` deduped by `rule_id`; each result `{ruleId, level:SEV_TO_LEVEL[sev], message:{text:detail}, locations:[physicalLocation...], properties:{security-severity,...}, partialFingerprints:{centurion:fingerprint}}`; top-level `{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[...]}`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): SARIF 2.1.0 <-> Finding conversion (sarif_to_findings/findings_to_sarif)`.

## Task 3: Scanner base + ScanResult

**Files:** Create `src/centurion/sast/scanner.py`. Test `tests/sast/test_scanner.py`.

**Consumes:** `Adapter` (adapters/base), `Finding`, `sarif_to_findings` (Task 2), `FakeRunner`.
**Produces:** `@dataclass ScanResult(scanner:str, findings:list[Finding], skipped:bool=False, error:str|None=None, duration_s:float=0.0)`; `class Scanner(Adapter)` with class attrs `languages: tuple[str,...]=("*",)`, `supports_sarif: bool=True`, `sast_category: Category=Category.STATIC`, methods `scan_command(tree:str, out:str)->list[str]` (abstract), `parse_native(text:str)->list[Finding]` (default `[]`), `scan(tree:str, workdir:str)->ScanResult`.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_scanner.py
from pathlib import Path
from centurion.sast.scanner import Scanner, ScanResult
from centurion.models import Category
from centurion.process import FakeRunner

SARIF_JSON = '{"runs":[{"results":[{"ruleId":"R1","level":"error","message":{"text":"bad"},' \
             '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]}]}]}'

class _Dummy(Scanner):
    name = "dummy"; binary = "dummy"; languages = ("python",)
    def install_hint(self): return "install dummy"
    def scan_command(self, tree, out): return ["dummy", tree, "-o", out]

def test_scan_reads_sarif(tmp_path):
    fake = FakeRunner(); fake.register("dummy", returncode=1)  # non-zero is fine for SAST tools
    s = _Dummy(fake)
    # scan writes SARIF to `out`; emulate by making scan_command's -o path pre-populated:
    out = tmp_path / "out.sarif"; out.write_text(SARIF_JSON)
    res = s.scan(str(tmp_path), str(tmp_path), _out=str(out))
    assert isinstance(res, ScanResult) and res.error is None and res.skipped is False
    assert len(res.findings) == 1 and res.findings[0].rule_id == "R1" and res.findings[0].tool == "dummy"

def test_scan_zero_results_not_error(tmp_path):
    out = tmp_path / "out.sarif"; out.write_text('{"runs":[{"results":[]}]}')
    res = _Dummy(FakeRunner()).scan(str(tmp_path), str(tmp_path), _out=str(out))
    assert res.findings == [] and res.error is None

def test_scan_tool_crash_records_error(tmp_path):
    fake = FakeRunner(); fake.register("dummy", returncode=2, stderr="boom")
    res = _Dummy(fake).scan(str(tmp_path), str(tmp_path))  # no SARIF written -> error
    assert res.error is not None and res.findings == []
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** `scan(tree, workdir, _out=None)`: `out = _out or <workdir>/<name>.sarif`; run `self.runner.run(self.scan_command(tree, out), timeout=1800)`; wrap in try/except → `ScanResult(error=...)`. After run: if `supports_sarif`: read `out` (if missing/empty → if returncode!=0 and no output: `error`; else `findings=[]`), `json.loads` → `sarif_to_findings(data, self.name)`; on `JSONDecodeError` fall back to `parse_native(result.stdout)` if overridden else record error. If not `supports_sarif`: `parse_native(result.stdout or Path(out).read_text())`. Return `ScanResult(scanner=self.name, findings=..., duration_s=...)`. (Do **not** treat non-zero returncode as failure — SAST tools exit non-zero when findings exist.)
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): Scanner base + ScanResult (SARIF-preferred, native fallback, skip-not-fail)`.

## Task 4: Language detection

**Files:** Create `src/centurion/sast/languages.py`. Test `tests/sast/test_languages.py`.

**Produces:** `detect(tree: str | Path) -> set[str]` returning languages/ecosystems from file extensions and manifest/lockfile names.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_languages.py
from centurion.sast.languages import detect

def test_detect_python(tmp_path):
    (tmp_path/"app.py").write_text("x=1"); (tmp_path/"requirements.txt").write_text("flask")
    assert "python" in detect(tmp_path)

def test_detect_js_go_tf(tmp_path):
    (tmp_path/"pkg").mkdir(); (tmp_path/"pkg/index.ts").write_text("let x=1")
    (tmp_path/"go.mod").write_text("module m"); (tmp_path/"main.tf").write_text("resource {}")
    langs = detect(tmp_path)
    assert {"typescript","go","terraform"} <= langs

def test_empty_tree(tmp_path):
    assert detect(tmp_path) == set()
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** Walk the tree (skip `.git`, `node_modules`, `.venv`, `vendor`, `dist`, `build`). `EXT = {".py":"python",".js":"javascript",".jsx":"javascript",".mjs":"javascript",".cjs":"javascript",".ts":"typescript",".tsx":"typescript",".go":"go",".rb":"ruby",".java":"java",".php":"php",".cs":"csharp",".rs":"rust",".tf":"terraform",".yaml":"yaml",".yml":"yaml",".json":"json",".c":"c",".h":"c",".cpp":"cpp"}`; `MANIFEST = {"requirements.txt":"python","pyproject.toml":"python","setup.py":"python","Pipfile":"python","package.json":"javascript","go.mod":"go","go.sum":"go","pom.xml":"java","build.gradle":"java","Gemfile":"ruby","composer.json":"php","Cargo.toml":"rust","Dockerfile":"docker"}`; add `"kubernetes"` if a `.yaml`/`.yml` contains `apiVersion:` + `kind:` (cheap read of first 2KB). Cap walk at a sane file count for huge trees. Return the set.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): language/ecosystem detection for scanner selection`.

## Task 5: Aggregation (fingerprint + merge)

**Files:** Create `src/centurion/sast/aggregate.py`. Test `tests/sast/test_aggregate.py`.

**Consumes:** `Finding`, `ScanResult` (Task 3).
**Produces:** `fingerprint(f: Finding) -> str`, `merge(results: list[ScanResult]) -> list[Finding]`.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_aggregate.py
from centurion.sast.aggregate import merge, fingerprint
from centurion.sast.scanner import ScanResult
from centurion.models import Finding

def F(**kw): d=dict(id="i",title="t",severity="low",tool="a"); d.update(kw); return Finding(**d)

def test_dedup_same_finding_from_two_tools_keeps_max_severity():
    a = F(tool="semgrep", severity="medium", rule_id="xss", file="a.js", line=5)
    b = F(tool="njsscan", severity="high", rule_id="xss", file="a.js", line=5)
    out = merge([ScanResult("semgrep",[a]), ScanResult("njsscan",[b])])
    # same file+line+rule collapses; max severity wins
    assert len(out) == 1 and out[0].severity == "high"

def test_distinct_findings_kept_and_sorted():
    a = F(severity="low", rule_id="r1", file="a", line=1)
    b = F(severity="critical", rule_id="r2", file="a", line=2)
    out = merge([ScanResult("a",[a,b])])
    assert [f.severity for f in out] == ["critical","low"]  # severity desc

def test_fingerprint_stable():
    f = F(tool="t", rule_id="r", file="a", line=3)
    assert fingerprint(f) == fingerprint(F(tool="t", rule_id="r", file="a", line=3))
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** `SEV_ORDER = {"critical":4,"high":3,"medium":2,"low":1,"info":0}`. `fingerprint(f)`: if `f.fingerprint` return it; else `sha1("|".join([f.rule_id or "", f.file or "", str(f.line or ""), (f.detail or "")[:80]]).encode()).hexdigest()[:16]`. **Dedup key** for merge = `(f.rule_id or f.title, f.file, f.line)` (tool-independent, so cross-tool dups collapse); keep the finding with max `SEV_ORDER`, and record the contributing tools on the kept finding's `references` is NOT needed — just keep max. Sort by `(-SEV_ORDER[sev], file or "", line or 0, rule_id or "")`. Set `f.fingerprint = fingerprint(f)` on each kept finding.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): findings aggregation — fingerprint + cross-tool dedup + deterministic order`.

## Task 6: Policy / gating

**Files:** Create `src/centurion/sast/policy.py`. Test `tests/sast/test_policy.py`.

**Consumes:** `Finding`, `Severity`, `Category`.
**Produces:** `@dataclass Policy(fail_on:str="critical", ignore_rules:set[str]=…, ignore_paths:list[str]=…, categories:set[str]|None=None)`; `load_policy(path:str|None=None, **overrides)->Policy`; `apply(findings, policy)->list[Finding]`; `gate(findings, policy, scan_errored:bool=False)->int`.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_policy.py
from centurion.sast.policy import Policy, apply, gate, load_policy
from centurion.models import Finding
def F(sev, rule="r", file="a.py"): return Finding(id="i",title="t",severity=sev,tool="x",rule_id=rule,file=file)

def test_gate_threshold():
    assert gate([F("low")], Policy(fail_on="high")) == 0
    assert gate([F("high")], Policy(fail_on="high")) == 1
    assert gate([F("critical")], Policy(fail_on="high")) == 1

def test_gate_scan_error():
    assert gate([], Policy(fail_on="critical"), scan_errored=True) == 2

def test_apply_ignores_rule_and_path():
    fs = [F("high", rule="skipme"), F("high", file="tests/x.py"), F("high")]
    out = apply(fs, Policy(ignore_rules={"skipme"}, ignore_paths=["tests/*"]))
    assert len(out) == 1

def test_load_policy_overrides():
    p = load_policy(None, fail_on="medium")
    assert p.fail_on == "medium"
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** `Policy` dataclass (defaults: `fail_on="critical"`, `ignore_rules=set()`, `ignore_paths=[]`, `categories=None`). `load_policy`: if `path` ends `.toml` → `tomllib.load`; `.json` → `json.load`; merge `overrides` (non-None wins); unknown file → defaults. `apply`: drop findings whose `rule_id` in `ignore_rules` or whose `file` matches any `fnmatch(ignore_paths)` or whose `category` not in `categories` (when set). `gate`: `if scan_errored: return 2`; `order={"info":0,"low":1,"medium":2,"high":3,"critical":4}`; `return 1 if any(order[f.severity] >= order[policy.fail_on] for f in findings) else 0`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): policy load + severity/rule/path gating with CI exit codes`.

## Task 7: Scanner registry / selection

**Files:** Create `src/centurion/sast/registry.py`. Test `tests/sast/test_sast_registry.py`.

**Consumes:** the scanner classes (Task 10–12 — import lazily inside the function to avoid a cycle; for the test, inject a fake list), `Category`, `ToolStatus`.
**Produces:** `SCANNER_CLASSES: list[type[Scanner]]`; `select(languages:set[str], categories:set[str]|None=None, runner=None, classes=None) -> tuple[list[Scanner], list[ToolStatus]]` → (installed scanners whose `languages` intersect the tree's languages (or `"*"`) and whose `sast_category` is in `categories`, the skipped `ToolStatus` for matching-but-not-installed tools).

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_sast_registry.py
from centurion.sast.registry import select
from centurion.sast.scanner import Scanner
from centurion.models import Category
from centurion.process import FakeRunner

class _Py(Scanner):
    name="pyscan"; binary="pyscan"; languages=("python",); sast_category=Category.STATIC
    def install_hint(self): return "install pyscan"
    def scan_command(self, t, o): return ["pyscan"]
class _Go(Scanner):
    name="goscan"; binary="goscan"; languages=("go",); sast_category=Category.STATIC
    def install_hint(self): return "install goscan"
    def scan_command(self, t, o): return ["goscan"]

def test_select_by_language_and_install_status():
    fake = FakeRunner(); fake.register("pyscan --version", stdout="1.0")  # only pyscan "installed"
    chosen, skipped = select({"python","go"}, None, runner=fake, classes=[_Py,_Go])
    assert [s.name for s in chosen] == ["pyscan"]
    assert any(t.name=="goscan" and not t.installed for t in skipped)
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** `SCANNER_CLASSES` imports the 8+ scanner classes (lazy module import inside a helper to dodge import cycles). `select`: `classes = classes or SCANNER_CLASSES`; for each cls: instantiate with `runner`; skip if `languages` disjoint from the tree langs (unless `"*"` in its languages); skip if `categories` set and `sast_category.value` not in it; `st = sc.detect()`; if `st.installed` append to chosen else append `st` to skipped. Return `(chosen, skipped)`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): scanner selection by language x category, skip-with-hint for missing tools`.

## Task 8: Target resolver + unpacker

**Files:** Create `src/centurion/sast/target.py`. Test `tests/sast/test_target.py`.

**Consumes:** nothing new.
**Produces:** `detect_kind(path:str)->str` (`source|apk|ipa|pe|elf|macho|electron|tauri|dotnet|python|jar|archive`); `@dataclass ResolvedTarget(kind:str, tree:str, meta:dict, cleanup)`; `class Unpacker(Protocol): def unpack(self, path:str, kind:str, dest:str)->str|None`; `class ChimeraUnpacker` (import-guarded; maps kind→chimera extractor, returns recovered-tree path or None); `class TargetResolver: def resolve(self, target:str, unpacker:Unpacker|None=None)->ResolvedTarget`.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_target.py
from centurion.sast.target import TargetResolver, detect_kind

def test_detect_source_dir(tmp_path):
    (tmp_path/"a.py").write_text("x=1")
    assert detect_kind(str(tmp_path)) == "source"

def test_detect_apk(tmp_path):
    p = tmp_path/"app.apk"; p.write_bytes(b"PK\x03\x04rest")
    assert detect_kind(str(p)) == "apk"

def test_resolve_source_passthrough(tmp_path):
    (tmp_path/"a.py").write_text("x=1")
    rt = TargetResolver().resolve(str(tmp_path))
    assert rt.kind == "source" and rt.tree == str(tmp_path)

def test_resolve_artifact_uses_unpacker(tmp_path):
    art = tmp_path/"app.apk"; art.write_bytes(b"PK\x03\x04")
    out = tmp_path/"unpacked"; out.mkdir()
    class FakeUnpacker:
        def unpack(self, path, kind, dest): return str(out)
    rt = TargetResolver().resolve(str(art), unpacker=FakeUnpacker())
    assert rt.kind == "apk" and rt.tree == str(out)

def test_resolve_unsupported_artifact_errors(tmp_path):
    art = tmp_path/"x.apk"; art.write_bytes(b"PK\x03\x04")
    class NoneUnpacker:
        def unpack(self, path, kind, dest): return None
    import pytest
    with pytest.raises(ValueError):
        TargetResolver().resolve(str(art), unpacker=NoneUnpacker())
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** `detect_kind`: dir → `source`; by extension (`.apk→apk, .ipa→ipa, .jar→jar, .asar→electron, .exe/.dll→pe, .dylib→macho`) then by magic (`PK\x03\x04`+`.apk/.ipa`→apk/ipa; `MZ`→pe; `\x7fELF`→elf; `\xca\xfe\xba\xbe`/`\xcf\xfa\xed\xfe`→macho; detect Tauri/dotnet via chimera later — default `archive`). `ChimeraUnpacker.unpack`: `try: import chimera...` map `apk`→(apktool/jadx via centurion's own android adapters OR chimera), `electron/pe`(node)→`chimera.unpacking.nodejs.extract_node_js`, `tauri`→`chimera.unpacking.tauri.extract_tauri`, `dotnet`→`chimera.unpacking.dotnet_bundle`, `python`→`chimera.unpacking.pyinstaller`; return the recovered dir or None; on ImportError return None. `TargetResolver.resolve`: `kind=detect_kind(target)`; if `source` → `ResolvedTarget("source", target, {}, None)`; else `unpacker = unpacker or ChimeraUnpacker()`; `tree = unpacker.unpack(target, kind, <tempdir>)`; if None → `raise ValueError(f"unsupported/failed artifact unpack: {kind}")`; return `ResolvedTarget(kind, tree, {...}, cleanup=lambda: shutil.rmtree(tempdir, ignore_errors=True))`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): target resolver + chimera-backed (import-guarded) artifact unpacker`.

## Task 9: `scan()` orchestration API

**Files:** Fill `src/centurion/sast/__init__.py`. Test `tests/sast/test_scan.py`.

**Consumes:** Tasks 2–8.
**Produces:** `@dataclass ScanReport(findings:list[Finding], skipped:list[ToolStatus], errors:list[str], languages:set[str], sarif_path:str|None, report:dict, exit_code:int)`; `scan(target:str, *, categories:set[str]|None=None, policy=None, out_dir:str|None=None, runner=None, unpacker=None, scanners=None) -> ScanReport`.

- [ ] **Step 1: Write the failing test**
```python
# tests/sast/test_scan.py
from centurion.sast import scan
from centurion.sast.scanner import Scanner
from centurion.models import Category, Finding
from centurion.process import FakeRunner

class _PyOK(Scanner):
    name="pyok"; binary="pyok"; languages=("python",)
    def install_hint(self): return "x"
    def scan_command(self, t, o): return ["pyok"]
    def scan(self, tree, workdir, _out=None):
        from centurion.sast.scanner import ScanResult
        return ScanResult("pyok", [Finding(id="i",title="t",severity="high",tool="pyok",rule_id="r",file="a.py",line=1)])
    def detect(self):
        from centurion.models import ToolStatus
        return ToolStatus(name="pyok", installed=True)

def test_scan_source_tree(tmp_path):
    (tmp_path/"a.py").write_text("x=1")
    out = tmp_path/"o"; 
    rep = scan(str(tmp_path), out_dir=str(out), scanners=[_PyOK])
    assert len(rep.findings) == 1 and rep.exit_code in (0,1)
    assert rep.sarif_path and (out/"findings.sarif").exists()
    assert "python" in rep.languages
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement `scan()`.** Import the submodules to avoid the `policy` param clashing with the module: `from centurion.sast import languages as _lang, registry as _reg, aggregate as _agg, policy as _pol, sarif as _sarif; from centurion.sast.target import TargetResolver; from centurion.sast.policy import Policy`. Then: `rt = TargetResolver().resolve(target, unpacker)`; `langs = _lang.detect(rt.tree)`; `chosen, skipped = _reg.select(langs, categories, runner, classes=scanners)`; `results = [sc.scan(rt.tree, out_dir or tempdir) for sc in chosen]`; `errors = [r.error for r in results if r.error]`; `findings = _agg.merge(results)`; `pol = policy or Policy()`; `findings = _pol.apply(findings, pol)`; write SARIF (`_sarif.findings_to_sarif(findings)` → `<out_dir>/findings.sarif`) and JSON (`[f.to_dict() for f in findings]`); build a `report` dict (reuse the existing `report/` model shape: `{"findings":[...], "skipped":[...], "summary":{by severity/category}}`); `exit_code = _pol.gate(findings, pol, scan_errored=bool(errors))`; `rt.cleanup and rt.cleanup()` in a `finally`; return `ScanReport(...)`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): scan() orchestration — resolve->detect->select->run->aggregate->gate`.

## Task 10: SARIF scanner adapters — semgrep (fold opengrep), bandit, gosec

**Files:** Create `src/centurion/adapters/sast/__init__.py`, `semgrep.py`, `bandit.py`, `gosec.py`. **Remove** `src/centurion/adapters/generic/opengrep.py` (and repoint any import/registry ref to the new `semgrep`). Test `tests/sast/test_adapters_static.py`.

**Consumes:** `Scanner` (Task 3).
**Produces:** `SemgrepScanner`, `BanditScanner`, `GosecScanner`. Each: `name`, `binary`, `languages`, `sast_category=Category.STATIC`, `install_hint()`, `scan_command()` producing SARIF.

Per-scanner spec (all `supports_sarif=True`, `platform=Platform.GENERIC`):
- **SemgrepScanner**: `name="semgrep"`; binary resolves `semgrep`→`opengrep` (override `detect()`/`version_command` to try both, or set `binary="semgrep"` and in `scan_command` prefer whichever `self.runner.which` finds); `languages=("*",)`; `scan_command(t,o)=[bin,"scan","--sarif","--output",o,t]`; `install_hint()="pip install semgrep (or opengrep)"`.
- **BanditScanner**: `name="bandit"`, `binary="bandit"`, `languages=("python",)`; `scan_command=["bandit","-r",t,"-f","sarif","-o",o]`; hint `pip install bandit`.
- **GosecScanner**: `name="gosec"`, `binary="gosec"`, `languages=("go",)`; `scan_command=["gosec","-fmt","sarif","-out",o,"./..."]` run with `cwd`=tree (note: gosec scans the module in cwd; the Scanner.scan passes tree as arg — for gosec, encode `t` by using `[...,"-no-fail","-fmt","sarif","-out",o, t+"/..."]`); hint `go install github.com/securego/gosec/v2/cmd/gosec@latest`.

- [ ] **Step 1: Write the failing test** (metadata + command + SARIF-parse via FakeRunner, one per scanner; reuse the SARIF fixture from Task 2):
```python
# tests/sast/test_adapters_static.py
from centurion.adapters.sast.semgrep import SemgrepScanner
from centurion.adapters.sast.bandit import BanditScanner
from centurion.adapters.sast.gosec import GosecScanner
from centurion.models import Category

def test_metadata():
    assert BanditScanner().languages == ("python",)
    assert GosecScanner().languages == ("go",)
    assert SemgrepScanner().languages == ("*",)
    for S in (SemgrepScanner, BanditScanner, GosecScanner):
        assert S().sast_category == Category.STATIC and S().install_hint()

def test_commands():
    assert BanditScanner().scan_command("/src","/o.sarif")[:3] == ["bandit","-r","/src"]
    assert "sarif" in " ".join(GosecScanner().scan_command("/src","/o.sarif"))
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement** the three modules + `adapters/sast/__init__.py` exporting them; delete `adapters/generic/opengrep.py`; `grep -rn opengrep src/ tests/` and repoint (registry, any import) to `SemgrepScanner`.
- [ ] **Step 4: Run — expect PASS** (plus `grep -rn opengrep src/` returns nothing).
- [ ] **Step 5: Commit** `feat(sast): semgrep(+opengrep fold)/bandit/gosec scanners; remove duplicate opengrep adapter`.

## Task 11: SARIF scanner adapters — njsscan, eslint-security, checkov

**Files:** Create `adapters/sast/njsscan.py`, `eslint_security.py`, `checkov.py`. Test add to `tests/sast/test_adapters_static.py`.

**Produces:** `NjsscanScanner` (`name="njsscan"`, `languages=("javascript","typescript")`, `scan_command=["njsscan","--sarif","-o",o,t]`, hint `pip install njsscan`), `EslintSecurityScanner` (`name="eslint-security"`, `languages=("javascript","typescript")`, `scan_command=["eslint",t,"-f","@microsoft/sarif","-o",o]`, hint `npm i -g eslint eslint-plugin-security @microsoft/eslint-formatter-sarif`), `CheckovScanner` (`name="checkov"`, `sast_category=Category.IAC`, `languages=("terraform","kubernetes","docker","yaml")`, `scan_command=["checkov","-d",t,"-o","sarif","--output-file-path",o]`, hint `pip install checkov`).

- [ ] **Step 1: Write the failing test** (metadata + command asserts, mirror Task 10).
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement** the three modules; export from `adapters/sast/__init__.py`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): njsscan/eslint-security/checkov scanners`.

## Task 12: SCA + secret adapters — trivy, grype (gitleaks reused)

**Files:** Create `adapters/sast/trivy.py`, `grype.py`. Test add to `tests/sast/test_adapters_static.py`.

**Produces:** `TrivyScanner` (`name="trivy"`, `sast_category=Category.SCA`, `languages=("*",)`, `scan_command=["trivy","fs","--quiet","--format","sarif","--scanners","vuln,misconfig","--output",o,t]` — secrets OFF by default to avoid double-reporting with gitleaks; hint `install trivy`), `GrypeScanner` (`name="grype"`, `sast_category=Category.SCA`, `languages=("*",)`, `scan_command=["grype","dir:"+t,"-o","sarif","--file",o]`, hint `install grype`). Keep the existing `adapters/generic/gitleaks.py` (secret source) — add a one-line note; do not duplicate secret scanning in trivy.

- [ ] **Step 1: Write the failing test** (metadata: `TrivyScanner().sast_category==Category.SCA`, command contains `sarif` and NOT `secret`; `GrypeScanner` metadata).
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement** both modules; export.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): trivy (SCA+IaC) and grype (SCA) scanners; secrets stay single-sourced via gitleaks`.

## Task 13: Wire SCANNER_CLASSES + register in default_registry

**Files:** Modify `src/centurion/sast/registry.py` (`SCANNER_CLASSES` = the real list incl. the existing `GitleaksAdapter` wrapped/listed), `src/centurion/registry.py` (`default_registry` also registers the SAST scanners so `doctor` shows them). Test `tests/sast/test_sast_registry.py` (extend) + `tests/test_registry_sast.py`.

- [ ] **Step 1: Write the failing test**
```python
# tests/test_registry_sast.py
from centurion.registry import default_registry
def test_doctor_includes_sast_tools():
    names = {s.name for s in default_registry().doctor()}
    assert {"semgrep","bandit","gosec","trivy","checkov","grype","njsscan"} <= names
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement** — set `SCANNER_CLASSES`; add the scanner instances to `default_registry`.
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): register SAST scanners in SCANNER_CLASSES + doctor`.

## Task 14: CLI — `centurion scan` + `centurion scan-tools`

**Files:** Add a `scan` command module under `src/centurion/cli/` (follow the existing CLI structure/registration). Test `tests/test_cli_scan.py`.

**Consumes:** `centurion.sast.scan`, `default_registry`.
**Produces:** `centurion scan <target> [--category ...] [--fail-on ...] [--sarif PATH] [--format md,html,json,sarif] [--ignore-rule R] [--ignore-path G] [--policy FILE]` (exit = `ScanReport.exit_code`), `centurion scan-tools` (doctor filtered to static/sca/secret/iac).

- [ ] **Step 1: Write the failing test** (use typer's CliRunner, monkeypatch `centurion.sast.scan` to return a canned `ScanReport`; assert exit code + that a summary line is printed; `scan-tools` lists tool names).
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement** the commands (parse `--category` CSV→set, build `Policy` from flags/`--policy`, call `scan`, render a rich summary table + write requested formats, `raise typer.Exit(rep.exit_code)`).
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): centurion scan + scan-tools CLI`.

## Task 15: MCP — `sast_scan` + `sast_tools` (Centurion server)

**Files:** Modify `src/centurion/mcp/server.py`. Test `tests/test_mcp_sast.py`.

**Produces:** `@mcp.tool() sast_scan(target, categories=None, fail_on=None, out_dir=None) -> dict` (returns `{summary:{by severity/category}, top: [first 50 findings], sarif_path, skipped, errors, exit_code}` — never inlines all findings), `@mcp.tool() sast_tools() -> list[dict]` (doctor filtered to static/sca/secret/iac).

- [ ] **Step 1: Write the failing test** (monkeypatch `centurion.sast.scan`; assert `sast_scan` returns a dict with `summary`+`sarif_path`+capped `top`; `sast_tools` returns tool dicts).
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement** both tools (call `centurion.sast.scan`, build the capped summary dict).
- [ ] **Step 4: Run — expect PASS**.
- [ ] **Step 5: Commit** `feat(sast): sast_scan + sast_tools MCP tools (summary + top-N + SARIF path)`.

## Task 16: Cleanup — dead code / legacy / mantis audit

**Files:** `src/centurion/adapters/generic/mantis.py` (+ its test), and a repo-wide dead-code sweep.

- [ ] **Step 1:** `grep -rn "opengrep" src/ tests/` → must be empty (Task 10 removed it); fix any stragglers.
- [ ] **Step 2:** Decide `mantis`: it ingests mantis-sast JSON. Wire it through the new aggregator as a findings source **iff** it already produces parseable JSON in tests; otherwise remove `mantis.py` + its registry entry + test (record the reason in the commit). Do not leave it half-wired.
- [ ] **Step 3:** Run `ruff check --select F src/` and `python -m pyflakes src/centurion` (or `ruff --select F`) → remove unused imports/vars the new layer orphaned; delete any now-unreferenced helper in `adapters/generic/` or `report/` (confirm no references via grep before deleting).
- [ ] **Step 4:** Full test suite green: `pytest -q`.
- [ ] **Step 5: Commit** `refactor(sast): remove duplicate/legacy adapters + dead code (opengrep folded, mantis <wired|removed>)`.

## Task 17: chimera integration — dependency + adapter + MCP tools

**Files (chimera repo):** Modify `pyproject.toml` (add `centurion>=0.2` to main deps); create `src/chimera/adapters/centurion_adapter.py`; create `src/chimera/mcp_schemas/sast.py` + wire into `mcp_schemas/__init__.py` (`from . import sast`, add to `_MODULES`); modify `src/chimera/mcp_handlers/analysis.py` (dispatch `sast_scan`/`sast_tools`); modify `tests/unit/test_mcp_surface.py` (pin the two tools); create `tests/unit/test_centurion_adapter.py`.

**Consumes:** `centurion.sast.scan`, `centurion.registry.default_registry`.
**Produces:** `chimera.adapters.centurion_adapter.sast_scan(path, categories=None, fail_on=None, out_dir=None)->dict` and `sast_tools()->list[dict]` (thin wrappers around centurion); MCP tools `sast_scan`, `sast_tools`.

- [ ] **Step 1: Write the failing test**
```python
# chimera: tests/unit/test_centurion_adapter.py
def test_sast_scan_wraps_centurion(monkeypatch, tmp_path):
    import chimera.adapters.centurion_adapter as ca
    class Rep:  # minimal ScanReport stand-in
        findings=[]; skipped=[]; errors=[]; languages=set(); sarif_path="x.sarif"
        report={"summary":{}}; exit_code=0
    monkeypatch.setattr(ca, "_centurion_scan", lambda *a, **k: Rep())
    out = ca.sast_scan(str(tmp_path))
    assert out["sarif_path"] == "x.sarif" and "summary" in out
```
- [ ] **Step 2: Run — expect FAIL**.
- [ ] **Step 3: Implement.** `centurion_adapter.py`: `from centurion.sast import scan as _centurion_scan`; `sast_scan(...)` calls it, builds `{summary, top(50), sarif_path, skipped, errors, exit_code}`; `sast_tools()` = `[s.to_dict() for s in default_registry().doctor() if s.category in {"static","sca","secret","iac"}]`. Add the two `Tool(...)` schemas in `mcp_schemas/sast.py` (`sast_scan`: `path` required, `categories`/`fail_on`/`out_dir` optional; `sast_tools`: no args). Wire `sast` into `mcp_schemas/__init__.py`. Add dispatch in `analysis.py` (`if name=="sast_scan": ... if name=="sast_tools": ...`). Pin both in `test_mcp_surface.EXPECTED_TOOLS`. Add `centurion>=0.2` to chimera `[project.dependencies]`.
- [ ] **Step 4: Run — expect PASS** (`pytest tests/unit/test_centurion_adapter.py tests/unit/test_mcp_surface.py -k "sast or well_formed or unexpected or duplicate" -q`).
- [ ] **Step 5: Commit (chimera repo)** `feat(sast): require centurion + wrap its scan as sast_scan/sast_tools MCP tools`.

## Task 18: End-to-end gated test + docs

**Files (centurion):** `tests/sast/test_e2e_bandit.py`; update `README.md` (new `scan`/`scan-tools` + MCP tools + SAST tool table).

- [ ] **Step 1: Write the gated e2e test**
```python
# tests/sast/test_e2e_bandit.py
import shutil, pytest
from centurion.sast import scan
@pytest.mark.skipif(shutil.which("bandit") is None, reason="bandit not installed")
def test_bandit_finds_vuln(tmp_path):
    (tmp_path/"v.py").write_text("import subprocess\nsubprocess.call(cmd, shell=True)\n")
    rep = scan(str(tmp_path), categories={"static"})
    assert any(f.tool=="bandit" for f in rep.findings)
    assert rep.sarif_path
```
- [ ] **Step 2: Run** (passes if bandit present, else skips).
- [ ] **Step 3: Update README** (SAST section: `scan`/`scan-tools`, the tool table, MCP `sast_scan`/`sast_tools`, policy file).
- [ ] **Step 4: Full suite** `pytest -q` (centurion) green; ruff-F clean.
- [ ] **Step 5: Commit** `test+docs(sast): gated bandit e2e + README SAST section`.

---

## Notes for the executor
- Follow the existing adapter test style (metadata + command + parse via `FakeRunner`); SARIF parse tests need **no real tool**.
- Keep each scanner adapter tiny — the `Scanner` base does the SARIF read; adapters only set attrs + `scan_command` + `install_hint`.
- Centurion commits on its own branch; chimera Task 17 commits in the chimera repo on its own branch. Author `TyrusRC`, no attribution trailer, no forbidden identifiers.
- Publish of centurion (for chimera's hard dep to resolve from PyPI) is the user's action; until then, chimera resolves it from the local checkout (editable install) — Task 17 still codes against the public import path.
