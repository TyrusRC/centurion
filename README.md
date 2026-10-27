# Centurion

A mobile QA + penetration-testing toolkit with OWASP Mobile Top 10 2024 mapping and MASVS v2 L1/L2 automated verification. Centurion wraps the OWASP MASTG tool set (Android + iOS) and device/QA tooling like scrcpy behind one consistent layer: a CLI for daily use and an MCP server (42 tools) so Claude Code can drive it, with shipped skills and subagents.

Centurion **wraps** existing tools — it shells out and parses their output into structured
results. It does **not** reimplement them, auto-install them, or duplicate MobSF. Every tool
is detected on demand; when one is missing, Centurion prints a manual install hint rather
than fetching anything.

## Tool coverage

26 adapters + 3 security testing tools across Android, iOS, and platform-generic tooling:

**Security testing (new):**
- `fuzz_intents` — fuzz exported activities/services/receivers with malformed extras, detect crashes
- `fuzz_deeplinks` — fuzz deep-link URIs with traversal/XSS/SSRF payloads
- `verify_masvs` — automated MASVS L1/L2 verification with per-control pass/fail + Mobile Top 10 coverage

**Adapters:**

| Category | Android | iOS | Generic |
|---|---|---|---|
| device / QA | adb, scrcpy | idevice (libimobiledevice + iproxy), ideviceinstaller | |
| static | jadx, apktool, dex2jar, apksigner, apkid, apkleaks, aapt2 | class-dump, otool, ldid | opengrep, gitleaks, mantis |
| dynamic | objection, drozer | frida-ios-dump | frida |
| recon | | | radare2, strings, nm |
| network | | | mitmproxy, tcpdump |

iOS plist/IPA introspection uses the Python standard library (`plistlib`/`zipfile`) — no
external tool required. `mantis` is a findings source for the sibling
[mantis-sast](https://github.com/TyrusRC/mantis) project: `MantisAdapter.audit()` calls
mantis's programmatic entry point (`from mantis import audit`) and maps its records into
Centurion `Finding`s, and the `mantis_scan` MCP tool exposes it (point it at jadx/apktool
output to statically audit recovered code). Centurion ingests mantis's validated findings
rather than scoring vulnerabilities itself.

## Install

System Python is often externally managed, so use a virtualenv:

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/centurion doctor
```

`doctor` reports every wrapped tool with its install status, version, and — when missing —
how to install it. `centurion install --group <android|ios|static|dynamic|network|recon|all>`
prints the install hints for a group of missing tools.

## CLI

```bash
centurion version
centurion doctor                 # tool inventory + install status
centurion install --group ios    # install hints for the iOS tools
centurion device list            # connected Android devices
centurion screenshot <target>    # capture a device screenshot into the workspace
centurion report <target>        # render the workspace report (Markdown + HTML)
```

## MCP (Claude Code)

Register the stdio server:

```bash
claude mcp add centurion -- centurion-mcp
```

This exposes 34 tools and 3 resources, including:

- **Recon:** `doctor`, `device_list`, `ios_device_list`, `recon_strings`, `recon_symbols`
  (nm), `recon_radare2`, `apk_badging` (aapt2)
- **Apps:** `app_list` / `app_pull` (Android), `ios_app_list` / `ios_app_pull` (decrypted IPA)
- **Static (Android):** `static_decode`, `static_scan` (Opengrep → findings), `apkid_scan`
  (packer/obfuscator), `apkleaks_scan` and `secrets_scan` (gitleaks) → findings
- **Static (iOS):** `ios_static_ipa`, `ios_plist`, `ios_classdump`, `ios_binary_info` (otool
  hardening → findings), `ios_entitlements` (ldid)
- **Dynamic:** `objection_run`, `frida_list_scripts`, `frida_run_named_script`,
  `frida_run_script`, `ssl_unpin`, `ios_relay` (iproxy USB relay)
- **Network:** `proxy_start` / `proxy_stop` / `proxy_flows` (mitmproxy)
- **Evidence:** `screenshot` (adb), `ios_screenshot` (idevicescreenshot) — plus dynamic runs
  (objection, Frida scripts) auto-capture a screenshot as evidence
- **Findings & reporting:** `findings_list` (MASVS-enriched), `report_generate` (Markdown +
  self-contained HTML with embedded screenshots)
- **Resources:** `centurion://scripts`, `centurion://findings/{target}`,
  `centurion://processes/{target}`

Long-running tools (mitmproxy, Frida scripts) are tracked through a durable, workspace-backed
process manager, so their handles survive across separate MCP invocations — no daemon.

### Skills

`centurion-recon`, `centurion-ios-recon`, `centurion-static-analysis`,
`centurion-dynamic-analysis`, `centurion-network-intercept`.

### Subagents

`centurion-static-analyst`, `centurion-dynamic-analyst`, `centurion-triage`.

### Bundled Frida scripts

Six vetted, original scripts (labelled for authorized testing only): Android —
`ssl_unpin`, `root_bypass`, `debugger_bypass`, `dump_class_hooks`; iOS — `ios_ssl_unpin`,
`ios_jailbreak_bypass`. List them with the `frida_list_scripts` tool; arbitrary scripts run
via `frida_run_script`.

## Development

```bash
.venv/bin/python -m pytest        # full suite (FakeRunner-based; never touches a real device)
```

Adapters are unit-tested with an injectable subprocess runner, so the suite runs offline with
no device or emulator.

## Chimera Integration

[Chimera](https://github.com/TyrusRC/chimera) (the RE MCP server) bridges centurion's
tools into its own MCP surface via two tools:

- **`centurion_tools`** — lists all 26 adapters with install status, version, and hints
- **`centurion_run`** — executes any centurion MCP tool by name, passing `target` and
  additional arguments

This lets an RE agent use centurion's mobile toolkit without switching MCP servers:

```python
# From chimera MCP:
centurion_tools()                              # see what's installed
centurion_run(command="static_decode", target="myapp", args={"apk": "/path/to/app.apk"})
centurion_run(command="apkid_scan", target="myapp", args={"apk": "/path/to/app.apk"})
centurion_run(command="apkleaks_scan", target="myapp", args={"apk": "/path/to/app.apk"})
centurion_run(command="ssl_unpin", target="myapp", args={"target_app": "com.example.app"})
```

The chimera `sast-workflow` skill guides the agent through the RE→centurion→mantis
pipeline: analyze binary → extract APK → centurion static analysis → mantis SAST audit.

## Praetor Integration

[Praetor](https://github.com/TyrusRC/praetor) registers centurion as a companion MCP server (`setup.sh` installs it). The `mobile-dynamic-agent` in praetor dispatches centurion tools for Frida hooking, SSL pinning bypass, deep-link abuse, and APK static analysis. Findings from centurion cite `apk_sha256` / `package_name` and feed into praetor's save-finding pipeline.

```
praetor agent: mobile-dynamic-agent → centurion MCP: frida_run, decompile_apk, app_control
```

## Legal / ethical scope

Centurion is for **authorized** mobile security testing and QA only — pentest engagements,
security research, CTFs, and testing applications you own or are explicitly permitted to
test. The bundled Frida scripts are for authorized use. You are responsible for staying
within the scope of your authorization.

## License

Apache-2.0.
