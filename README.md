# Centurion

A mobile QA + penetration-testing toolkit. Centurion wraps the OWASP MASTG tool set
(Android + iOS) and device/QA tooling like scrcpy behind one consistent layer: a CLI for
daily use and an MCP server so Claude Code can drive it, with shipped skills and subagents.

Centurion **wraps** existing tools — it shells out and parses their output into structured
results. It does **not** reimplement them, auto-install them, or duplicate MobSF. Every tool
is detected on demand; when one is missing, Centurion prints a manual install hint rather
than fetching anything.

## Tool coverage

18 adapters across Android, iOS, and platform-generic tooling:

| Category | Android | iOS | Generic |
|---|---|---|---|
| device / QA | adb, scrcpy | idevice (libimobiledevice), ideviceinstaller | |
| static | jadx, apktool, dex2jar, apksigner | class-dump | opengrep |
| dynamic | objection, drozer | frida-ios-dump | frida |
| recon | | | radare2, strings |
| network | | | mitmproxy, tcpdump |

iOS plist/IPA introspection uses the Python standard library (`plistlib`/`zipfile`) — no
external tool required.

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
```

## MCP (Claude Code)

Register the stdio server:

```bash
claude mcp add centurion -- centurion-mcp
```

This exposes 23 tools and 3 resources, including:

- **Recon:** `doctor`, `device_list`, `ios_device_list`, `recon_strings`, `recon_radare2`
- **Apps:** `app_list` / `app_pull` (Android), `ios_app_list` / `ios_app_pull` (decrypted IPA)
- **Static:** `static_decode`, `static_scan` (Opengrep → findings), `ios_static_ipa`,
  `ios_plist`, `ios_classdump`
- **Dynamic:** `objection_run`, `frida_list_scripts`, `frida_run_named_script`,
  `frida_run_script`, `ssl_unpin`
- **Network:** `proxy_start` / `proxy_stop` / `proxy_flows` (mitmproxy)
- **Findings:** `findings_list`
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

## Legal / ethical scope

Centurion is for **authorized** mobile security testing and QA only — pentest engagements,
security research, CTFs, and testing applications you own or are explicitly permitted to
test. The bundled Frida scripts are for authorized use. You are responsible for staying
within the scope of your authorization.

## License

Apache-2.0.
