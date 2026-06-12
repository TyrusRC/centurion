---
name: centurion-dynamic-analysis
description: Use to dynamically instrument a running Android app with Frida/objection — list and run vetted hook scripts, bypass TLS pinning, and explore at runtime. Drives the Centurion MCP server.
---

# Centurion: Dynamic Analysis

Attach, hook, observe. Use the Centurion MCP server. Operate only on apps you are authorized to test.

## Steps

1. **Confirm Frida is ready.** Call `doctor` and check `frida`/`objection`. A frida-server must be running on the device/emulator; if missing, give the user the install hint (don't auto-install).

2. **Browse hooks.** Call `frida_list_scripts` to show the bundled, vetted scripts (ssl_unpin, root_bypass, debugger_bypass, dump_class_hooks) with descriptions.

3. **Run a hook.** Call `frida_run_named_script(target_app, script, target)` to spawn the app under a bundled script, or `ssl_unpin(target_app, target)` for the common pinning bypass. For a custom script, use `frida_run_script(target_app, script_path, target)`. Each returns a durable process handle that survives across sessions.

4. **Explore with objection.** For interactive-style runtime queries, call `objection_run(package, commands)` with startup commands (e.g. `android hooking list classes`).

5. **Report.** Summarize what the hooks observed. Long-running handles appear in `centurion://processes/{target}`.

## Scope reminder

Authorized assessments only. The bundled scripts are for authorized testing.
