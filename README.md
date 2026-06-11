# Centurion

A mobile QA + penetration-testing toolkit. Centurion wraps the OWASP MASTG tool set
(Android + iOS) and device/QA tooling like scrcpy behind one consistent layer: a CLI for
daily use and an MCP server so Claude Code can drive it, with shipped skills and subagents.

Centurion **wraps** existing tools — it does not reimplement them, and it deliberately
does not duplicate MobSF.

## Status

Phase 1 (vertical slice): core, Android device layer, `doctor`/`install`, CLI + MCP
skeletons, and four anchor adapters — adb, scrcpy, jadx, frida.

## Install

```bash
pip install -e ".[dev]"
centurion doctor
```

## MCP (Claude Code)

Register the stdio server:

```bash
claude mcp add centurion -- centurion-mcp
```

Then use the bundled skills (e.g. `centurion-recon`).

## Legal / ethical scope

Centurion is for **authorized** mobile security testing and QA only — pentest engagements,
security research, CTFs, and testing applications you own or are explicitly permitted to
test. You are responsible for staying within the scope of your authorization.

## License

Apache-2.0.
