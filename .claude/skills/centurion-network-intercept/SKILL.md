---
name: centurion-network-intercept
description: Use to intercept an Android app's HTTPS traffic — start a mitmproxy capture, guide CA-cert install, then summarize captured flows. Drives the Centurion MCP server.
---

# Centurion: Network Intercept

Proxy, trust, capture, summarize. Use the Centurion MCP server. Operate only on traffic you are authorized to intercept.

## Steps

1. **Start the proxy.** Call `proxy_start(target, port)` (default port 8080). It returns a durable `proxy` handle; flows are written into the workspace.

2. **Make the device trust mitmproxy.** Guide the user: set the device/emulator Wi-Fi proxy to the host IP and port, browse to `mitm.it` to install the CA certificate, and (for API >= 24) note that user CAs are not trusted by apps unless they opt in — system-CA install or a Frida pinning/`ssl_unpin` bypass may be required.

3. **Exercise the app**, then **summarize.** Call `proxy_flows(target)` to list captured request method + URL pairs. Highlight cleartext, sensitive endpoints, and tokens.

4. **Stop.** Call `proxy_stop(target)` when done.

## iOS variant

The proxy flow is identical for iOS. To trust mitmproxy, install the CA profile via Settings
and enable it under General > About > Certificate Trust Settings. App-level pinning still
needs a bypass — run the `ios_ssl_unpin` Frida script via
`frida_run_named_script(bundle_id, "ios_ssl_unpin", target)`.

## Scope reminder

Authorized assessments only.
