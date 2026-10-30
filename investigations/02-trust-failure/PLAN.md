# Investigation 2: certificate trust failure procedure

The live test and selected-flow capture review are complete; see
[observations](OBSERVATIONS.md) for the exact browser error and packet evidence.

Use `Caddyfile-untrusted` inside the VM. It preserves the original trusted
configuration and uses a separate storage directory to generate a fresh local
CA and leaf certificate. `skip_install_trust` prevents automatically trusting
the new CA. Merely adding that option to the original configuration would not
remove the already-trusted root and would not create the intended experiment.

Close all Firefox windows, stop the original Caddy process with Ctrl+C, then
start the untrusted configuration with the explicit Caddyfile adapter. Fresh
storage avoids reusing the original localhost certificate. The storage directory
contains private CA material and must not be published as evidence.

Expected: TCP connectivity succeeds, TLS begins, and Firefox rejects the
certificate's trust chain. Exact browser code and packet behavior are to be
observed; no TLS alert is presumed to be visible without session secrets.

Start a fresh loopback capture before requesting
`https://localhost/?case=trust-failure-02`. Use `tcp.port == 443` as the display
filter. Do not reuse client port 52203; a new connection can use a different port.
Do not accept a certificate exception or import the new CA during the test.

Save as `C:\Lab\HTTPS\02-trust-failure.pcapng`. Record the browser error,
related client/server ports, TCP/TLS observations, and whether an HTTP request
appears in `access-untrusted.json`. File absence or missing log entries alone
does not prove which TLS validation step failed.

Restore the working configuration afterward by stopping Caddy and running
`caddy.exe run --config .\Caddyfile`. Keep captures separate from the upcoming
session-secret-assisted decryption investigation.

References: [Caddy skip_install_trust and storage](https://caddyserver.com/docs/caddyfile/options)
and [internal TLS issuer](https://caddyserver.com/docs/caddyfile/directives/tls).
