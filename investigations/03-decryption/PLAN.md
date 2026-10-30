# Investigation 3: encrypted versus decrypted traffic (procedure)

Live decryption of HTTP/2 headers, response status and response body has been
observed and checked. See [observations](OBSERVATIONS.md) for the evidence.

The user restored the original Caddy configuration. Startup at
2026-10-28 23:18:58 UTC reported the original storage location, h1/h2 serving,
and a root certificate already trusted by the system.

Collect a new loopback capture before launching Firefox. Close all Firefox
windows first so a running process does not reuse its existing environment.
In a second PowerShell window inside the VM, set a process-scoped variable
and start the browser from that same shell:

```powershell
$env:SSLKEYLOGFILE = 'C:\Lab\HTTPS\03-session-secrets.log'
Start-Process -FilePath "$env:ProgramFiles\Mozilla Firefox\firefox.exe" -ArgumentList '-private-window', 'https://localhost/?case=decryption-03'
Remove-Item Env:\SSLKEYLOGFILE
```

The browser inherits the variable on launch. Removing it from this shell
after launch does not stop logging in the browser; close that browser after
the experiment. Do not set a persistent user or machine variable. The launch
path assumes the standard 64-bit installation; if missing, locate the actual
executable before proceeding.

Save the capture as `C:\Lab\HTTPS\03-decryption.pcapng`. First inspect it
without a TLS key-log preference configured. Then verify the key-log file
exists and is nonempty (do not print the secrets), configure Wireshark's
Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename,
and compare the same connection with the keys loaded.

Look for the exact HTTP/2 request path, response status, and response body.
Distinguish observed header decryption from confirmation of response body bytes.
Correlate with Caddy's access log. Retain packet numbers and the TCP stream
identifier from the actual capture rather than reusing earlier port numbers.

The session-secret file stays private and is excluded by `.gitignore`.
Do not embed secrets in captures intended for publication. Review captures
for unrelated traffic before sharing. The actual captures have now been
transferred and reviewed; the public evidence includes selected connections
and verification results, with all session-secret values excluded.

Reference: [Wireshark TLS decryption workflow](https://wiki.wireshark.org/TLS).
