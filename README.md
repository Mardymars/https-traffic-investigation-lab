# HTTPS Traffic Investigation Lab

![Evidence checks](https://github.com/Mardymars/https-traffic-investigation-lab/actions/workflows/verify-evidence.yml/badge.svg)

Investigated HTTPS over TCP port 443 in a Windows VM using **Wireshark,
Npcap, Caddy, Firefox and PowerShell**. Completed three experiments and
correlated packet evidence with browser behavior and server access logs.

| Experiment | What I observed |
| --- | --- |
| Successful HTTPS | TCP three-way handshake, TLS 1.3 negotiation, encrypted traffic and a matching HTTP/2 200 access entry |
| Certificate rejection | Firefox SEC_ERROR_BAD_SIGNATURE, a client TCP reset and no matching access-log entry |
| Controlled TLS decryption | Readable HTTP/2 request, 200 response and exact response text after supplying my lab browser's session secrets |

## Start here

- [Findings report](REPORT.md): what happened and why it matters for SOC and IT work.
- [Reviewed captures](evidence/captures/): three small loopback captures, frame maps,
  hashes and decryption verification results.
- [Evidence inventory](EVIDENCE.md): sources, review method and limitations.
- Detailed notes: [successful HTTPS](investigations/01-success/OBSERVATIONS.md),
  [certificate rejection](investigations/02-trust-failure/OBSERVATIONS.md),
  [decryption](investigations/03-decryption/OBSERVATIONS.md).

## Lab setup

All traffic stayed on loopback inside the Windows VM. Caddy served
`https://localhost:443`; HTTP/3 was disabled to focus on TCP. Wireshark captured
on the Npcap loopback interface. Observed versions: Wireshark 4.6.9, Caddy 2.11.7
and Firefox 159.0. No public domain was needed.

Copy `Caddyfile` alongside `caddy.exe` into `C:\Lab\HTTPS` in a disposable
Windows lab VM and run:

```powershell
cd C:\Lab\HTTPS
.\caddy.exe run --config .\Caddyfile
```

Caddy creates a local CA and may request permission to trust it inside the VM.
The response at `https://localhost/?case=success-01` is
`HTTPS lab is working.`. Start capturing before visiting the site.

Use the [separate certificate-test procedure](investigations/02-trust-failure/PLAN.md)
and [session-key procedure](investigations/03-decryption/PLAN.md) for the other
experiments. Browser certificate errors can vary; record the actual error.
Close the lab browser and stop Caddy with Ctrl+C when finished.

## Reading the evidence

Open a capture in Wireshark and use `tcp.port == 443`. Public captures contain
only the selected encrypted lab connections; session secrets are not included.
To reproduce the decryption exercise, collect your own capture and browser
key log using the procedure above. Recorded results verify the original lab's
decrypted response without exposing those keys.

Packet numbers in the investigation notes refer to the original captures.
Each exported capture has a `.frames.csv` map to its new frame numbers.

Run `python scripts/verify_evidence.py` to check capture hashes, selected
connections, TCP handshakes, frame maps and supporting record consistency.
GitHub Actions runs the same check. It does not repeat decryption or receive
session secrets.

## Skills demonstrated

Packet analysis, TCP/IP troubleshooting, TLS 1.3, certificate validation,
HTTP/2, log correlation and evidence reporting. This was a controlled lab,
with findings limited to the selected connections.

Related project: [Windows Detection Validation Lab](https://github.com/Mardymars/sigma-detection-validation-lab)
uses live Sysmon events to evaluate existing Sigma detection rules.

Sources: [Wireshark TLS](https://wiki.wireshark.org/TLS),
[loopback capture](https://wiki.wireshark.org/CaptureSetup/Loopback),
[Caddy local HTTPS](https://caddyserver.com/docs/automatic-https),
and [Caddy configuration options](https://caddyserver.com/docs/caddyfile/options).
