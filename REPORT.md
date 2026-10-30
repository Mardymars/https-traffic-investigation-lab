# HTTPS traffic investigation: findings

Built a local HTTPS service in a Windows VM and investigated successful
connections, certificate rejection, and browser-assisted TLS decryption.
All three hands-on experiments produced the evidence described below.

Tools: Wireshark 4.6.9, Npcap loopback capture, Caddy 2.11.7, Firefox and
PowerShell. Browser and server ran inside the same VM on loopback; the HTTPS
listener used TCP 443 with HTTP/3 disabled. Internet access was not needed
for the local experiments after installing the tools.

## Results

| Investigation | Evidence | Finding |
| --- | --- | --- |
| Successful HTTPS | TCP SYN/SYN-ACK/ACK, Client Hello, Server Hello and a matching access entry | TLS 1.3 negotiated TLS_AES_128_GCM_SHA256; Caddy recorded HTTP/2 GET and status 200 |
| Certificate rejection | Firefox SEC_ERROR_BAD_SIGNATURE, TCP/TLS negotiation followed by a client reset, no matching access-log entry | The service was reachable, but certificate validation failed; the exact chain failure was not diagnosed |
| TLS decryption | Same capture before and after supplying browser session secrets; readable HTTP/2 GET, 200 OK and response body | Session secrets allowed Wireshark to reveal HTTPS contents; Caddy's port, URI, status and body length matched |

### Successful connection

Frames 643-645 show TCP establishment on client port 52203. Frame 646 shows
Client Hello with SNI localhost. Frame 797 selects TLS 1.3 in supported_versions
and cipher suite 0x1301. The legacy TLS 1.2 version field does not identify the
negotiated version. Caddy's matching log entry corroborates the HTTP result;
the encrypted-only capture view did not reveal the request path or response.

### Certificate rejection

A separate Caddy storage directory generated a new CA, with automatic trust
installation disabled. Firefox displayed SEC_ERROR_BAD_SIGNATURE, rather
than the anticipated simple unknown-issuer warning. For client port 54254,
frames 39-41 establish TCP and frame 77 shows a client reset after TLS begins.
No matching request was returned by the access-log search.

This supports a certificate-validation failure, not a connectivity failure.
The reset alone does not identify the cause. A reported conflict between
same-named Caddy CAs is a hypothesis, not a confirmed finding in this lab.
The encrypted client record was not decoded into a specific TLS alert.

### Decrypted connection

For client port 52951, frame 187 reveals GET /?case=decryption-03, frame 267
reveals 200 OK, and frame 269 contains the 21-byte body
`HTTPS lab is working.`. Caddy's access entry agrees on the client port,
HTTP/2 protocol, exact URI, status and response size.

Offline verification of the transferred capture also authenticated the selected
TLS records and decoded the 200 response and exact 21-byte body using the
privately held session secrets. The request path remains corroborated by the
Wireshark GUI and server log; the local helper did not decode its HPACK value.

The same traffic had appeared as TLS Application Data before loading the
browser's session secrets. Decryption supplied the HTTP details for analysis;
the connection itself remained encrypted.

## Relevance to SOC and IT work

- Separate TCP reachability, TLS negotiation and HTTP outcomes when diagnosing
  a failed web connection.
- Use packet metadata and server logs together to support an investigation.
- Explain what encrypted captures reveal and why session secrets change
  visibility. Encryption does not establish that an application is benign.
- Record an unexpected error accurately and distinguish a working hypothesis
  from a verified cause.

## Evidence limits

Findings combine browser/Wireshark screenshots, Caddy logs and offline checks
of the transferred captures. Public exports contain only the selected
connections: 31, 10 and 31 packets. Original packet bytes and timestamps are
preserved; background traffic and capture annotations are omitted. No session
secrets are embedded. Frame maps relate the exported frames to the original
numbers used in this report. Only selected connections were examined.
No real incident, exploitation,
arbitrary HTTPS decryption or production monitoring deployment is claimed.
See the investigation notes for packet references, procedures and sources.
