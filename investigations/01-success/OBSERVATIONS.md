# Investigation 1: successful local HTTPS connection

Evidence includes browser/Wireshark screenshots, pasted Caddy output and the
transferred capture. Offline parsing verified the selected flow's TCP handshake,
Client Hello SNI, Server Hello TLS version and cipher suite. The original file
contains 996 packets; the reviewed export contains the 31 packets on client
port 52203 and server port 443. See the evidence manifest and frame map.

The user saved `C:\Lab\HTTPS\01-success.pcapng` inside the Windows VM.
Wireshark's screenshot shows that filename, 996 packets in the capture, and
0 dropped packets reported. This is not a claim that every packet was reviewed.

## Recorded setup observations

- Caddy version command: 2.11.7.
- Caddy startup output reports h1/h2 protocols, a certificate obtained for
  localhost from its local issuer, and successful installation of its root
  certificate into Windows trust stores.
- Firefox (visible in the screenshot) loaded
  `https://localhost/?case=success-01` and displayed `HTTPS lab is working.`
  No certificate error is visible. The browser was initially planned as Edge;
  evidence from this investigation is Firefox and should be documented as such.
- The selected connection uses IPv4 loopback `127.0.0.1`, client port 52203,
  server port 443. Another observed connection uses port 52204 and has a reset;
  it has not been diagnosed and is not treated as a failure of the selected flow.

## Packet observations from screenshots

| Frame | Direction | Observation | Interpretation |
| --- | --- | --- | --- |
| 643 | 52203 -> 443 | TCP SYN, relative Seq=0 | Client requests a TCP connection |
| 644 | 443 -> 52203 | TCP SYN/ACK, relative Seq=0 Ack=1 | Server acknowledges and responds |
| 645 | 52203 -> 443 | TCP ACK, relative Seq=1 Ack=1 | Final step of the TCP three-way handshake |
| 646 | 52203 -> 443 | TLS Client Hello; SNI=localhost | Client begins TLS negotiation and exposes this server name in the captured hello |
| 647 | 443 -> 52203 | TCP ACK | Acknowledges receipt of client data; not itself the TLS Server Hello |
| 797 | 443 -> 52203 | Server Hello, supported_versions selects TLS 1.3 (0x0304); TLS_AES_128_GCM_SHA256 (0x1301) | Confirms selected TLS version and cipher suite |

Later screenshots show TLSv1.3 Application Data records for this connection.
The expanded Server Hello screenshot now confirms `Supported Version: TLS 1.3
(0x0304)`, rather than relying on the protocol-column label alone. Its legacy
Version field shows TLS 1.2 (0x0303), which is not the selected version here.
In TLS 1.3, encrypted
records can also contain handshake messages; the label Application Data alone
does not identify a particular HTTP request or response.

## Filters used

Full selected connection:

```text
tcp.port == 443 && tcp.port == 52203
```

Initial SYN-bearing packets:

```text
tcp.port == 443 && tcp.port == 52203 && tcp.flags.syn == 1
```

Early frame range:

```text
tcp.port == 443 && tcp.port == 52203 && frame.number >= 643 && frame.number <= 650
```

## Remaining evidence

- Server Hello, selected TLS version, and cipher suite identified from screenshots.
- Matching server access-log entry preserved in `access-entry.json`.
- Scoped capture transferred, parsed and exported; packet bytes and timestamps
  preserved while background traffic and original capture annotations were removed.
- Keep encrypted-only observations separate from the later decryption investigation.

## HTTP outcome corroboration

The user supplied three JSON access-log entries. `access-entry.json` preserves
the first one, reformatted but without changing its values: remote IP 127.0.0.1,
remote port 52203, GET `/?case=success-01`, HTTP/2.0, status 200, response size
21 bytes. The TLS metadata records version 772 (0x0304, TLS 1.3), cipher suite
4865 (0x1301, TLS_AES_128_GCM_SHA256), ALPN h2, SNI localhost, and no resumption.
These agree with the selected connection's packet screenshots.

The other supplied entries were a favicon request on 52203 (the text filter
matched its Referer header) and a later main-page request on client port 55475.
Neither is silently substituted for the selected main-page request. The capture
has not been decrypted; HTTP method/path/status here are established by the
server log and browser observation, not by reading encrypted packet payloads.
