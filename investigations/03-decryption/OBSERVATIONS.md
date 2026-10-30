# Investigation 3: successful HTTP/2 request and response decryption

Evidence includes browser/Wireshark screenshots, the transferred capture and a
matching Caddy entry. A privately copied session-secret log enabled offline
verification of the selected connection's TLS records and response. The
secrets remain excluded from the public evidence package.

The browser screenshot shows `https://localhost/?case=decryption-03` displaying
`HTTPS lab is working.`. A later screenshot shows the saved capture
`03-decryption.pcapng` with 678 packets and zero reported drops, filtered to
TCP port 443. Its visible application records were labeled TLS Application
Data, without readable HTTP request paths or response statuses in the list.

After instructions to load the browser key-log file into Wireshark, the next
screenshot shows the same capture filtered with `http2`, displaying 12 packets:

| Frame | Visible observation |
| --- | --- |
| 185 | HTTP/2 connection preface, SETTINGS and WINDOW_UPDATE |
| 187 | HEADERS for stream 3: GET /?case=decryption-03 |
| 267 | SETTINGS, WINDOW_UPDATE and HEADERS for stream 3: 200 OK |
| 269 | DATA for stream 3, text/plain; decrypted bytes show HTTPS lab is working. |
| 362 | HEADERS for stream 5: GET /favicon.ico |
| 394 | HEADERS for stream 5: 200 OK |
| 396 | DATA for stream 5, labeled text/plain |

Selected frame 185 shows client port 52951 to server port 443, TCP stream
index 1, and a `Decrypted TLS (70 bytes)` tab. Both addresses are 127.0.0.1.
Other listed packets include GOAWAY frames; their codes and connection
associations have not been inspected, so no failure is inferred from them.

The readable request and status, together with Wireshark's Decrypted TLS tab,
demonstrate successful decryption. A subsequent screenshot shows frame 269
selected with `Decrypted TLS (30 bytes)` active. Its bytes are:

```text
00 00 15 00 01 00 00 00 03 48 54 54 50 53 20 6c
61 62 20 69 73 20 77 6f 72 6b 69 6e 67 2e
```

These consist of a nine-byte HTTP/2 DATA frame header followed by the 21-byte
body `HTTPS lab is working.`. The header specifies stream 3, payload length
21, and END_STREAM. The response text matches the browser and Caddy config.
The user subsequently supplied the exact matching Caddy access entry.
[`access-entry.json`](access-entry.json) preserves it as formatted JSON, with
console line wrapping removed. It reports client port 52951, HTTP/2.0,
GET `/?case=decryption-03`, status 200 and size 21. This matches the decrypted
request, response status and response body length. TLS metadata reports
version 772 (0x0304, TLS 1.3), cipher suite 4865 (0x1301), ALPN h2 and no
session resumption.

## Offline verification after transfer

Parsing confirmed 678 original packets; 31 belong to the selected loopback
connection on client port 52951. The selected Client Hello uses SNI localhost
and the Server Hello selects TLS 1.3 / cipher 0x1301.

A local verification helper reassembled the selected TCP byte streams and used
Node.js authenticated AES-GCM decryption with the supplied TLS 1.3 session
secrets. It authenticated five client records and nine server records, verified
the HTTP/2 client connection preface, decoded the stream-3 response status
(HPACK static entry 8, status 200), and confirmed the exact 21-byte DATA body
and END_STREAM. See
[verification results](../../evidence/captures/decryption-verification.json).
The compressed request path was not independently decoded by that helper;
its evidence remains the Wireshark screenshot and matching Caddy log.

The reviewed export preserves the selected packets and timestamps without
background traffic, original capture annotations or embedded session secrets.
Exported frame numbers differ; use the CSV frame map beside the capture.

This demonstrates decryption with session secrets supplied from the lab's own
browser; it does not demonstrate decrypting arbitrary HTTPS traffic without
keys. The TLS traffic remains encrypted on the connection.

Reference: [Wireshark TLS decryption](https://wiki.wireshark.org/TLS).
