# Investigation 2: certificate rejection

Evidence includes browser/Wireshark screenshots, pasted Caddy startup output
and the transferred capture. Offline parsing verified 409 original packets,
the selected TCP handshake, TLS 1.3 / cipher 0x1301 selection and the final
RST/ACK in original frame 77. The reviewed export contains only the ten
packets for client port 54254 to server port 443.

The alternate Caddy configuration started at 2026-10-28 23:02:42 UTC with
separate storage at `C:/Lab/HTTPS/untrusted-storage`. Startup reported that
root certificate trust store installation was disabled and that a localhost
certificate was obtained successfully.

Firefox rejected `https://localhost/?case=trust-failure-02` with:

- `SEC_ERROR_BAD_SIGNATURE`
- `Peer's certificate has an invalid signature.`

Record this exact outcome, rather than relabeling it as
`SEC_ERROR_UNKNOWN_ISSUER`. A certificate validation failure was observed;
the underlying reason has not been established.

The next Wireshark screenshot shows IPv4 loopback connections to TCP 443:

| Frames | Observation |
| --- | --- |
| 39, 40, 41 | Client port 54254: SYN, SYN/ACK, ACK |
| 42 | Client Hello with SNI localhost, port 54254 |
| 48, 49, 50 | Client port 54255: SYN, SYN/ACK, ACK |
| 51 | Client Hello with SNI localhost, port 54255 |
| 53 | Server Hello and additional TLS records to port 54254 |
| 57 | Server Hello and additional TLS records to port 54255 |
| 75 | Encrypted TLS record labeled Application Data, client 54254 to server 443 |
| 76 | Server acknowledges the client's bytes |
| 77 | Client 54254 sends RST/ACK to server 443 |

The filtered follow-up screenshot shows ten packets for port 54254, from TCP
establishment through a client reset. Together with the browser error, this
shows connectivity followed by certificate rejection and a client-side reset.
The reset alone does not establish its cause. Packet 75's contents cannot be
identified from this encrypted view; no particular TLS alert or HTTP request
is established. Encrypted records labeled Application Data can contain
encrypted handshake messages or alerts in TLS 1.3.

The user ran a conditional `Test-Path` / `Select-String` check against
`C:\Lab\HTTPS\access-untrusted.json` for the literal
`/?case=trust-failure-02`. The reported output contained neither matching lines
nor the fallback message for a missing file. This indicates that the file
existed and no matching line was returned. This is supporting evidence, not
independent proof that no HTTP request was sent or a diagnosis of the
certificate-chain failure.

The browser error, TCP/TLS sequence, client reset, and absence of a matching
access entry have now been recorded. The second connection (port 54255) has
not been examined through its end, and no session secrets were available to
identify the encrypted client record. The underlying signature failure remains
unconfirmed. The original server configuration was restored for investigation 3.

## Research context

[Mozilla's NSS error reference](https://www-archive.mozilla.org/projects/security/pki/nss/ref/ssl/sslerr)
distinguishes a bad signature from an unknown certificate issuer.
A [firsthand Nextcloud project report](https://github.com/nextcloud/all-in-one/discussions/7937)
describes this Firefox error with two Caddy certificate authorities using the
same default names. That is a possible explanation to test here, not a confirmed
diagnosis. No certificate chain or CA key comparison has been performed.
