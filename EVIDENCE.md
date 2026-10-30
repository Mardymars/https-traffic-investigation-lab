# Evidence inventory

## Reviewed capture exports

All three originals were transferred from the VM and parsed locally.
The public exports retain only the selected IPv4 loopback TCP connection.

| Export | Original packets | Exported packets | Client port |
| --- | --- | --- | --- |
| [01-success.pcapng](evidence/captures/01-success.pcapng) | 996 | 31 | 52203 |
| [02-trust-failure.pcapng](evidence/captures/02-trust-failure.pcapng) | 409 | 10 | 54254 |
| [03-decryption.pcapng](evidence/captures/03-decryption.pcapng) | 678 | 31 | 52951 |

All selected packets use 127.0.0.1 in both directions and TCP server port 443.
The original packet bytes and timestamps were preserved. Other connections,
section/interface annotations and packet options were omitted. Only timestamp
resolution/offset options were retained. Exported packets were read back and
compared with the selected originals. No Decryption Secrets Blocks are present.

The [manifest](evidence/captures/manifest.json) records original and export
SHA-256 hashes, counts and TLS selections. Each capture's `.frames.csv` maps
new frame numbers to the originals cited in the notes.

## Supporting records

- [Investigation 1 notes](investigations/01-success/OBSERVATIONS.md) and
  [matching Caddy entry](investigations/01-success/access-entry.json).
- [Investigation 2 notes](investigations/02-trust-failure/OBSERVATIONS.md),
  including Firefox's exact error and client reset. The access-log search
  returned no matching entry; this alone does not diagnose the TLS failure.
- [Investigation 3 notes](investigations/03-decryption/OBSERVATIONS.md),
  [matching Caddy entry](investigations/03-decryption/access-entry.json) and
  [offline decryption verification](evidence/captures/decryption-verification.json).
- Original and alternate Caddy configurations and reproduction procedures.

Browser and Wireshark screenshots were reviewed during the exercise. Their
observations are transcribed in the notes; screenshot image files are not
included. Caddy entries were pasted from the VM and reformatted as JSON, with
console wrapping removed.

## Verification scope

Local analysis helpers parsed the pcapng block structure and selected loopback
TCP packets, reassembled TLS byte streams, and checked SNI, TLS version and
cipher suite. A separate offline helper used Node.js AES-GCM authentication
with privately held browser secrets to verify the third connection's HTTP/2
preface, response status, body and END_STREAM. This supplements the Wireshark
GUI evidence; it is not a full protocol-analyzer implementation. The request
path was corroborated in the GUI and server log, not decoded by that helper.

The helpers and raw inputs are working files, excluded from this portfolio
package. Public captures can be inspected directly with Wireshark.

## Private material and cleanup

Original captures and the copied session-key log remain in the private working
folder, excluded from Git. Caddy's private CA storage remains inside the VM.
No private keys, browser session-secret values or embedded decryption secrets
are part of the public package.

Close the Firefox process launched with SSLKEYLOGFILE to stop its logging;
the launch shell's process-scoped variable was already removed. Stop Caddy
with Ctrl+C. Captures and notes remain available after shutdown.
