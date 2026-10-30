"""Verify public evidence integrity without dependencies or session secrets.

This does not repeat TLS decryption: those secrets deliberately stay private.
Open the captures in Wireshark to inspect their protocol details.
"""
import csv
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_packets(raw):
    offset = 0
    packets = []
    interface_seen = False
    section_seen = False
    while offset < len(raw):
        require(offset + 12 <= len(raw), 'Incomplete pcapng block')
        kind, size = struct.unpack_from('<II', raw, offset)
        require(size >= 12 and size % 4 == 0 and offset + size <= len(raw), 'Invalid block size')
        require(struct.unpack_from('<I', raw, offset + size - 4)[0] == size, 'Invalid block trailer')
        body = raw[offset + 8:offset + size - 4]
        require(kind in (0x0a0d0d0a, 1, 6), 'Unexpected metadata or secrets block')
        if kind == 0x0a0d0d0a:
            require(not section_seen and not packets and len(body) == 16, 'Unexpected section')
            require(struct.unpack('<IHHq', body) == (0x1a2b3c4d, 1, 0, -1), 'Unexpected section format')
            section_seen = True
        elif kind == 1:
            require(section_seen and not interface_seen and not packets, 'Unexpected interface order')
            require(struct.unpack_from('<H', body)[0] == 0, 'Expected NULL loopback link type')
            option_offset = 8
            while option_offset < len(body):
                code, length = struct.unpack_from('<HH', body, option_offset)
                require(code in (0, 9, 14), 'Unexpected interface annotation')
                option_offset += 4
                if code == 0:
                    require(length == 0 and option_offset == len(body), 'Invalid option terminator')
                    break
                require(option_offset + length <= len(body), 'Invalid interface option')
                option_offset += (length + 3) & ~3
            interface_seen = True
        else:
            require(interface_seen and len(body) >= 20, 'Missing interface or packet header')
            interface, _, _, caplen, original = struct.unpack_from('<IIIII', body)
            require(interface == 0 and caplen == original, 'Unexpected or truncated packet')
            require(len(body) == 20 + ((caplen + 3) & ~3), 'Packet options are not expected')
            packets.append(body[20:20 + caplen])
        offset += size
    require(section_seen and interface_seen and packets, 'Empty or incomplete capture')
    return packets


def inspect_tcp(packet):
    require(len(packet) >= 44, 'Packet too short for IPv4/TCP')
    require(struct.unpack_from('<I', packet)[0] == 2, 'Expected IPv4 loopback family')
    ip = packet[4:]
    require(ip[0] >> 4 == 4 and ip[9] == 6, 'Expected IPv4/TCP')
    require(ip[12:20] == bytes([127, 0, 0, 1]) * 2, 'Unexpected address')
    require(not (int.from_bytes(ip[6:8], 'big') & 0x3fff), 'Fragmented packet')
    ihl = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], 'big')
    require(ihl >= 20 and ihl + 20 <= total == len(ip), 'Invalid IPv4 length')
    tcp = ip[ihl:total]
    header_length = (tcp[12] >> 4) * 4
    require(20 <= header_length <= len(tcp), 'Invalid TCP header')
    source, destination = struct.unpack_from('!HH', tcp)
    return source, destination, tcp[13], len(tcp) - header_length


def main():
    capture_dir = ROOT / 'evidence/captures'
    manifest = json.loads((capture_dir / 'manifest.json').read_text(encoding='utf-8'))
    require(len(manifest) == 3, 'Expected three capture entries')
    expected = {'01-success.pcapng': (31, 52203),
                '02-trust-failure.pcapng': (10, 54254),
                '03-decryption.pcapng': (31, 52951)}
    require({entry['file'] for entry in manifest} == set(expected), 'Unexpected capture names')
    for entry in manifest:
        name = entry['file']
        raw = (capture_dir / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == entry['scoped_sha256'], f'Hash mismatch: {name}')
        require(len(raw) == entry['scoped_bytes'], f'Size mismatch: {name}')
        packets = read_packets(raw)
        count, client_port = expected[name]
        require(len(packets) == entry['selected_packets'] == count, f'Count mismatch: {name}')
        with (capture_dir / (name + '.frames.csv')).open(encoding='utf-8', newline='') as stream:
            rows = list(csv.DictReader(stream))
        require(len(rows) == count, f'Frame map length mismatch: {name}')
        previous_original = 0
        observed = []
        for index, (packet, row) in enumerate(zip(packets, rows), 1):
            source, destination, flags, payload_length = inspect_tcp(packet)
            require({source, destination} == {client_port, 443}, f'Unexpected connection: {name}')
            require(int(row['export_frame']) == index, f'Invalid export frame: {name}')
            require(int(row['original_frame']) > previous_original, f'Unordered original frame: {name}')
            previous_original = int(row['original_frame'])
            require((source, destination, flags, payload_length) ==
                    (int(row['src_port']), int(row['dst_port']), int(row['flags_hex'], 16),
                     int(row['tcp_payload_bytes'])), f'Frame map mismatch: {name}')
            observed.append((source, destination, flags))
        require(observed[:3] == [(client_port, 443, 2), (443, client_port, 18),
                                 (client_port, 443, 16)], f'Missing handshake: {name}')
        if name.startswith('02-'):
            require(observed[-1] == (client_port, 443, 20) and previous_original == 77,
                    'Certificate test reset missing')
        print(f'PASS {name}: hash, {count} loopback packets, frame map, TCP handshake')

    result = json.loads((capture_dir / 'decryption-verification.json').read_text())
    log = json.loads((ROOT / 'investigations/03-decryption/access-entry.json').read_text())
    require(result['response_status'] == log['status'] == 200, 'Response status mismatch')
    require(result['response_body'] == 'HTTPS lab is working.', 'Unexpected recorded body')
    require(result['response_body_bytes'] == log['size'] == 21, 'Response size mismatch')
    require(hashlib.sha256(result['response_body'].encode()).hexdigest() ==
            result['response_body_sha256'], 'Response body hash mismatch')
    require(log['request']['remote_port'] == '52951' and
            log['request']['uri'] == '/?case=decryption-03', 'Unexpected correlated request')

    for document in ROOT.rglob('*.md'):
        for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)', document.read_text(encoding='utf-8')):
            if '://' not in link and not link.startswith('#'):
                require((document.parent / link.split('#')[0]).exists(), f'Broken link in {document.name}: {link}')
    for file in ROOT.rglob('*'):
        if file.is_file() and '.git' not in file.parts:
            require(file.suffix.lower() not in ('.log', '.key', '.keylog', '.exe'),
                    f'Unexpected private/binary working file: {file.name}')
    print('PASS recorded response/log consistency and documentation links')
    print('TLS decryption is recorded evidence; CI does not receive or use session secrets.')


if __name__ == '__main__':
    main()
