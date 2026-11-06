# SecureChannel

Linux-based prototype of a secure inline TCP communication channel.

## Network topology

PC1 → Device1 → Device2 → PC2

The prototype uses Linux network namespaces to simulate four hosts.

## Features

- X25519 Diffie-Hellman key exchange
- Pre-shared key (PSK) authentication
- Session key confirmation
- AES-256-GCM encryption and authentication
- Encryption of TCP payload only
- Preservation of original IPv4 and TCP header fields
- AES-GCM authentication tag appended to ciphertext
- IP and TCP checksum recalculation
- Linux NetfilterQueue packet interception
- No UDP encapsulation or custom protocol header

## Demonstration

The prototype protects selected TCP/IPv4 traffic from:

10.0.1.2 (PC1) → 10.0.3.2 (PC2), TCP port 8080.

Device1 encrypts the TCP payload. Device2 authenticates and decrypts it before forwarding the packet to PC2.

A successful HTTP request returned HTTP 200 OK.

## Tests

The following test scripts are available:

- test_crypto.py
- test_aes.py
- test_packet.py
- test_secure_packet.py

Run them using the Python virtual environment.

## Implemented Features

- Linux network namespaces: PC1, Device1, Device2, PC2.
- Inline TCP/IPv4 processing using NetfilterQueue.
- Authenticated X25519 Diffie-Hellman handshake.
- HKDF-based session key derivation.
- Separate AES-GCM keys for both directions.
- TCP payload encryption without UDP encapsulation.
- AES-GCM authentication tag appended to the TCP payload.
- TCP/IP checksum recalculation.
- TCP MSS clamping to 1400 bytes.
- Rejection of modified encrypted packets.
- Cached ciphertext for identical TCP retransmissions.

## Tests Performed

- HTTP GET request: 200 OK.
- Bidirectional encryption and decryption.
- 10,000-byte HTTP POST transmission.
- AES-GCM authentication tag verification.
- NFQUEUE handler rejection of tampered packets.
- TCP retransmission and conflicting-segment tests.
- Python syntax validation.

## Known Limitations

This is an educational prototype, not a production-ready VPN.

- Nonce uniqueness is not guaranteed across all TCP connection lifecycles.
- Replay protection is incomplete.
- Packet caches have no eviction policy.
- Session rekeying is not fully implemented.
- IP fragmentation and network offloading require additional testing.
- MSS clamping is configured for the demonstration topology.
- Only selected TCP/IPv4 traffic is protected.

The PSK must be provisioned separately and must never be committed to Git.