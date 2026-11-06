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

## Limitations

This is an educational prototype, not a production-ready VPN.

Nonce derivation uses TCP flow identifiers and sequence numbers. Retransmitted identical segments reuse cached ciphertext rather than performing a new encryption. Conflicting payloads with the same segment identity are dropped.

The implementation does not provide general replay protection, full TCP sequence-reuse handling, robust session rekeying, IP fragmentation handling, or complete MTU/MSS management.

The demonstration currently protects selected client-to-server TCP payloads only. It does not encrypt the reverse HTTP response.

The PSK file must be provisioned separately and must never be committed to Git.

## Implemented Features

- Linux network namespaces simulating PC1, Device1, Device2, and PC2.
- Inline TCP/IPv4 packet processing using NetfilterQueue.
- Authenticated X25519 Diffie-Hellman key exchange.
- Session key derivation using HKDF.
- Separate AES-GCM keys for both traffic directions.
- Encryption of TCP payloads without UDP encapsulation or custom protocol headers.
- AES-GCM authentication tag appended to encrypted TCP payloads.
- TCP payload decryption and packet checksum recalculation.
- TCP MSS clamping to accommodate the authentication tag.
- Detection and rejection of modified encrypted packets.
- Cached ciphertext for identical TCP retransmissions.

## Tests Performed

- Successful HTTP GET request and response.
- Bidirectional AES-GCM encryption and decryption.
- Transmission of a 10,000-byte HTTP POST request.
- AES-GCM authentication tag verification.
- Rejection of tampered packets by the Device2 NFQUEUE handler.
- Identical TCP retransmission handling.
- Rejection of conflicting TCP segments.
- Python syntax validation.

## Known Limitations

This is an educational prototype, not a production-ready VPN or security appliance.

- The nonce derivation scheme does not guarantee uniqueness across every possible TCP connection lifecycle.
- Packet caches grow without a defined eviction policy.
- Replay protection is incomplete.
- The implementation targets selected TCP/IPv4 traffic, not arbitrary network protocols.
- Additional testing is required for packet loss, fragmentation, offloading, and session rekeying.
