import hashlib
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP

from handshake import server
from session_keys import derive_direction_keys
from bidirectional_crypto import encrypt_packet, decrypt_packet
from packet_nonce import derive_packet_nonce

KEYS = {}
CACHE = {}
USED_NONCES = {}


def process_packet(packet):
    try:
        original = packet.get_payload()
        ip = IP(original)

        if not ip.haslayer(TCP):
            packet.accept()
            return

        tcp = ip[TCP]
        payload = bytes(tcp.payload)

        if not payload:
            packet.accept()
            return

        if ip.src == "10.0.1.2" and ip.dst == "10.0.3.2" and tcp.dport == 8080:
            direction = "pc1_to_pc2"

            decrypted = decrypt_packet(
                original,
                KEYS[direction],
                direction
            )

            packet.set_payload(decrypted)
            packet.accept()

            print(
                f"Device2: decrypted {len(payload) - 16} bytes",
                flush=True
            )
            return

        if ip.src == "10.0.3.2" and ip.dst == "10.0.1.2" and tcp.sport == 8080:
            direction = "pc2_to_pc1"
            key = KEYS[direction]

            identity = (
                ip.src, ip.dst,
                tcp.sport, tcp.dport, tcp.seq
            )

            digest = hashlib.sha256(payload).digest()

            if identity in CACHE:
                old_digest, encrypted = CACHE[identity]

                if old_digest != digest:
                    print("Device2: conflicting TCP segment", flush=True)
                    packet.drop()
                    return
            else:
                nonce = derive_packet_nonce(original, key, direction)

                if nonce in USED_NONCES:
                    print("Device2: nonce reuse blocked", flush=True)
                    packet.drop()
                    return

                encrypted = encrypt_packet(original, key, direction)

                USED_NONCES[nonce] = identity
                CACHE[identity] = (digest, encrypted)

            packet.set_payload(encrypted)
            packet.accept()

            print(
                f"Device2: encrypted {len(payload)} bytes",
                flush=True
            )
            return

        packet.accept()

    except Exception as error:
        print(f"Device2 error: {error}", flush=True)
        packet.drop()


def main():
    global KEYS

    print("Device2: starting handshake...", flush=True)

    session_key = server()
    KEYS = derive_direction_keys(session_key)

    print("Device2: secure session ready", flush=True)

    queue = NetfilterQueue()
    queue.bind(2, process_packet)

    print("Device2: waiting for packets...", flush=True)

    try:
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        queue.unbind()


if __name__ == "__main__":
    main()
