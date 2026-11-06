import hashlib
import hmac
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from handshake import server
from secure_packet import decrypt_tcp_packet

SESSION_KEY = None

def nonce_for(packet, key):
    ip = IP(packet)
    tcp = ip[TCP]
    identity = (
        ip.src.encode() + b"|" +
        ip.dst.encode() + b"|" +
        tcp.sport.to_bytes(2, "big") +
        tcp.dport.to_bytes(2, "big") +
        tcp.seq.to_bytes(4, "big")
    )
    return hmac.new(key, b"nonce-v1|" + identity, hashlib.sha256).digest()[:12]

def process_packet(packet):
    try:
        original = packet.get_payload()
        ip = IP(original)

        if not ip.haslayer(TCP):
            packet.accept()
            return

        tcp = ip[TCP]
        payload = bytes(tcp.payload)

        if ip.src != "10.0.1.2" or ip.dst != "10.0.3.2" or tcp.dport != 8080 or not payload:
            packet.accept()
            return

        nonce = nonce_for(original, SESSION_KEY)
        decrypted = decrypt_tcp_packet(original, SESSION_KEY, nonce)

        packet.set_payload(decrypted)
        packet.accept()
        print(f"Device2: authenticated and decrypted {len(payload) - 16} bytes", flush=True)

    except Exception as error:
        print(f"Device2: authentication/decryption failed: {error}", flush=True)
        packet.drop()

def main():
    global SESSION_KEY
    print("Device2: starting handshake...", flush=True)
    SESSION_KEY = server()
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
