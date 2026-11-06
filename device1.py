import hashlib
import hmac
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP
from handshake import client
from secure_packet import encrypt_tcp_packet

SESSION_KEY = None
CACHE = {}

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
        identity = (ip.src, ip.dst, tcp.sport, tcp.dport, tcp.seq)
        digest = hashlib.sha256(payload).digest()

        if identity in CACHE:
            previous_digest, encrypted = CACHE[identity]
            if previous_digest != digest:
                print("Device1: conflicting TCP sequence; dropping", flush=True)
                packet.drop()
                return
        else:
            encrypted = encrypt_tcp_packet(original, SESSION_KEY, nonce)
            CACHE[identity] = (digest, encrypted)

        packet.set_payload(encrypted)
        packet.accept()
        print(f"Device1: encrypted {len(payload)} bytes", flush=True)

    except Exception as error:
        print(f"Device1 error: {error}", flush=True)
        packet.drop()

def main():
    global SESSION_KEY
    print("Device1: starting handshake...", flush=True)
    SESSION_KEY = client()
    print("Device1: secure session ready", flush=True)

    queue = NetfilterQueue()
    queue.bind(1, process_packet)
    print("Device1: waiting for packets...", flush=True)
    try:
        queue.run()
    except KeyboardInterrupt:
        pass
    finally:
        queue.unbind()

if __name__ == "__main__":
    main()
