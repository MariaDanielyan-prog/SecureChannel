
import argparse
import hashlib
import hmac
import os
import socket
from pathlib import Path

from crypto_utils import (
    generate_keypair,
    public_key_to_bytes,
    derive_session_key,
)

PORT = 9000
SERVER_IP = "10.0.2.2"
PSK_PATH = Path(__file__).resolve().parent / "psk.key"

PROTOCOL_ID = b"SecureChannel-v1-authenticated"
CLIENT_CONFIRM = b"SecureChannel-v1-client-confirm"
SERVER_CONFIRM = b"SecureChannel-v1-server-confirm"


def receive_exact(sock, length):
    data = bytearray()

    while len(data) < length:
        chunk = sock.recv(length - len(data))

        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")

        data.extend(chunk)

    return bytes(data)


def load_psk():
    psk = PSK_PATH.read_bytes()

    if len(psk) != 32:
        raise ValueError("PSK must be exactly 32 bytes")

    return psk


def make_transcript(client_public, server_public, salt):
    return (
        PROTOCOL_ID
        + client_public
        + server_public
        + salt
    )


def make_proof(psk, role, transcript):
    return hmac.new(
        psk,
        role + transcript,
        hashlib.sha256
    ).digest()


def confirm_session_key(sock, session_key, transcript, role):
    if role == "client":
        client_proof = hmac.new(
            session_key,
            CLIENT_CONFIRM + transcript,
            hashlib.sha256
        ).digest()

        sock.sendall(client_proof)

        server_proof = receive_exact(sock, 32)

        expected = hmac.new(
            session_key,
            SERVER_CONFIRM + transcript,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(server_proof, expected):
            raise ValueError("Server key confirmation failed")

    else:
        client_proof = receive_exact(sock, 32)

        expected = hmac.new(
            session_key,
            CLIENT_CONFIRM + transcript,
            hashlib.sha256
        ).digest()

        if not hmac.compare_digest(client_proof, expected):
            raise ValueError("Client key confirmation failed")

        server_proof = hmac.new(
            session_key,
            SERVER_CONFIRM + transcript,
            hashlib.sha256
        ).digest()

        sock.sendall(server_proof)

    print("Session key confirmed!", flush=True)


def server():
    psk = load_psk()
    private_key, public_key = generate_keypair()
    server_public = public_key_to_bytes(public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )

        listener.bind((SERVER_IP, PORT))
        listener.listen(1)

        print("Device2: waiting for handshake...", flush=True)

        connection, address = listener.accept()

        with connection:
            connection.settimeout(10)

            print(f"Device2: connected to {address}")

            client_public = receive_exact(connection, 32)
            salt = receive_exact(connection, 32)

            transcript = make_transcript(
                client_public,
                server_public,
                salt
            )

            server_proof = make_proof(
                psk,
                b"server-auth",
                transcript
            )

            connection.sendall(server_public + server_proof)

            client_proof = receive_exact(connection, 32)

            expected = make_proof(
                psk,
                b"client-auth",
                transcript
            )

            if not hmac.compare_digest(client_proof, expected):
                raise ValueError("Device1 authentication failed")

            print("PSK authentication successful!", flush=True)

            session_key = derive_session_key(
                private_key,
                client_public,
                salt
            )

            confirm_session_key(
                connection,
                session_key,
                transcript,
                "server"
            )

            print("Device2: secure session established!", flush=True)

            return session_key


def client():
    psk = load_psk()
    private_key, public_key = generate_keypair()
    client_public = public_key_to_bytes(public_key)
    salt = os.urandom(32)

    with socket.create_connection(
        (SERVER_IP, PORT),
        timeout=10
    ) as connection:
        print("Device1: connected to Device2")

        connection.sendall(client_public + salt)

        server_public = receive_exact(connection, 32)
        server_proof = receive_exact(connection, 32)

        transcript = make_transcript(
            client_public,
            server_public,
            salt
        )

        expected = make_proof(
            psk,
            b"server-auth",
            transcript
        )

        if not hmac.compare_digest(server_proof, expected):
            raise ValueError("Device2 authentication failed")

        client_proof = make_proof(
            psk,
            b"client-auth",
            transcript
        )

        connection.sendall(client_proof)

        print("PSK authentication successful!", flush=True)

        session_key = derive_session_key(
            private_key,
            server_public,
            salt
        )

        confirm_session_key(
            connection,
            session_key,
            transcript,
            "client"
        )

        print("Device1: secure session established!", flush=True)

        return session_key


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "role",
        choices=["server", "client"]
    )

    args = parser.parse_args()

    if args.role == "server":
        server()
    else:
        client()
