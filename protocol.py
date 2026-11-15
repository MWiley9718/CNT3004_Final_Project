import hashlib
import hmac
import json
import socket
import struct



DEFAULT_PORT = 4450
CHUNK = 1024 * 1024            
PBKDF2_ITERATIONS = 200_000
MAX_CONTROL_MSG= 1024 * 1024


def send_msg(sock: socket.socket, obj: dict) -> None:
    """This sends a JSON control message."""
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data))+data)



def recv_exact(sock: socket.socket, n: int) -> bytes:
    """This reads exactly n bytes """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed by peer")
        buf += chunk
    return bytes(buf)


def recv_msg(sock: socket.socket) -> dict:
    """Receive JSON message."""
    (length,) = struct.unpack("!I", recv_exact(sock, 4))
    if length > MAX_CONTROL_MSG:
        raise ConnectionError("Control message too large")
    return json.loads(recv_exact(sock, length).decode("utf-8"))



def derive_key(password: str, salt_hex: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """This the hex key stores plus salt."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt_hex), iterations).hex()


def make_proof(key_hex: str, nonce_hex: str) -> str:
    """HMAC"""
    return hmac.new(bytes.fromhex(key_hex), bytes.fromhex(nonce_hex), hashlib.sha256).hexdigest()



def sha256_file(path: str) -> str:
    """ This is the SHA-256 of file"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()
