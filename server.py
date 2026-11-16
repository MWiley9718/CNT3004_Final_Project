# server.py
# multithreaded tcp file server for the cnt3004 final project
#
#   python server.py                       starts on 0.0.0.0 port 4450
#   python server.py --adduser bob pw123   makes or updates a user then quits
#
# how it works in short
# every client gets its own thread so people can upload and download at the same time
# files sit in ./server_storage and get a logical name like TS001_notes.txt
# the first letter is the type, T for text, A for audio, V for video, O for other
# the S just means it lives on the server
# a small json index remembers the real name, size, sha256 and who uploaded it
# files in use are locked so nobody can delete a file while it is moving
# the analysis module starts up right alongside the server

import argparse
import hashlib
import hmac
import json
import os
import secrets
import socket
import threading
import time
import uuid

import protocol as P
from analysis import StatsCollector, calc_mbps

STORAGE_DIR = "server_storage"
USERS_FILE = "users.json"

# extension to type letter, anything not listed becomes O
TYPE_MAP = {".txt": "T", ".md": "T", ".csv": "T", ".log": "T",
            ".wav": "A", ".mp3": "A", ".flac": "A", ".aac": "A",
            ".mp4": "V", ".mkv": "V", ".avi": "V", ".mov": "V"}
MAX_AUTH_FAILS = 3

# random key so a made up username still gets the same fake salt every time
# that way nobody can tell real usernames from fake ones
FAKE_SALT_KEY = secrets.token_bytes(16)


# ---------------------------------------------------------------- user database
def load_users():
    # no file yet just means no users yet
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}


def add_user(name, password):
    # only the salt and the derived key get saved, never the password itself
    users = load_users()
    salt = secrets.token_hex(16)
    users[name] = {"salt": salt, "iterations": P.PBKDF2_ITERATIONS,
                   "key": P.derive_key(password, salt)}
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


# ------------------------------------------------------------------- file store
class FileStore:
    # keeps track of every file, hands out the logical names and does the locking

    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.lock = threading.RLock()
        self.index_path = os.path.join(self.root, ".index.json")
        self.index = {}                                  # path the user sees maps to its entry
        self.counters = {"T": 0, "A": 0, "V": 0, "O": 0}
        self.readers = {}                                # how many downloads are running per file
        self.writing = set()                             # files being uploaded or deleted right now
        # pick up where we left off if the server was restarted
        if os.path.exists(self.index_path):
            with open(self.index_path) as f:
                data = json.load(f)
            self.index, self.counters = data["files"], data["counters"]

    def _save(self):
        # write to a temp file first so a crash cant leave a half written index
        tmp = self.index_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"files": self.index, "counters": self.counters}, f, indent=1)
        os.replace(tmp, self.index_path)

    # ---- path safety
    @staticmethod
    def norm(rel):
        # clean up the path and refuse anything sneaky like .. or hidden names
        parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
        if any(p == ".." or p.startswith(".") or ":" in p for p in parts):
            raise ValueError("Invalid path")
        return "/".join(parts)

    def abs_dir(self, rel):
        # turn a relative path into a real one and make sure it stays inside storage
        rel = self.norm(rel)
        p = os.path.abspath(os.path.join(self.root, *rel.split("/"))) if rel else self.root
        if p != self.root and not p.startswith(self.root + os.sep):
            raise ValueError("Invalid path")
        return p

    # ---- lookup and naming
    def find(self, name):
        # people can ask for a file by its path or by its id like TS001
        key = self.norm(name)
        with self.lock:
            if key in self.index:
                return key, self.index[key]
            for k, e in self.index.items():
                if e["id"].lower() == key.lower():
                    return k, e
        return None, None

    def stored_path(self, key, entry):
        return os.path.join(self.abs_dir(os.path.dirname(key)), entry["stored"])

    # ---- locking
    def acquire(self, key, write=False):
        # many downloads at once is fine but a write needs the file to itself
        with self.lock:
            if key in self.writing:
                return False
            if write:
                if self.readers.get(key, 0) > 0:
                    return False
                self.writing.add(key)
            else:
                self.readers[key] = self.readers.get(key, 0) + 1
            return True

    def release(self, key, write=False):
        with self.lock:
            if write:
                self.writing.discard(key)
            else:
                self.readers[key] = self.readers.get(key, 1) - 1
                if self.readers[key] <= 0:
                    self.readers.pop(key, None)

    # ---- changes
    def commit(self, key, tmp_path, size, sha, owner):
        # move the finished upload into place and record it in the index
        with self.lock:
            old = self.index.get(key)
            base = os.path.basename(key)
            if old:
                fid = old["id"]                         # overwriting keeps the same id
            else:
                t = TYPE_MAP.get(os.path.splitext(base)[1].lower(), "O")
                self.counters[t] += 1
                fid = f"{t}S{self.counters[t]:03d}"
            stored = f"{fid}_{base}"
            os.replace(tmp_path, os.path.join(os.path.dirname(tmp_path), stored))
            entry = {"id": fid, "stored": stored, "size": size, "sha256": sha, "owner": owner,
                     "uploaded": time.strftime("%Y-%m-%d %H:%M:%S")}
            self.index[key] = entry
            self._save()
            return entry

    def delete(self, key):
        # gives back a pair, whether it worked and a message to show the user
        if not self.acquire(key, write=True):
            return False, "File is currently being processed by another client"
        try:
            with self.lock:
                entry = self.index.get(key)
                if not entry:
                    return False, "File not found"
                try:
                    os.remove(self.stored_path(key, entry))
                except FileNotFoundError:
                    pass                                # already gone from disk so just clean the index
                del self.index[key]
                self._save()
            return True, f"Deleted {key}"
        finally:
            self.release(key, write=True)

    def listing(self, rel):
        # folders come from the real disk and files come from the index
        d = self.abs_dir(rel)
        if not os.path.isdir(d):
            raise FileNotFoundError("Folder does not exist")
        rel = self.norm(rel)
        folders = sorted(e.name for e in os.scandir(d) if e.is_dir() and not e.name.startswith("."))
        files = []
        with self.lock:
            for key, e in sorted(self.index.items()):
                if os.path.dirname(key) == rel:
                    files.append({"name": os.path.basename(key), "id": e["id"],
                                  "size": e["size"], "owner": e["owner"],
                                  "type": {"T": "text", "A": "audio", "V": "video", "O": "other"}[e["id"][0]]})
        return folders, files


# --------------------------------------------------------------- client session
class Session:
    # one of these runs in its own thread for every connected client

    def __init__(self, conn, addr, store, users, stats):
        self.conn, self.addr, self.store, self.users, self.stats = conn, addr, store, users, stats
        self.user = None
        self.pending_user = None
        self.nonce = None
        self.fails = 0
        self.t_cmd = time.perf_counter()
        self.resp_ms = None

    # ---- helpers
    def reply(self, **kw):
        # the first reply to a command decides the response time we log
        if self.resp_ms is None:
            self.resp_ms = round((time.perf_counter() - self.t_cmd) * 1000, 3)
        P.send_msg(self.conn, kw)

    def error(self, msg, code="ERROR"):
        self.reply(status="ERROR", code=code, msg=msg)

    def log(self, op, file="", nbytes=0, secs=0.0, status="OK"):
        self.stats.record(source="server", user=self.user or "", client_ip=self.addr[0], op=op,
                          file=file, bytes=nbytes, transfer_s=round(secs, 4), resp_ms=self.resp_ms,
                          mbps=calc_mbps(nbytes, secs), status=status)

    # ---- main loop
    def run(self):
        print(f"[+] {self.addr} connected")
        self.reply(status="OK", msg="Connected to CNT3004 file server. Please LOGIN.")
        try:
            while True:
                msg = P.recv_msg(self.conn)
                self.t_cmd, self.resp_ms = time.perf_counter(), None
                cmd = str(msg.get("cmd", "")).upper()
                # nothing works until the client has logged in
                if not self.user and cmd not in ("AUTH_START", "AUTH_PROOF", "LOGOUT"):
                    self.error("Authentication required", "AUTH")
                    continue
                # every command maps to a do_ method so adding one is easy
                fn = getattr(self, "do_" + cmd.lower(), None)
                if fn is None:
                    self.error(f"Unknown command: {cmd}")
                    continue
                try:
                    if fn(msg) == "CLOSE":
                        break
                except (ConnectionError, socket.timeout):
                    raise
                except (ValueError, KeyError, TypeError) as e:
                    self.error(f"Bad request: {e}")
                except OSError as e:
                    self.error(f"Server I/O error: {e}")
        except (ConnectionError, socket.timeout) as e:
            print(f"[!] {self.addr} connection lost: {e}")
        finally:
            self.conn.close()
            print(f"[-] {self.addr} disconnected ({self.user or 'unauthenticated'})")

    # ---- authentication
    def do_auth_start(self, msg):
        # step one, hand the client the salt and a fresh random nonce
        name = str(msg.get("user", ""))
        rec = self.users.get(name)
        salt = rec["salt"] if rec else hmac.new(FAKE_SALT_KEY, name.encode(), hashlib.sha256).hexdigest()[:32]
        self.pending_user, self.nonce = name, secrets.token_hex(16)
        self.reply(status="OK", salt=salt, nonce=self.nonce,
                   iterations=rec["iterations"] if rec else P.PBKDF2_ITERATIONS)

    def do_auth_proof(self, msg):
        # step two, check the proof the client built from the nonce
        rec = self.users.get(self.pending_user or "")
        nonce, self.nonce = self.nonce, None             # nonce only works once so replays fail
        ok = False
        if rec and nonce:
            expected = P.make_proof(rec["key"], nonce)
            ok = hmac.compare_digest(expected, str(msg.get("proof", "")))
        if ok:
            self.user, self.fails = self.pending_user, 0
            self.reply(status="OK", msg=f"Welcome, {self.user}")
            self.log("LOGIN")
            print(f"[auth] {self.addr} logged in as {self.user}")
        else:
            self.fails += 1
            self.log("LOGIN", status="FAIL")
            self.error("Invalid username or password", "AUTH")
            print(f"[auth] {self.addr} FAILED login ({self.fails}/{MAX_AUTH_FAILS})")
            # too many misses and we hang up on this connection
            if self.fails >= MAX_AUTH_FAILS:
                return "CLOSE"

    def do_logout(self, msg):
        self.reply(status="OK", msg="Goodbye")
        self.log("LOGOUT")
        return "CLOSE"

    # ---- upload, client sends to server
    def do_upload(self, msg):
        key, size = self.store.norm(msg["path"]), int(msg["size"])
        if not key or size < 0:
            return self.error("Invalid file name or size")
        parent = os.path.dirname(key)
        if not os.path.isdir(self.store.abs_dir(parent)):
            return self.error("Remote folder does not exist")
        # grab the write lock so two people cant upload the same name together
        if not self.store.acquire(key, write=True):
            return self.error("File is currently being processed by another client", "BUSY")
        tmp = None
        try:
            # file already there so ask the client if it really wants to replace it
            if key in self.store.index:
                self.reply(status="EXISTS", msg=f"'{key}' already exists on the server")
                if not P.recv_msg(self.conn).get("overwrite"):
                    self.reply(status="CANCELLED", msg="Upload cancelled")
                    return
            tmp = os.path.join(self.store.abs_dir(parent), ".tmp_" + uuid.uuid4().hex)
            self.reply(status="READY")
            h, remaining, t0 = hashlib.sha256(), size, time.perf_counter()
            # write straight to disk in chunks so a 2gb file never sits in memory
            with open(tmp, "wb") as f:
                while remaining > 0:
                    chunk = self.conn.recv(min(P.CHUNK, remaining))
                    if not chunk:
                        raise ConnectionError("Client disconnected during upload")
                    f.write(chunk)
                    h.update(chunk)
                    remaining -= len(chunk)
            secs = time.perf_counter() - t0
            entry = self.store.commit(key, tmp, size, h.hexdigest(), self.user)
            tmp = None
            P.send_msg(self.conn, {"status": "OK", "id": entry["id"], "sha256": entry["sha256"],
                                   "msg": f"Stored as {entry['stored']}"})
            self.log("UPLOAD", key, size, secs)
            print(f"[upload] {self.user}: {key} ({size/P.CHUNK:.1f} MB, {calc_mbps(size, secs)} MB/s)")
        except ConnectionError:
            self.log("UPLOAD", key, status="ABORTED")
            raise
        finally:
            # throw away any half finished temp file and let go of the lock
            if tmp and os.path.exists(tmp):
                os.remove(tmp)
            self.store.release(key, write=True)

    # ---- download, server sends to client, offset lets a client resume
    def do_download(self, msg):
        key, entry = self.store.find(msg["path"])
        if not entry:
            return self.error("File does not exist on the server", "NOTFOUND")
        offset = int(msg.get("offset", 0))
        if offset < 0 or offset > entry["size"]:
            return self.error("Invalid resume offset", "BAD_OFFSET")
        path = self.store.stored_path(key, entry)
        if not os.path.isfile(path):
            return self.error("File missing from server storage")
        if not self.store.acquire(key):
            return self.error("File is currently being uploaded", "BUSY")
        try:
            # tell the client the size and hash first so it knows what to expect
            self.reply(status="OK", name=os.path.basename(key), size=entry["size"],
                       offset=offset, sha256=entry["sha256"])
            t0 = time.perf_counter()
            # sendfile lets the os push the bytes out starting from the offset
            with open(path, "rb") as f:
                sent = self.conn.sendfile(f, offset)
            secs = time.perf_counter() - t0
            self.log("DOWNLOAD", key, sent, secs)
            print(f"[download] {self.user}: {key} from byte {offset} ({sent/P.CHUNK:.1f} MB, {calc_mbps(sent, secs)} MB/s)")
        except (ConnectionError, socket.timeout):
            self.log("DOWNLOAD", key, status="ABORTED")
            raise
        finally:
            self.store.release(key)

    # ---- delete, dir and subfolder
    def do_delete(self, msg):
        key, entry = self.store.find(msg["path"])
        if not entry:
            return self.error("File does not exist on the server", "NOTFOUND")
        ok, text = self.store.delete(key)
        (self.reply(status="OK", msg=text) if ok else self.error(text, "BUSY"))
        self.log("DELETE", key, status="OK" if ok else "FAIL")

    def do_dir(self, msg):
        try:
            folders, files = self.store.listing(msg.get("path", ""))
        except FileNotFoundError as e:
            return self.error(str(e), "NOTFOUND")
        self.reply(status="OK", path=self.store.norm(msg.get("path", "")), folders=folders, files=files)
        self.log("DIR", msg.get("path", ""))

    def do_subfolder(self, msg):
        action, key = str(msg["action"]).lower(), self.store.norm(msg["path"])
        if not key:
            return self.error("A folder path is required")
        target = self.store.abs_dir(key)
        if action == "create":
            if os.path.exists(target):
                return self.error("Folder already exists")
            os.makedirs(target)
            self.reply(status="OK", msg=f"Created folder '{key}'")
        elif action == "delete":
            if not os.path.isdir(target):
                return self.error("Folder does not exist", "NOTFOUND")
            # rmdir only works on empty folders which is exactly what we want
            try:
                os.rmdir(target)
            except OSError:
                return self.error("Folder is not empty")
            self.reply(status="OK", msg=f"Deleted folder '{key}'")
        else:
            return self.error("Use: SUBFOLDER create|delete <path>")
        self.log("SUBFOLDER_" + action.upper(), key)

    # ---- numbers the client measured on its side, saved next to ours
    def do_stats(self, msg):
        self.stats.record(source="client", user=self.user, client_ip=self.addr[0], op=msg.get("op", ""),
                          file=msg.get("file", ""), bytes=msg.get("bytes", 0),
                          transfer_s=msg.get("transfer_s", 0), mbps=msg.get("mbps", 0),
                          resp_ms=msg.get("resp_ms", ""), status=msg.get("status", "OK"))
        self.reply(status="OK")


# ------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0", help="interface to bind (0.0.0.0 = all)")
    ap.add_argument("--port", type=int, default=P.DEFAULT_PORT)
    ap.add_argument("--adduser", nargs=2, metavar=("USER", "PASSWORD"))
    args = ap.parse_args()

    # adduser is a quick one shot job so do it and leave
    if args.adduser:
        add_user(*args.adduser)
        print(f"User '{args.adduser[0]}' saved to {USERS_FILE}")
        return
    # first run with no users gets a demo account so you can log in right away
    if not load_users():
        add_user("student", "cnt3004")
        print("No users found - created demo user  student / cnt3004")

    users = load_users()
    store = FileStore(STORAGE_DIR)
    stats = StatsCollector("server_stats.csv").start()   # the analysis side boots with the server

    # plain ipv4 tcp socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen()
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip = "?"
    print(f"Server listening on {args.host}:{args.port}  (clients should use this machine's LAN IP, e.g. {ip})")
    print("Press Ctrl+C to stop and print the performance summary.")
    try:
        while True:
            conn, addr = server.accept()
            # long timeout because idle clients just sit at the prompt, keepalive drops dead ones
            conn.settimeout(1800)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            # new thread per client so they dont block each other
            threading.Thread(target=Session(conn, addr, store, users, stats).run, daemon=True).start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.close()
        from analysis import print_summary
        print_summary(stats.summary())
        stats.stop()


if __name__ == "__main__":
    main()
