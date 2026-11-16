# server.py
# multithreaded tcp file server, one thread per client
# run with   python server.py
# add a user with   python server.py --adduser name password

import hashlib
import hmac
import json
import os
import secrets
import socket
import sys
import threading
import time
import uuid

import protocol as P
from analysis import StatsCollector, calc_mbps, print_summary

PORT = P.DEFAULT_PORT
STORAGE = os.path.abspath("server_storage")
USERS_FILE = "users.json"
INDEX_FILE = os.path.join(STORAGE, ".index.json")

#file type letter used in the logical name, anything else is O
TYPES = {".txt": "T", ".wav": "A", ".mp3": "A", ".mp4": "V", ".mkv": "V", ".avi": "V"}

index = {} # user path maps to {id, stored, size, sha256, owner}
counters = {"T": 0, "A": 0, "V": 0, "O": 0}
busy = {}# file maps to -1 while written or deleted, or a count of downloads
lock = threading.Lock()
stats = StatsCollector("server_stats.csv")


#users
def add_user(name, password):
    #only the salt and derived key are stored, never the password
    users = json.load(open(USERS_FILE)) if os.path.exists(USERS_FILE) else {}
    salt = secrets.token_hex(16)
    users[name] = {"salt": salt, "key": P.derive_key(password, salt)}
    json.dump(users, open(USERS_FILE, "w"), indent=2)


#files
def save_index():
    json.dump({"files": index, "counters": counters}, open(INDEX_FILE, "w"), indent=1)


def clean(path):
    #normalise the path and refuse anything that could climb out of storage
    parts = [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." or p.startswith(".") or ":" in p for p in parts):
        raise ValueError("invalid path")
    return "/".join(parts)


def real_dir(rel):
    return os.path.join(STORAGE, *rel.split("/")) if rel else STORAGE


def take(key, write):
    #a write needs the file to itself, downloads can share it
    with lock:
        v = busy.get(key, 0)
        if write and v == 0:
            busy[key] = -1
        elif not write and v >= 0:
            busy[key] = v + 1
        else:
            return False
        return True


def give(key):
    with lock:
        v = busy.get(key, 0)
        if v <= 1:
            busy.pop(key, None)
        else:
            busy[key] = v - 1


#one client
def handle_client(conn, addr):
    users = json.load(open(USERS_FILE))
    state = {"user": None, "pending": None, "nonce": None, "t0": 0, "resp": None}
    print(f"[+] {addr} connected")

    def reply(**kw):
        # response time is command received until first reply sent
        if state["resp"] is None:
            state["resp"] = round((time.perf_counter() - state["t0"]) * 1000, 3)
        P.send_msg(conn, kw)

    def error(msg, code="ERROR"):
        reply(status="ERROR", code=code, msg=msg)

    def log(op, file="", nbytes=0, secs=0.0, status="OK"):
        stats.record(source="server", user=state["user"] or "", client_ip=addr[0], op=op, file=file,
                     bytes=nbytes, transfer_s=round(secs, 4), mbps=calc_mbps(nbytes, secs),
                     resp_ms=state["resp"], status=status)

    try:
        state["t0"] = time.perf_counter()
        reply(status="OK", msg="Connected. Please LOGIN.")
        while True:
            msg = P.recv_msg(conn)
            state["t0"], state["resp"] = time.perf_counter(), None
            cmd = str(msg.get("cmd", "")).upper()

            #login in two steps so the password never crosses the network
            if cmd == "AUTH_START":
                rec = users.get(msg.get("user", ""))
                state["pending"], state["nonce"] = msg.get("user", ""), secrets.token_hex(16)
                reply(status="OK", nonce=state["nonce"], iterations=P.PBKDF2_ITERATIONS,
                      salt=rec["salt"] if rec else secrets.token_hex(16))
                continue
            if cmd == "AUTH_PROOF":
                rec, nonce, state["nonce"] = users.get(state["pending"]), state["nonce"], None
                if rec and nonce and hmac.compare_digest(P.make_proof(rec["key"], nonce), msg.get("proof", "")):
                    state["user"] = state["pending"]
                    reply(status="OK", msg=f"Welcome, {state['user']}")
                    log("LOGIN")
                else:
                    error("Invalid username or password", "AUTH")
                    log("LOGIN", status="FAIL")
                continue
            if cmd == "LOGOUT":
                reply(status="OK", msg="Goodbye")
                break
            if not state["user"]:
                error("Authentication required", "AUTH")
                continue

            #upload
            if cmd == "UPLOAD":
                key, size = clean(msg["path"]), int(msg["size"])
                if not key or not os.path.isdir(real_dir(os.path.dirname(key))):
                    error("Remote folder does not exist")
                    continue
                if not take(key, True):
                    error("File is currently being processed by another client", "BUSY")
                    continue
                tmp = None
                try:
                    #ask before replacing a file that already exists
                    if key in index:
                        reply(status="EXISTS", msg=f"'{key}' already exists on the server")
                        if not P.recv_msg(conn).get("overwrite"):
                            reply(status="CANCELLED", msg="Upload cancelled")
                            continue
                    tmp = os.path.join(real_dir(os.path.dirname(key)), ".tmp_" + uuid.uuid4().hex)
                    reply(status="READY")
                    h, left, t0 = hashlib.sha256(), size, time.perf_counter()
                    with open(tmp, "wb") as f:               # chunks go to disk, not memory
                        while left > 0:
                            chunk = conn.recv(min(P.CHUNK, left))
                            if not chunk:
                                raise ConnectionError("client left during upload")
                            f.write(chunk)
                            h.update(chunk)
                            left -= len(chunk)
                    secs = time.perf_counter() - t0
                    with lock:
                        old = index.get(key)
                        if old:
                            fid = old["id"]                   # overwrite keeps the same id
                        else:
                            t = TYPES.get(os.path.splitext(key)[1].lower(), "O")
                            counters[t] += 1
                            fid = f"{t}S{counters[t]:03d}"    # for example TS001
                        stored = f"{fid}_{os.path.basename(key)}"
                        os.replace(tmp, os.path.join(os.path.dirname(tmp), stored))
                        tmp = None
                        index[key] = {"id": fid, "stored": stored, "size": size,
                                      "sha256": h.hexdigest(), "owner": state["user"]}
                        save_index()
                    P.send_msg(conn, {"status": "OK", "id": fid, "sha256": h.hexdigest(), "msg": f"Stored as {stored}"})
                    log("UPLOAD", key, size, secs)
                finally:
                    if tmp and os.path.exists(tmp):
                        os.remove(tmp)
                    give(key)

            #download, offset lets a client resume a broken download
            elif cmd == "DOWNLOAD":
                key = clean(msg["path"])
                entry = index.get(key)
                if not entry:
                    error("File does not exist on the server", "NOTFOUND")
                    continue
                offset = int(msg.get("offset", 0))
                if offset < 0 or offset > entry["size"]:
                    error("Invalid resume offset", "BAD_OFFSET")
                    continue
                if not take(key, False):
                    error("File is currently being uploaded", "BUSY")
                    continue
                try:
                    reply(status="OK", name=os.path.basename(key), size=entry["size"],
                          offset=offset, sha256=entry["sha256"])
                    t0 = time.perf_counter()
                    with open(os.path.join(real_dir(os.path.dirname(key)), entry["stored"]), "rb") as f:
                        sent = conn.sendfile(f, offset)
                    log("DOWNLOAD", key, sent, time.perf_counter() - t0)
                finally:
                    give(key)

            #delete
            elif cmd == "DELETE":
                key = clean(msg["path"])
                if key not in index:
                    error("File does not exist on the server", "NOTFOUND")
                elif not take(key, True):
                    error("File is currently being processed by another client", "BUSY")
                else:
                    with lock:
                        os.remove(os.path.join(real_dir(os.path.dirname(key)), index.pop(key)["stored"]))
                        save_index()
                    give(key)
                    reply(status="OK", msg=f"Deleted {key}")
                    log("DELETE", key)

            #dir
            elif cmd == "DIR":
                rel = clean(msg.get("path", ""))
                d = real_dir(rel)
                if not os.path.isdir(d):
                    error("Folder does not exist", "NOTFOUND")
                    continue
                folders = sorted(e.name for e in os.scandir(d) if e.is_dir() and not e.name.startswith("."))
                files = [{"name": os.path.basename(k), "id": e["id"], "size": e["size"], "owner": e["owner"],
                          "type": {"T": "text", "A": "audio", "V": "video", "O": "other"}[e["id"][0]]}
                         for k, e in sorted(index.items()) if os.path.dirname(k) == rel]
                reply(status="OK", path=rel, folders=folders, files=files)
                log("DIR", rel)

            #subfolder
            elif cmd == "SUBFOLDER":
                action, key = str(msg["action"]).lower(), clean(msg["path"])
                d = real_dir(key)
                if not key:
                    error("A folder path is required")
                elif action == "create" and os.path.exists(d):
                    error("Folder already exists")
                elif action == "create":
                    os.makedirs(d)
                    reply(status="OK", msg=f"Created folder '{key}'")
                    log("SUBFOLDER_CREATE", key)
                elif action == "delete" and not os.path.isdir(d):
                    error("Folder does not exist", "NOTFOUND")
                elif action == "delete" and os.listdir(d):
                    error("Folder is not empty")
                elif action == "delete":
                    os.rmdir(d)
                    reply(status="OK", msg=f"Deleted folder '{key}'")
                    log("SUBFOLDER_DELETE", key)
                else:
                    error("Use SUBFOLDER create or delete")

            #numbers measured by the client, stored with ours
            elif cmd == "STATS":
                stats.record(source="client", user=state["user"], client_ip=addr[0], op=msg.get("op", ""),
                             file=msg.get("file", ""), bytes=msg.get("bytes", 0),
                             transfer_s=msg.get("transfer_s", 0), mbps=msg.get("mbps", 0),
                             resp_ms=msg.get("resp_ms", ""), status=msg.get("status", "OK"))
                reply(status="OK")
            else:
                error(f"Unknown command: {cmd}")

    except (ConnectionError, socket.timeout, ValueError, KeyError) as e:
        print(f"[!] {addr} {e}")
    finally:
        conn.close()
        print(f"[-] {addr} disconnected")


#main
def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--adduser":
        add_user(sys.argv[2], sys.argv[3])
        print("user saved")
        return
    if not os.path.exists(USERS_FILE):
        add_user("student", "cnt3004")
        print("created demo user student / cnt3004")

    os.makedirs(STORAGE, exist_ok=True)
    if os.path.exists(INDEX_FILE):
        data = json.load(open(INDEX_FILE))
        index.update(data["files"])
        counters.update(data["counters"])

    stats.start() # analysis starts with the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", PORT))
    server.listen()
    print(f"listening on port {PORT}, ctrl+c to stop")
    try:
        while True:
            conn, addr = server.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        print_summary(stats.summary())
        stats.stop()


if __name__ == "__main__":
    main()
