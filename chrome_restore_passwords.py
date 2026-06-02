#!/usr/bin/env python3
"""chrome-restore-local-passwords-linux

Decrypt locally-stored Chrome/Chromium passwords on Linux and export them to
Chrome-importable CSV files — one CSV per browser profile.

Designed for the "I have my old disk mounted and want my passwords back" case:
point it at an old ``.config`` directory (and the matching old ``login.keyring``)
and it walks every profile of Google Chrome, Google Chrome Beta and Chromium,
decrypts the ``Login Data`` databases, and writes CSVs you can import via
``chrome://password-manager/settings`` -> Import.

Linux + GNOME Keyring (libsecret) only. Handles both encryption schemes used by
Chrome's OSCrypt on Linux:

  * ``v10`` blobs — key derived from the hardcoded "peanuts" password
    (used when the browser ran with ``--password-store=basic`` / no keyring).
  * ``v11`` blobs — key derived from the random "Chrome Safe Storage" /
    "Chromium Safe Storage" secret kept in the GNOME login keyring, which is
    itself unlocked by your login password.

Everything runs offline. Your login password is read with getpass and is never
printed, logged, or written anywhere.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import hashlib
import json
import os
import shutil
import sqlite3
import struct
import sys
import tempfile
from dataclasses import dataclass, field

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover
    sys.exit("error: the 'cryptography' package is required (pip install cryptography)")

# Browser key -> subdirectory of .config. Chrome stable/beta/dev all share the
# "Chrome Safe Storage" keyring secret; Chromium uses its own.
BROWSERS = {
    "google-chrome": "Chrome Safe Storage",
    "google-chrome-beta": "Chrome Safe Storage",
    "google-chrome-unstable": "Chrome Safe Storage",
    "chromium": "Chromium Safe Storage",
}

GNOME_KEYRING_MAGIC = b"GnomeKeyring\n\r\x00\n"


# --------------------------------------------------------------------------- #
# GNOME keyring (legacy file format) decoding
# --------------------------------------------------------------------------- #
class _Reader:
    """Big-endian reader for the gnome-keyring public header."""

    def __init__(self, data: bytes, offset: int = 0):
        self.d, self.o = data, offset

    def u8(self) -> int:
        v = self.d[self.o]
        self.o += 1
        return v

    def u32(self) -> int:
        v = struct.unpack_from(">I", self.d, self.o)[0]
        self.o += 4
        return v

    def u64(self) -> int:
        v = struct.unpack_from(">Q", self.d, self.o)[0]
        self.o += 8
        return v

    def raw(self, n: int) -> bytes:
        v = self.d[self.o:self.o + n]
        self.o += n
        return v

    def gstr(self):
        """gnome-keyring string: u32 length then bytes; 0xFFFFFFFF == NULL."""
        ln = self.u32()
        if ln == 0xFFFFFFFF:
            return None
        return self.raw(ln)


@dataclass
class Keyring:
    iterations: int
    salt: bytes
    encrypted: bytes


def parse_keyring(path: str) -> Keyring:
    data = open(path, "rb").read()
    if data[:16] != GNOME_KEYRING_MAGIC:
        raise ValueError(f"{path}: not a legacy GNOME keyring file")
    r = _Reader(data, 16)
    r.u8(); r.u8()              # version major / minor
    crypto = r.u8(); hashalg = r.u8()
    if crypto != 0 or hashalg != 0:
        raise ValueError(f"{path}: unsupported crypto={crypto} hash={hashalg}")
    r.gstr()                   # keyring display name
    r.u64(); r.u64()           # ctime / mtime
    r.u32(); r.u32()           # flags / lock_timeout
    iterations = r.u32()
    salt = r.raw(8)
    r.raw(16)                  # 4 reserved u32
    num_items = r.u32()
    for _ in range(num_items):  # public (unencrypted) attribute index
        r.u32(); r.u32()        # id / type
        for _ in range(r.u32()):
            r.gstr()            # attr name
            atype = r.u32()
            if atype == 0:
                r.gstr()        # string value
            elif atype == 1:
                r.u32()         # uint32 value
            else:
                raise ValueError(f"{path}: bad attribute type {atype}")
    enc_len = r.u32()          # encrypted region is length-prefixed
    encrypted = r.raw(enc_len)
    if len(encrypted) % 16 != 0:
        raise ValueError(f"{path}: encrypted region not block-aligned")
    return Keyring(iterations=iterations, salt=salt, encrypted=encrypted)


def _derive_keyring_key(password: bytes, salt: bytes, iterations: int):
    """egg_symkey_generate_simple(AES-128, SHA256): 16-byte key + 16-byte IV."""
    h = hashlib.sha256(password + salt).digest()
    for _ in range(1, iterations):
        h = hashlib.sha256(h).digest()
    return h[:16], h[16:32]


def _aes_cbc_decrypt(key: bytes, iv: bytes, ct: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(ct) + dec.finalize()


def unlock_keyring(kr: Keyring, password: bytes) -> bytes:
    """Decrypt the keyring body; raises on a wrong password."""
    key, iv = _derive_keyring_key(password, kr.salt, kr.iterations)
    plain = _aes_cbc_decrypt(key, iv, kr.encrypted)
    digest, body = plain[:16], plain[16:]
    if hashlib.md5(body).digest() != digest:
        raise ValueError("wrong login password (keyring MD5 verification failed)")
    return body


def extract_safe_storage_secrets(body: bytes) -> dict:
    """Find every '<Browser> Safe Storage' secret in the decrypted keyring.

    In a decrypted item the display-name string is immediately followed by the
    secret string, so we locate the length-prefixed label and read the next
    length-prefixed string after it.
    """
    secrets = {}
    for label in {v.encode() for v in BROWSERS.values()}:
        needle = struct.pack(">I", len(label)) + label
        i = body.find(needle)
        if i < 0:
            continue
        j = i + len(needle)
        slen = struct.unpack_from(">I", body, j)[0]
        secrets[label.decode()] = body[j + 4:j + 4 + slen]
    return secrets


# --------------------------------------------------------------------------- #
# Chrome OSCrypt password decryption
# --------------------------------------------------------------------------- #
def chrome_aes_key(safe_storage_password: bytes) -> bytes:
    """Linux OSCrypt: PBKDF2-HMAC-SHA1, salt 'saltysalt', 1 iter, 16-byte key."""
    return hashlib.pbkdf2_hmac("sha1", safe_storage_password, b"saltysalt", 1, 16)


def decrypt_password(blob: bytes, v11_key, v10_key) -> str:
    if not blob:
        return ""
    scheme, key = blob[:3], None
    if scheme == b"v11":
        key = v11_key
    elif scheme == b"v10":
        key = v10_key
    else:
        return ""  # not OSCrypt-encrypted (legacy plaintext) — handled by caller
    if key is None:
        return ""
    pt = _aes_cbc_decrypt(key, b" " * 16, blob[3:])
    if pt:  # strip PKCS7 padding
        pad = pt[-1]
        if 1 <= pad <= 16:
            pt = pt[:-pad]
    return pt.decode("utf-8", "replace")


def _looks_decrypted(blob: bytes, key: bytes) -> bool:
    """Heuristic: a correct key yields valid PKCS7 padding + clean UTF-8."""
    try:
        pt = _aes_cbc_decrypt(key, b" " * 16, blob[3:])
    except Exception:
        return False
    if not pt:
        return False
    pad = pt[-1]
    if not 1 <= pad <= 16 or len(pt) < pad:
        return False
    try:
        pt[:-pad].decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# --------------------------------------------------------------------------- #
# Profile discovery & export
# --------------------------------------------------------------------------- #
@dataclass
class Profile:
    browser: str          # e.g. "google-chrome-beta"
    folder: str           # e.g. "Default" / "Profile 3"
    display_name: str     # e.g. "devstuff"
    login_db: str


# Non-user pseudo-profiles Chrome keeps next to real ones.
SKIP_FOLDERS = {"System Profile", "Guest Profile"}


def discover_profiles(config_dir: str, browsers) -> list:
    profiles = []
    for browser in browsers:
        bdir = os.path.join(config_dir, browser)
        if not os.path.isdir(bdir):
            continue
        names = {}
        ls = os.path.join(bdir, "Local State")
        if os.path.isfile(ls):
            try:
                cache = json.load(open(ls)).get("profile", {}).get("info_cache", {})
                names = {k: (v.get("name") or k) for k, v in cache.items()}
            except Exception:
                pass
        # fall back to any directory that has a Login Data db
        candidates = set(names)
        for entry in os.listdir(bdir):
            if os.path.isfile(os.path.join(bdir, entry, "Login Data")):
                candidates.add(entry)
        for folder in sorted(candidates):
            db = os.path.join(bdir, folder, "Login Data")
            if os.path.isfile(db):
                profiles.append(Profile(browser, folder, names.get(folder, folder), db))
    return profiles


def _read_logins(login_db: str):
    """Copy the db (it may be locked) and read its rows."""
    tmp = tempfile.mktemp(suffix=".db")
    shutil.copy(login_db, tmp)
    try:
        con = sqlite3.connect(tmp)
        try:
            rows = con.execute(
                "SELECT origin_url, username_value, password_value FROM logins"
            ).fetchall()
        finally:
            con.close()
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return rows


def needs_keyring(profiles) -> bool:
    """True if any profile has at least one v11 (keyring-encrypted) blob."""
    for p in profiles:
        for _, _, pw in _read_logins(p.login_db):
            if pw[:3] == b"v11":
                return True
    return False


def resolve_v11_key(rows, secrets: dict, preferred_label: str):
    """Pick the keyring secret that actually decrypts this profile's v11 blobs."""
    sample = next((pw for *_, pw in rows if pw[:3] == b"v11"), None)
    if sample is None:
        return None
    ordered = []
    if preferred_label in secrets:
        ordered.append(secrets[preferred_label])
    ordered += [s for lbl, s in secrets.items() if lbl != preferred_label]
    for secret in ordered:
        key = chrome_aes_key(secret)
        if _looks_decrypted(sample, key):
            return key
    return None


@dataclass
class ExportResult:
    profile: Profile
    csv_path: str
    total: int = 0
    decrypted: int = 0
    failed: int = 0
    warnings: list = field(default_factory=list)


def export_profile(p: Profile, secrets: dict, out_dir: str) -> ExportResult:
    rows = _read_logins(p.login_db)
    v10_key = chrome_aes_key(b"peanuts")
    v11_key = resolve_v11_key(rows, secrets, BROWSERS.get(p.browser, ""))

    safe_browser = p.browser
    safe_profile = p.folder.replace(" ", "_")
    safe_name = "".join(c if c.isalnum() or c in "-_." else "_" for c in p.display_name)
    csv_path = os.path.join(out_dir, f"{safe_browser}__{safe_profile}__{safe_name}.csv")

    res = ExportResult(profile=p, csv_path=csv_path)
    if any(pw[:3] == b"v11" for *_, pw in rows) and v11_key is None:
        res.warnings.append("v11 entries present but no matching keyring secret found")

    with open(os.open(csv_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w",
              newline="") as f:
        w = csv.writer(f)
        w.writerow(["name", "url", "username", "password"])
        for url, user, pw in rows:
            res.total += 1
            password = decrypt_password(pw, v11_key, v10_key)
            if pw and pw[:3] in (b"v10", b"v11") and password == "":
                res.failed += 1
            elif pw:
                res.decrypted += 1
            host = url.split("/")[2] if "//" in url else url
            w.writerow([host or url, url, user, password])
    return res


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def default_keyring_path(config_dir: str) -> str:
    base = os.path.dirname(os.path.abspath(config_dir.rstrip("/")))
    kdir = os.path.join(base, ".local", "share", "keyrings")
    login = os.path.join(kdir, "login.keyring")
    if os.path.isfile(login):
        return login
    if os.path.isdir(kdir):  # otherwise pick the first real keyring file
        for name in sorted(os.listdir(kdir)):
            path = os.path.join(kdir, name)
            try:
                if open(path, "rb").read(16) == GNOME_KEYRING_MAGIC:
                    return path
            except OSError:
                continue
    return login  # report the expected-but-missing path


def get_password(args) -> bytes:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n").encode()
    env = os.environ.get("CHROME_KEYRING_PASSWORD")
    if env is not None:
        return env.encode()
    return getpass.getpass("Old login password (for the keyring, not echoed): ").encode()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="chrome-restore-passwords",
        description="Decrypt local Chrome/Chromium passwords on Linux to per-profile CSVs.",
        epilog=(
            "importing into chrome:\n"
            "  This tool writes one CSV per profile (Chrome's 'name,url,username,password'\n"
            "  import format). To load them back into Chrome:\n"
            "    1. Open a Chrome window in the PROFILE you want to import into.\n"
            "    2. Visit:  chrome://password-manager/settings\n"
            "    3. Click 'Import passwords' and choose the CSV for that profile.\n"
            "  Imports go into whichever profile's window you started from, so match them up.\n"
            "\n"
            "  The CSVs contain PLAINTEXT passwords (written mode 0600). Delete them securely\n"
            "  when finished:\n"
            "    shred -u <output-dir>/*.csv\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--config-dir", default=os.path.expanduser("~/.config"),
                    help="path to a .config directory (point at the OLD disk). "
                         "Default: ~/.config")
    ap.add_argument("--out", default="./chrome-passwords-export",
                    help="output directory for CSV files (default: ./chrome-passwords-export)")
    ap.add_argument("--browser", action="append", choices=list(BROWSERS),
                    help="restrict to specific browser(s); repeatable. Default: all found")
    ap.add_argument("--keyring", help="explicit path to the login.keyring "
                                      "(default: autodetected next to --config-dir)")
    ap.add_argument("--password-stdin", action="store_true",
                    help="read the login password from stdin instead of prompting")
    ap.add_argument("--list", action="store_true",
                    help="only list discovered profiles, do not decrypt")
    args = ap.parse_args(argv)

    config_dir = os.path.expanduser(args.config_dir)
    if not os.path.isdir(config_dir):
        return _fail(f"--config-dir not found: {config_dir}")

    browsers = args.browser or list(BROWSERS)
    profiles = discover_profiles(config_dir, browsers)
    if not profiles:
        return _fail(f"no Chrome/Chromium profiles with a 'Login Data' db under {config_dir}")

    print(f"Found {len(profiles)} profile(s) under {config_dir}:")
    for p in profiles:
        n = len(_read_logins(p.login_db))
        print(f"  - {p.browser:24} {p.folder:12} {p.display_name!r:20} ({n} logins)")
    if args.list:
        return 0

    secrets = {}
    if needs_keyring(profiles):
        keyring_path = args.keyring or default_keyring_path(config_dir)
        if not os.path.isfile(keyring_path):
            return _fail(f"keyring needed (v11 entries) but not found: {keyring_path}\n"
                         f"       pass --keyring /path/to/login.keyring")
        print(f"\nv11 (keyring-encrypted) entries present; unlocking {keyring_path}")
        try:
            body = unlock_keyring(parse_keyring(keyring_path), get_password(args))
        except ValueError as e:
            return _fail(str(e))
        secrets = extract_safe_storage_secrets(body)
        if not secrets:
            return _fail("keyring unlocked but no '*Safe Storage' secret inside it")
        print(f"keyring unlocked; found secrets for: {', '.join(sorted(secrets))}")
    else:
        print("\nNo v11 entries; keyring/password not required.")

    os.makedirs(args.out, exist_ok=True)
    print(f"\nWriting CSVs to {os.path.abspath(args.out)}/ (mode 600):")
    grand = 0
    for p in profiles:
        if not _read_logins(p.login_db):
            continue  # nothing to export for empty profiles
        r = export_profile(p, secrets, args.out)
        grand += r.decrypted
        flag = "" if not r.warnings else "  [!] " + "; ".join(r.warnings)
        print(f"  - {os.path.basename(r.csv_path):50} "
              f"{r.decrypted} ok / {r.failed} failed / {r.total} total{flag}")

    print(f"\nDone: {grand} passwords decrypted across {len(profiles)} profile(s).")
    print("Import each CSV via chrome://password-manager/settings -> Import "
          "(from a window of the target profile), then SHRED the CSVs:")
    print(f"    shred -u {os.path.abspath(args.out)}/*.csv")
    return 0


def _fail(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
