"""Create private, persistent qualification keys; never emit their contents."""

import base64
import grp
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import tempfile


def check(path, mode, gid=0, directory=False):
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_gid != gid:
        raise ValueError("unsafe credential ownership or file type")
    if stat.S_IMODE(info.st_mode) != mode or (not directory and info.st_nlink != 1):
        raise ValueError("unsafe credential permissions or link count")


def contents(keys):
    def knot(names):
        return "key:\n" + "".join(
            f"  - id: kaiba-lan-{name}\n    algorithm: hmac-sha256\n    secret: {keys[name]}\n"
            for name in names
        )

    return {
        "private/primary.conf": knot(["update", "transfer-a", "transfer-b"]),
        "private/replica-a.conf": knot(["transfer-a"]),
        "private/replica-b.conf": knot(["transfer-b"]),
        "publisher/update.secret": keys["update"] + "\n",
    }


def write(path, data, mode, gid):
    with open(path, "x", encoding="ascii") as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, gid)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    os.umask(0o077)
    base = Path(sys.argv[1])
    check(base, 0o755, directory=True)
    publisher_gid = grp.getgrnam("kaiba-publisher").gr_gid
    final = base / "credentials"
    if not os.path.lexists(final):
        # Do not silently replace partially initialized or removed credentials.
        if any(base.iterdir()):
            raise ValueError("partial qualification state requires operator recovery")
        staged = Path(tempfile.mkdtemp(prefix=".initialize-", dir=base))
        (staged / "private").mkdir(mode=0o700)
        (staged / "publisher").mkdir(mode=0o750)
        os.chmod(staged / "publisher", 0o750)
        os.chown(staged / "publisher", 0, publisher_gid)
        keys = {name: base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                for name in ["update", "transfer-a", "transfer-b"]}
        write(staged / "private/keys.json", json.dumps(keys, sort_keys=True), 0o600, 0)
        for name, data in contents(keys).items():
            publisher = name.startswith("publisher/")
            write(staged / name, data, 0o640 if publisher else 0o600,
                  publisher_gid if publisher else 0)
        os.chmod(staged, 0o751)
        for path in [staged / "private", staged / "publisher", staged]:
            fd = os.open(path, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        os.rename(staged, final)
        fd = os.open(base, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    check(final, 0o751, directory=True)
    check(final / "private", 0o700, directory=True)
    check(final / "publisher", 0o750, publisher_gid, directory=True)
    check(final / "private/keys.json", 0o600)
    keys = json.loads((final / "private/keys.json").read_text(encoding="ascii"))
    if set(keys) != {"update", "transfer-a", "transfer-b"} or len(set(keys.values())) != 3:
        raise ValueError("invalid qualification keys")
    for value in keys.values():
        decoded = base64.b64decode(value, validate=True)
        if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
            raise ValueError("invalid qualification key encoding")
    for name, expected in contents(keys).items():
        publisher = name.startswith("publisher/")
        check(final / name, 0o640 if publisher else 0o600, publisher_gid if publisher else 0)
        if (final / name).read_text(encoding="ascii") != expected:
            raise ValueError("inconsistent qualification credentials")
    marker = base / "initialized"
    if not os.path.lexists(marker):
        write(marker, "kaiba-lan-dns-credentials-v1\n", 0o600, 0)
    check(marker, 0o600)
    if marker.read_text(encoding="ascii") != "kaiba-lan-dns-credentials-v1\n":
        raise ValueError("invalid qualification initialization marker")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Exceptions from parsers must never disclose a secret value.
        sys.exit("LAN DNS credential initialization refused; inspect private state locally")
