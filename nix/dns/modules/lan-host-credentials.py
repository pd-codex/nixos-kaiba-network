"""Initialize or validate host-scoped LAN TSIG material; never print secrets."""
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
        raise ValueError("unsafe credential ownership or type")
    if stat.S_IMODE(info.st_mode) != mode or (not directory and info.st_nlink != 1):
        raise ValueError("unsafe credential mode or links")


def secret(value):
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("invalid canonical key")
    return value


def content(role, keys, scope):
    names = ["update", "transfer"] if role == "primary" else ["transfer"]
    include = "key:\n" + "".join(
        f"  - id: kaiba-lan-{name}\n    algorithm: hmac-sha256\n    secret: {keys[name]}\n"
        for name in names
    )
    result = {"private/keys.json": json.dumps(keys, sort_keys=True),
              "private/keys.conf": include,
              "private/scope.json": json.dumps(scope, sort_keys=True)}
    if role == "primary":
        result.update({"private/transfer.secret": keys["transfer"] + "\n",
                       "publisher/update.secret": keys["update"] + "\n"})
    return result


def write(path, value, mode, gid):
    with open(path, "x", encoding="ascii") as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, gid)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def main():
    os.umask(0o077)
    role, base, config = sys.argv[1], Path(sys.argv[2]), json.loads(Path(sys.argv[3]).read_bytes())
    if role not in ("primary", "secondary"):
        raise ValueError("invalid role")
    check(base, 0o755, directory=True)
    publisher_gid = grp.getgrnam("kaiba-publisher").gr_gid if role == "primary" else 0
    imported = None
    if role == "secondary":
        source = Path(config["transfer_secret_file"])
        # Exact root-controlled runtime path; no symlinked parent directories.
        for parent in source.parents:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("unsafe transfer credential parent")
        check(source, 0o600)
        if source.stat().st_size != 45:
            raise ValueError("invalid transfer credential size")
        imported = secret(source.read_text(encoding="ascii").removesuffix("\n"))
    final = base / "credentials"
    if not os.path.lexists(final):
        if any(base.iterdir()):
            raise ValueError("partial credential state requires operator recovery")
        dns_state = Path(config["dns_state"])
        if os.path.lexists(dns_state):
            if not stat.S_ISDIR(dns_state.lstat().st_mode) or any(dns_state.iterdir()):
                raise ValueError("retained DNS state requires the original credentials")
        staged = Path(tempfile.mkdtemp(prefix=".initialize-", dir=base))
        (staged / "private").mkdir(mode=0o700)
        if role == "primary":
            (staged / "publisher").mkdir(mode=0o750)
            os.chmod(staged / "publisher", 0o750)
            os.chown(staged / "publisher", 0, publisher_gid)
        keys = ({name: base64.b64encode(secrets.token_bytes(32)).decode("ascii")
                 for name in ("update", "transfer")} if role == "primary" else {"transfer": imported})
        for name, value in content(role, keys, config).items():
            publisher = name.startswith("publisher/")
            write(staged / name, value, 0o640 if publisher else 0o600, publisher_gid if publisher else 0)
        os.chmod(staged, 0o751)
        for directory in [staged / "private"] + ([staged / "publisher"] if role == "primary" else []) + [staged]:
            fd = os.open(directory, os.O_DIRECTORY)
            os.fsync(fd)
            os.close(fd)
        os.rename(staged, final)
        fd = os.open(base, os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
    check(final, 0o751, directory=True)
    check(final / "private", 0o700, directory=True)
    if role == "primary":
        check(final / "publisher", 0o750, publisher_gid, directory=True)
    check(final / "private/keys.json", 0o600)
    keys = json.loads((final / "private/keys.json").read_bytes())
    if set(keys) != ({"update", "transfer"} if role == "primary" else {"transfer"}):
        raise ValueError("unexpected key set")
    for value in keys.values():
        secret(value)
    if role == "primary" and keys["update"] == keys["transfer"]:
        raise ValueError("key roles must be separate")
    if role == "secondary" and keys["transfer"] != imported:
        raise ValueError("transfer credential changed; explicit recovery required")
    for name, value in content(role, keys, config).items():
        publisher = name.startswith("publisher/")
        check(final / name, 0o640 if publisher else 0o600, publisher_gid if publisher else 0)
        if (final / name).read_text(encoding="ascii") != value:
            raise ValueError("persisted credentials or scope differ")
    marker = base / "initialized"
    if not os.path.lexists(marker):
        write(marker, "kaiba-lan-host-credentials-v1\n", 0o600, 0)
    check(marker, 0o600)
    if marker.read_text(encoding="ascii") != "kaiba-lan-host-credentials-v1\n":
        raise ValueError("invalid initialization marker")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("LAN host credential initialization refused; inspect private state locally")
