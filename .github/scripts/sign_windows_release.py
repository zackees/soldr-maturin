#!/usr/bin/env python3
"""Authenticode-sign maturin's Windows release binaries through Azure Artifact Signing.

Each Windows lane of ``.github/workflows/release.yml`` ships ``maturin.exe``
twice: inside the ``win_amd64``/``win32``/``win_arm64`` wheel (under
``.data/scripts/``) and bare in the ``maturin-<target>.zip`` archive built from
``target/<target>/release/maturin.exe``. The workflow signs both right after
the build and before the zip is archived or anything is uploaded, attested or
published. Each argument is a wheel (every PE inside is signed and RECORD is
rewritten) or a bare PE (signed in place).

Signing uses jsign (https://github.com/ebourg/jsign), a pure-Java Authenticode
signer with a ``TRUSTEDSIGNING`` keystore for Azure Artifact Signing; the jar
is pinned by version and SHA-256 and refused on mismatch. Adapted from
forge-ci/bosn ``ci/sign_windows_release.py``.

The workflow runs ``azure/login`` (OIDC, no client secret) first; ``sign``
asks the Azure CLI for a short-lived code-signing access token and hands it to
jsign through the environment, never on argv.

``sign`` and ``verify`` then check every PE structurally (the PE
security directory holds a PKCS#7 ``WIN_CERTIFICATE`` naming the expected
publisher and carrying an RFC 3161 timestamp) and that each wheel's ``RECORD`` matches its
bytes; any unsigned PE fails the step. ``check`` runs on native Windows
and requires ``Get-AuthenticodeSignature`` to report ``Valid`` for every PE.

Usage (CI):
    python .github/scripts/sign_windows_release.py sign dist/*.whl target/<t>/release/maturin.exe
    python .github/scripts/sign_windows_release.py verify <same paths>
    python .github/scripts/sign_windows_release.py check <same paths>   # native Windows
"""

from __future__ import annotations

import argparse
import base64
import csv
import glob
import hashlib
import io
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

JSIGN_VERSION = "7.6"
JSIGN_URL = f"https://github.com/ebourg/jsign/releases/download/{JSIGN_VERSION}/jsign-{JSIGN_VERSION}.jar"
JSIGN_SHA256 = "6cf58aa080e7ff82656f320cff8d4a3bff30408df8766806dcba3740dd839fa5"
DEFAULT_JSIGN_DIR = Path("target/jsign")
RECORD_SUFFIX = ".dist-info/RECORD"

TIMESTAMP_URL = "http://timestamp.acs.microsoft.com"
CODESIGNING_RESOURCE = "https://codesigning.azure.net"
TOKEN_ENV = "MATURIN_AZURE_SIGNING_TOKEN"

PE_SUFFIXES = (".exe", ".dll", ".pyd")

# WIN_CERTIFICATE: wRevision 0x0200, wCertificateType WIN_CERT_TYPE_PKCS_SIGNED_DATA.
WIN_CERT_REVISION_2 = 0x0200
WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002
# DER of OID 1.3.6.1.4.1.311.3.3.1 (Microsoft RFC 3161 timestamp countersignature).
RFC3161_TIMESTAMP_OID = bytes.fromhex("060a2b060104018237030301")
SECURITY_DIRECTORY_INDEX = 4


class SigningError(RuntimeError):
    """A signing precondition or post-signing check failed."""


@dataclass(frozen=True)
class SigningConfig:
    """Azure Artifact Signing coordinates, read from the job environment."""

    endpoint_host: str
    account: str
    profile: str
    publisher: str


def endpoint_host(endpoint: str) -> str:
    """``https://eus.codesigning.azure.net/`` -> ``eus.codesigning.azure.net``."""
    host = endpoint.strip().removeprefix("https://").removeprefix("http://")
    host = host.split("/", 1)[0]
    if not host.endswith(".codesigning.azure.net"):
        raise SigningError(f"unexpected Artifact Signing endpoint: {endpoint!r}")
    return host


def _required_env(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise SigningError(f"{name} is not set (expected a repository Actions secret)")
    return value


def publisher_common_name(publisher: str) -> str:
    """Accept either a bare name or a full subject DN (``CN=..., O=...``)."""
    for part in publisher.split(","):
        key, _, value = part.strip().partition("=")
        if key.strip().upper() == "CN" and value.strip():
            return value.strip().strip('"')
    return publisher.strip()


def config_from_env(env: dict[str, str]) -> SigningConfig:
    return SigningConfig(
        endpoint_host=endpoint_host(_required_env(env, "AZURE_SIGNING_ENDPOINT")),
        account=_required_env(env, "AZURE_SIGNING_ACCOUNT"),
        profile=_required_env(env, "AZURE_SIGNING_PROFILE"),
        publisher=publisher_common_name(_required_env(env, "AZURE_SIGN_PUBLISHER")),
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_jsign(dest_dir: Path) -> Path:
    """Download the pinned jsign jar once and verify its SHA-256."""
    jar = dest_dir / f"jsign-{JSIGN_VERSION}.jar"
    if jar.is_file() and sha256_file(jar) == JSIGN_SHA256:
        return jar
    dest_dir.mkdir(parents=True, exist_ok=True)
    partial = jar.with_suffix(".partial")
    with urllib.request.urlopen(JSIGN_URL, timeout=120) as response:
        with partial.open("wb") as out:
            shutil.copyfileobj(response, out)
    actual = sha256_file(partial)
    if actual != JSIGN_SHA256:
        partial.unlink()
        raise SigningError(f"jsign {JSIGN_VERSION} sha256 mismatch: got {actual}, pinned {JSIGN_SHA256}")
    partial.replace(jar)
    print(f"jsign {JSIGN_VERSION}: sha256 verified ({JSIGN_SHA256})")
    return jar


def access_token() -> str:
    """Mint an Artifact Signing token from the ``azure/login`` session."""
    completed = subprocess.run(
        [
            "az",
            "account",
            "get-access-token",
            "--resource",
            CODESIGNING_RESOURCE,
            "--query",
            "accessToken",
            "-o",
            "tsv",
        ],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    token = completed.stdout.strip()
    if not token:
        raise SigningError("az returned an empty code-signing access token")
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::add-mask::{token}", flush=True)
    return token


def jsign_command(jar: Path, config: SigningConfig, files: list[Path]) -> list[str]:
    return [
        "java",
        "-jar",
        str(jar),
        "--storetype",
        "TRUSTEDSIGNING",
        "--keystore",
        config.endpoint_host,
        "--storepass",
        f"env:{TOKEN_ENV}",
        "--alias",
        f"{config.account}/{config.profile}",
        "--alg",
        "SHA-256",
        "--tsaurl",
        TIMESTAMP_URL,
        "--tsmode",
        "RFC3161",
        "--replace",
        *[str(path) for path in files],
    ]


def is_pe_name(name: str) -> bool:
    return name.lower().endswith(PE_SUFFIXES)


def authenticode_blob(data: bytes) -> bytes | None:
    """Return the PE's WIN_CERTIFICATE table, or None when it has none."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        raise SigningError("not a PE image (missing MZ header)")
    (pe_offset,) = struct.unpack_from("<I", data, 0x3C)
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise SigningError("not a PE image (missing PE signature)")
    optional = pe_offset + 24
    (magic,) = struct.unpack_from("<H", data, optional)
    directories = {0x10B: optional + 96, 0x20B: optional + 112}.get(magic)
    if directories is None:
        raise SigningError(f"unknown PE optional-header magic {magic:#x}")
    entry = directories + SECURITY_DIRECTORY_INDEX * 8
    offset, size = struct.unpack_from("<II", data, entry)
    if offset == 0 or size == 0:
        return None
    return data[offset : offset + size]


def signature_problem(data: bytes, publisher: str) -> str | None:
    """Describe why ``data`` is not a timestamped signature by ``publisher``."""
    blob = authenticode_blob(data)
    if blob is None or len(blob) < 8:
        return "no Authenticode signature (empty PE security directory)"
    _length, revision, cert_type = struct.unpack_from("<IHH", blob, 0)
    if revision != WIN_CERT_REVISION_2 or cert_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA:
        return f"unexpected WIN_CERTIFICATE revision/type {revision:#x}/{cert_type:#x}"
    if publisher.encode("utf-8") not in blob:
        return f"signature does not name publisher {publisher!r}"
    if RFC3161_TIMESTAMP_OID not in blob:
        return "signature carries no RFC 3161 timestamp"
    return None


def record_hash(data: bytes) -> str:
    """The wheel RECORD form: ``sha256=<urlsafe base64, no padding>``."""
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def record_name(names: list[str]) -> str:
    records = [name for name in names if name.endswith(RECORD_SUFFIX) and name.count("/") == 1]
    if len(records) != 1:
        raise SigningError(f"expected exactly one .dist-info/RECORD, found {records}")
    return records[0]


def rewrite_record(record: bytes, members: dict[str, bytes]) -> bytes:
    """RECORD with every listed member re-hashed from ``members``."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for row in csv.reader(io.StringIO(record.decode("utf-8"))):
        if not row:
            continue
        name = row[0]
        if name in members and not name.endswith(RECORD_SUFFIX):
            data = members[name]
            writer.writerow([name, record_hash(data), str(len(data))])
        else:
            writer.writerow(row)
    return out.getvalue().encode("utf-8")


def read_wheel(wheel: Path) -> tuple[list[zipfile.ZipInfo], dict[str, bytes]]:
    with zipfile.ZipFile(wheel) as archive:
        infos = archive.infolist()
        return infos, {info.filename: archive.read(info) for info in infos}


def wheel_pe_names(names: list[str]) -> list[str]:
    found = sorted(name for name in names if is_pe_name(name))
    if not found:
        raise SigningError("no Windows PE files found in the wheel")
    return found


def write_wheel(wheel: Path, infos: list[zipfile.ZipInfo], members: dict[str, bytes]) -> None:
    """Rewrite ``wheel`` in place, keeping member order and metadata."""
    partial = wheel.with_suffix(".partial")
    with zipfile.ZipFile(partial, "w") as archive:
        for info in infos:
            archive.writestr(info, members[info.filename], compress_type=info.compress_type)
    partial.replace(wheel)


def verify_wheel(wheel: Path, publisher: str) -> None:
    _infos, members = read_wheel(wheel)
    names = list(members)
    failures = []
    for name in wheel_pe_names(names):
        problem = signature_problem(members[name], publisher)
        if problem:
            failures.append(f"  {name}: {problem}")
        else:
            print(f"signed: {wheel.name}!{name}")
    record = members[record_name(names)]
    expected = rewrite_record(record, members)
    if record != expected:
        failures.append("  RECORD does not match the wheel's bytes")
    if failures:
        raise SigningError(f"{wheel.name} is not a signed release wheel:\n" + "\n".join(failures))


WINDOWS_WHEEL_SUFFIXES = ("-win_amd64.whl", "-win32.whl", "-win_arm64.whl")


def is_wheel(path: Path) -> bool:
    return path.name.endswith(".whl")


def pe_members(path: Path) -> dict[str, bytes]:
    """``{display name: bytes}`` for every PE the artifact ships."""
    if is_wheel(path):
        _infos, members = read_wheel(path)
        return {f"{path.name}!{name}": members[name] for name in wheel_pe_names(list(members))}
    return {path.name: path.read_bytes()}


def verify_artifact(path: Path, publisher: str) -> None:
    if is_wheel(path):
        verify_wheel(path, publisher)
        return
    problem = signature_problem(path.read_bytes(), publisher)
    if problem:
        raise SigningError(f"{path}: {problem}")
    print(f"signed: {path}")


def sign_artifacts(jar: Path, config: SigningConfig, paths: list[Path]) -> None:
    """Sign every bare PE and every PE inside each wheel in one jsign call."""
    env = dict(os.environ)
    env[TOKEN_ENV] = access_token()
    with tempfile.TemporaryDirectory(prefix="maturin-sign-") as scratch:
        files: list[Path] = []
        wheels: list[tuple[Path, list[zipfile.ZipInfo], dict[str, bytes], list[tuple[str, Path]]]] = []
        for path in paths:
            if not is_wheel(path):
                files.append(path)
                continue
            infos, members = read_wheel(path)
            staged = []
            for name in wheel_pe_names(list(members)):
                tmp = Path(scratch) / str(len(files)) / Path(name).name
                tmp.parent.mkdir()
                tmp.write_bytes(members[name])
                files.append(tmp)
                staged.append((name, tmp))
            wheels.append((path, infos, members, staged))
        print(f"jsign: signing {len(files)} file(s) with {config.account}/{config.profile}")
        subprocess.run(jsign_command(jar, config, files), env=env, check=True)
        for wheel, infos, members, staged in wheels:
            for name, tmp in staged:
                members[name] = tmp.read_bytes()
            record = record_name(list(members))
            members[record] = rewrite_record(members[record], members)
            write_wheel(wheel, infos, members)


def authenticode_status(binary: Path) -> str:
    """Windows' own verdict on a PE's signature (chain, timestamp, hash)."""
    literal = str(binary.resolve()).replace("'", "''")
    completed = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"(Get-AuthenticodeSignature -LiteralPath '{literal}').Status",
        ],
        stdout=subprocess.PIPE,
        text=True,
        check=True,
    )
    return completed.stdout.strip()


def check_artifacts(paths: list[Path]) -> None:
    failures = []
    count = 0
    with tempfile.TemporaryDirectory(prefix="maturin-authenticode-") as scratch:
        for path in paths:
            for name, data in pe_members(path).items():
                tmp = Path(scratch) / str(count) / name.rsplit("/", 1)[-1].rsplit("!", 1)[-1]
                tmp.parent.mkdir()
                tmp.write_bytes(data)
                count += 1
                status = authenticode_status(tmp)
                if status != "Valid":
                    failures.append(f"  {name}: {status}")
    if failures:
        raise SigningError("Windows binaries without a Valid Authenticode signature:\n" + "\n".join(failures))
    print(f"Authenticode Valid: {count} Windows PE file(s)")


def resolve_artifacts(patterns: list[str]) -> list[Path]:
    paths: list[Path] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if not matches:
            raise SigningError(f"nothing matches {pattern!r}")
        for match in matches:
            path = Path(match)
            if is_wheel(path):
                if not path.name.endswith(WINDOWS_WHEEL_SUFFIXES):
                    raise SigningError(f"not a Windows wheel: {path.name}")
            elif not is_pe_name(path.name):
                raise SigningError(f"not a Windows PE: {path}")
            paths.append(path)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("mode", choices=("sign", "verify", "check"))
    parser.add_argument("artifacts", nargs="+", help="paths or globs naming Windows wheels and/or bare PEs")
    parser.add_argument("--jsign-dir", type=Path, default=DEFAULT_JSIGN_DIR)
    args = parser.parse_args(argv)

    try:
        paths = resolve_artifacts(args.artifacts)
        if args.mode == "check":
            check_artifacts(paths)
            return 0
        config = config_from_env(dict(os.environ))
        if args.mode == "sign":
            sign_artifacts(fetch_jsign(args.jsign_dir), config, paths)
        for path in paths:
            verify_artifact(path, config.publisher)
    except SigningError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
