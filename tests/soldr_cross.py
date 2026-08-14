"""Exercise soldr-maturin with Soldr's externally prepared MSVC toolchain."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def load_github_env(path: Path) -> dict[str, str]:
    """Read the one-line KEY=VALUE records emitted by `soldr prepare`."""
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        if "<<" in line:
            raise RuntimeError(f"multiline GitHub environment record is unsupported: {line}")
        key, separator, value = line.partition("=")
        if not separator:
            raise RuntimeError(f"invalid GitHub environment record: {line}")
        values[key] = value
    return values


def tree_digest(root: Path) -> tuple[int, int, str]:
    """Return file count, byte count, and a content digest for a directory tree."""
    digest = hashlib.sha256()
    files = 0
    size = 0
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        files += 1
    return files, size, digest.hexdigest()


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    print(f"+ {' '.join(command)}", flush=True)
    subprocess.run(command, cwd=cwd, env=env, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--maturin", type=Path, required=True)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--target", default="x86_64-pc-windows-msvc")
    args = parser.parse_args()

    project = args.project.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    before_wheels = set(out.glob("*.whl"))

    run(
        [
            "soldr",
            "build",
            "--target",
            args.target,
            "--release",
            "--features",
            "tokio-console",
        ],
        cwd=project,
    )

    with tempfile.TemporaryDirectory(prefix="soldr-maturin-cross-") as temp:
        temp_dir = Path(temp)
        github_env = temp_dir / "github-env"
        shim_dir = temp_dir / "shims"
        run(
            ["soldr", "prepare", "--target", args.target, "--github-env", str(github_env)],
            cwd=project,
        )
        run(
            ["soldr", "toolchain", "link", "--shim-dir", str(shim_dir), "--force"],
            cwd=project,
        )

        env = os.environ.copy()
        env.update(load_github_env(github_env))
        env["PATH"] = os.pathsep.join((str(shim_dir), env["PATH"]))
        env["MATURIN_USE_XWIN"] = "0"
        env["XWIN_HTTP_RETRIES"] = "0"
        env["CARGO_NET_OFFLINE"] = "true"
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env[name] = "http://127.0.0.1:9"

        xwin_cache = Path(env["XWIN_CACHE_DIR"])
        before_cache = tree_digest(xwin_cache)
        command = [
            str(args.maturin.resolve()),
            "build",
            "--target",
            args.target,
            "--release",
            "--offline",
            "--out",
            str(out),
        ]
        print(f"+ {' '.join(command)}", flush=True)
        completed = subprocess.run(
            command,
            cwd=project,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        print(completed.stdout, end="")
        if completed.returncode != 0:
            return completed.returncode
        if "Using xwin" in completed.stdout:
            raise RuntimeError("soldr-maturin selected xwin despite MATURIN_USE_XWIN=0")
        after_cache = tree_digest(xwin_cache)
        if after_cache != before_cache:
            raise RuntimeError(f"xwin cache changed: before={before_cache}, after={after_cache}")

    produced = sorted(set(out.glob("*.whl")) - before_wheels)
    if not produced:
        raise RuntimeError(f"no new wheel was produced in {out}")
    for wheel in produced:
        print(f"verified wheel: {wheel} ({wheel.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
