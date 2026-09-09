"""Bounded local process execution; no shell and no inherited cloud credentials."""

import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path


class ExecutionError(RuntimeError):
    pass


def run(argv: list[str], cwd: Path, timeout: float = 30, max_output: int = 1_048_576) -> str:
    if not argv or timeout <= 0 or max_output <= 0:
        raise ValueError("invalid process limits")
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        in {
            "PATH",
            "LANG",
            "LC_ALL",
            "LD_LIBRARY_PATH",
            "SYSTEMROOT",
        }
    }
    env["HOME"] = str(cwd)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            proc = subprocess.Popen(
                argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, start_new_session=True
            )
        except OSError as exc:
            raise ExecutionError(f"cannot start {argv[0]}: {exc}") from exc
        deadline = time.monotonic() + timeout
        try:
            while True:
                if (
                    os.fstat(stdout.fileno()).st_size + os.fstat(stderr.fileno()).st_size
                    > max_output
                ):
                    raise ExecutionError("process output limit exceeded")
                if proc.poll() is not None:
                    break
                if time.monotonic() >= deadline:
                    raise ExecutionError(f"process exceeded {timeout}s deadline")
                time.sleep(0.01)
        finally:
            # Also reap descendants of a wrapper that exited before its children.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        stdout.seek(0)
        stderr.seek(0)
        out = stdout.read(max_output).decode(errors="replace")
        err = stderr.read(max_output).decode(errors="replace")
        if proc.returncode:
            raise ExecutionError(f"process exited {proc.returncode}: {err[-2000:]}")
        return out
