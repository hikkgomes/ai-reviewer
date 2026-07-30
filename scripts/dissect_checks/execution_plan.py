from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Callable

from .redaction import redact_argv, redact_sensitive_text


PLAN_SCHEMA_VERSION = 1
APPROVAL_DOMAIN = b"dissect-execution-plan-v1\0"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_fd(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    for chunk in iter(lambda: os.read(fd, 1024 * 1024), b""):
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _resolve_executable(value: str) -> Path | None:
    detected = shutil.which(value)
    if not detected:
        return None
    try:
        return Path(detected).resolve(strict=True)
    except OSError:
        return None


@dataclass(frozen=True)
class ExecutionPlan:
    kind: str
    name: str
    executable_path: str
    executable_sha256: str
    argv: tuple[str, ...]
    working_directory: str
    finding_exit_codes: tuple[int, ...] = ()

    def canonical_payload(self) -> dict:
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "kind": self.kind,
            "name": self.name,
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "finding_exit_codes": list(self.finding_exit_codes),
        }

    @property
    def approval_digest(self) -> str:
        encoded = json.dumps(
            self.canonical_payload(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8", errors="surrogatepass")
        return hashlib.sha256(APPROVAL_DOMAIN + encoded).hexdigest()

    def redacted_payload(self) -> dict:
        payload = self.canonical_payload()
        payload["name"] = redact_sensitive_text(self.name)
        payload["executable_path"] = redact_sensitive_text(self.executable_path)
        payload["argv"] = redact_argv(self.argv)
        payload["working_directory"] = redact_sensitive_text(self.working_directory)
        payload["approval_digest"] = self.approval_digest
        return payload


def build_execution_plan(
    *,
    kind: str,
    name: str,
    argv: list[str] | tuple[str, ...],
    working_directory: Path,
    finding_exit_codes: set[int] | tuple[int, ...] = (),
) -> tuple[ExecutionPlan | None, str | None]:
    if not argv or not all(isinstance(value, str) and value for value in argv):
        return None, "execution plan requires a non-empty string argv array"
    resolved = _resolve_executable(argv[0])
    if resolved is None:
        return None, "configured executable was not found"
    try:
        cwd = working_directory.resolve(strict=True)
        executable_digest = _sha256_file(resolved)
    except OSError:
        return None, "configured executable identity could not be read"
    plan = ExecutionPlan(
        kind=kind,
        name=name,
        executable_path=str(resolved),
        executable_sha256=executable_digest,
        argv=(str(resolved), *tuple(argv[1:])),
        working_directory=str(cwd),
        finding_exit_codes=tuple(sorted(set(finding_exit_codes))),
    )
    return plan, None


def valid_approval_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _fd_executable_path(fd: int) -> str:
    proc_path = Path(f"/proc/self/fd/{fd}")
    if proc_path.exists():
        return str(proc_path)
    return f"/dev/fd/{fd}"


def _run_open_executable(plan: ExecutionPlan, fd: int) -> subprocess.CompletedProcess[str]:
    if sys.platform == "darwin":
        snapshot_path = ""
        execution_path = ""
        try:
            try:
                temp_dir = tempfile.mkdtemp(prefix="dissect-approved-executable-")
                snapshot_path = str(Path(temp_dir) / "executable")
                os.link(plan.executable_path, snapshot_path)
                if os.fstat(fd).st_ino != os.stat(snapshot_path).st_ino:
                    raise OSError("hard-linked executable identity changed")
                execution_path = snapshot_path
            except OSError:
                current = Path(plan.executable_path)
                immutable = True
                while True:
                    if os.access(current, os.W_OK):
                        immutable = False
                        break
                    if current.parent == current:
                        break
                    current = current.parent
                if not immutable:
                    raise OSError(
                        "mutable executable cannot be bound to an immutable macOS handle"
                    )
                execution_path = plan.executable_path
            return subprocess.run(
                list(plan.argv),
                executable=execution_path,
                shell=False,
                cwd=plan.working_directory,
                text=True,
                capture_output=True,
                check=False,
            )
        finally:
            if snapshot_path:
                try:
                    os.unlink(snapshot_path)
                    os.rmdir(str(Path(snapshot_path).parent))
                except OSError:
                    pass
    return subprocess.run(
        list(plan.argv),
        executable=_fd_executable_path(fd),
        pass_fds=(fd,),
        shell=False,
        cwd=plan.working_directory,
        text=True,
        capture_output=True,
        check=False,
    )


def execute_approved_plan(
    plan: ExecutionPlan,
    approval_digest: str,
    *,
    runner: Callable[[ExecutionPlan, int], subprocess.CompletedProcess[str]] = _run_open_executable,
) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    if not valid_approval_digest(approval_digest):
        return None, "malformed execution-plan approval digest"
    if approval_digest != plan.approval_digest:
        return None, "execution-plan approval is stale or does not match this plan"

    resolved = _resolve_executable(plan.argv[0])
    if resolved is None or str(resolved) != plan.executable_path:
        return None, "executable path identity changed after planning"
    try:
        if _sha256_file(resolved) != plan.executable_sha256:
            return None, "executable bytes changed after planning"
        fd = os.open(resolved, os.O_RDONLY)
    except OSError:
        return None, "approved executable could not be opened"

    try:
        before_stat = os.fstat(fd)
        if _sha256_fd(fd) != plan.executable_sha256:
            return None, "executable bytes changed before execution"
        completed = runner(plan, fd)
        after_stat = os.fstat(fd)
        if (
            before_stat.st_dev,
            before_stat.st_ino,
            before_stat.st_size,
            before_stat.st_mtime_ns,
        ) != (
            after_stat.st_dev,
            after_stat.st_ino,
            after_stat.st_size,
            after_stat.st_mtime_ns,
        ) or _sha256_fd(fd) != plan.executable_sha256:
            return None, "executable identity changed during execution"
        return completed, None
    except OSError:
        return None, "approved executable could not be executed safely"
    finally:
        os.close(fd)
