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
from typing import Callable, Mapping

from .redaction import redact_argv, redact_environment, redact_shell_command, redact_sensitive_text


PLAN_SCHEMA_VERSION = 2
APPROVAL_DOMAIN = b"dissect-execution-plan-v2\0"
_ENV_NAME = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")


def _sha256_file(path: Path) -> str:
    with path.open("rb") as handle:
        return _sha256_handle(handle.fileno())


def _sha256_handle(fd: int) -> str:
    digest = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return digest.hexdigest()


def _valid_environment_name(name: str) -> bool:
    return bool(name) and name[0] not in "0123456789" and all(char in _ENV_NAME for char in name)


def canonical_environment(configured: Mapping[str, str] | None = None) -> tuple[tuple[str, str], ...]:
    """Return the *entire* child environment; nothing is inherited implicitly."""
    values: dict[str, str] = {"PATH": os.defpath}
    if configured:
        for name, value in configured.items():
            if not isinstance(name, str) or not _valid_environment_name(name):
                raise ValueError("execution environment contains an invalid variable name")
            if not isinstance(value, str):
                raise ValueError("execution environment values must be strings")
            values[name] = value
    # Deliberately do not add HOME, locale, loader, shell, interpreter, or package-manager
    # state from os.environ. Explicit configured values remain reviewable and digest-bound.
    return tuple(sorted(values.items()))


def _resolve_executable(value: str, environment: Mapping[str, str]) -> Path | None:
    detected = shutil.which(value, path=environment.get("PATH"))
    if not detected:
        return None
    try:
        return Path(detected).resolve(strict=True)
    except OSError:
        return None


def _shebang_identity(path: Path, environment: Mapping[str, str]) -> tuple[str, str] | None:
    try:
        first = path.read_bytes().splitlines()[0]
    except (OSError, IndexError):
        return None
    if not first.startswith(b"#!"):
        return None
    try:
        words = first[2:].decode("utf-8").strip().split()
    except UnicodeDecodeError:
        raise ValueError("script executable has a non-UTF-8 shebang")
    if not words:
        raise ValueError("script executable has an empty shebang")
    interpreter = words[0]
    # /usr/bin/env intentionally delegates interpreter selection to PATH. Bind the
    # selected interpreter itself rather than accepting an extra mutable resolver.
    if Path(interpreter).name == "env":
        if len(words) != 2 or words[1].startswith("-"):
            raise ValueError("script executable uses an unsupported env shebang")
        interpreter = words[1]
    resolved = _resolve_executable(interpreter, environment)
    if resolved is None:
        raise ValueError("script interpreter was not found in the approved environment")
    return str(resolved), _sha256_file(resolved)


@dataclass(frozen=True)
class ExecutionPlan:
    kind: str
    name: str
    executable_path: str
    executable_sha256: str
    argv: tuple[str, ...]
    working_directory: str
    environment: tuple[tuple[str, str], ...]
    finding_exit_codes: tuple[int, ...] = ()
    interpreter_path: str = ""
    interpreter_sha256: str = ""
    shell_semantics: str = ""

    @property
    def environment_dict(self) -> dict[str, str]:
        return dict(self.environment)

    def canonical_payload(self) -> dict:
        return {
            "schema_version": PLAN_SCHEMA_VERSION,
            "kind": self.kind,
            "name": self.name,
            "executable_path": self.executable_path,
            "executable_sha256": self.executable_sha256,
            "argv": list(self.argv),
            "working_directory": self.working_directory,
            "environment": [{"name": key, "value": value} for key, value in self.environment],
            "finding_exit_codes": list(self.finding_exit_codes),
            "interpreter_path": self.interpreter_path,
            "interpreter_sha256": self.interpreter_sha256,
            "shell_semantics": self.shell_semantics,
        }

    @property
    def approval_digest(self) -> str:
        encoded = json.dumps(self.canonical_payload(), ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8", errors="surrogatepass")
        return hashlib.sha256(APPROVAL_DOMAIN + encoded).hexdigest()

    def redacted_payload(self) -> dict:
        payload = self.canonical_payload()
        payload["name"] = redact_sensitive_text(self.name)
        payload["executable_path"] = redact_sensitive_text(self.executable_path)
        payload["argv"] = redact_argv(self.argv)
        if self.shell_semantics and len(self.argv) >= 3:
            payload["argv"][2] = redact_shell_command(self.argv[2])
        payload["working_directory"] = redact_sensitive_text(self.working_directory)
        payload["environment"] = redact_environment(self.environment)
        payload["approval_digest"] = self.approval_digest
        return payload


def build_execution_plan(*, kind: str, name: str, argv: list[str] | tuple[str, ...], working_directory: Path, finding_exit_codes: set[int] | tuple[int, ...] = (), environment: Mapping[str, str] | None = None) -> tuple[ExecutionPlan | None, str | None]:
    if not argv or not all(isinstance(value, str) and value for value in argv):
        return None, "execution plan requires a non-empty string argv array"
    try:
        approved_environment = canonical_environment(environment)
        env = dict(approved_environment)
        resolved = _resolve_executable(argv[0], env)
        if resolved is None:
            return None, "configured executable was not found in the approved PATH"
        cwd = working_directory.resolve(strict=True)
        executable_digest = _sha256_file(resolved)
        interpreter = _shebang_identity(resolved, env)
    except (OSError, ValueError) as error:
        return None, str(error) or "configured executable identity could not be read"
    shell_semantics = ""
    if len(argv) == 3 and Path(argv[0]).name == "sh" and argv[1] == "-c":
        shell_semantics = "shell command is bound; nested executables are not independently authenticated"
    plan = ExecutionPlan(kind=kind, name=name, executable_path=str(resolved), executable_sha256=executable_digest, argv=(str(resolved), *tuple(argv[1:])), working_directory=str(cwd), environment=approved_environment, finding_exit_codes=tuple(sorted(set(finding_exit_codes))), interpreter_path=interpreter[0] if interpreter else "", interpreter_sha256=interpreter[1] if interpreter else "", shell_semantics=shell_semantics)
    return plan, None


def valid_approval_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _open_verified(path: str, expected: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if _sha256_handle(fd) != expected:
            raise ValueError("executable bytes changed after planning")
        return fd
    except Exception:
        os.close(fd)
        raise


def _copy_snapshot(source_fd: int, directory: Path, name: str) -> tuple[Path, int]:
    path = directory / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o500)
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                written = os.write(fd, view)
                view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(path, 0o500)
    read_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    return path, read_fd


def _run_snapshot(plan: ExecutionPlan, executable_snapshot: Path, interpreter_snapshot: Path | None) -> subprocess.CompletedProcess[str]:
    if interpreter_snapshot is not None:
        # macOS can refuse to execute a copied, platform-signed system binary. The
        # script bytes still come only from the verified private snapshot; bind and
        # re-verify the system interpreter immediately before this narrow fallback.
        interpreter = plan.interpreter_path if sys.platform == "darwin" else str(interpreter_snapshot)
        command = [interpreter, str(executable_snapshot), *plan.argv[1:]]
        executable = interpreter
    else:
        executable = plan.executable_path if sys.platform == "darwin" else str(executable_snapshot)
        command = [executable, *plan.argv[1:]]
    return subprocess.run(command, executable=executable, shell=False, cwd=plan.working_directory, env=plan.environment_dict, text=True, capture_output=True, check=False)


def execute_approved_plan(plan: ExecutionPlan, approval_digest: str, *, runner: Callable[[ExecutionPlan, int], subprocess.CompletedProcess[str]] | None = None) -> tuple[subprocess.CompletedProcess[str] | None, str | None]:
    if not valid_approval_digest(approval_digest):
        return None, "malformed execution-plan approval digest"
    if approval_digest != plan.approval_digest:
        return None, "execution-plan approval is stale or does not match this plan"
    try:
        # Validate the canonical environment rather than trusting a forged plan object.
        if canonical_environment(plan.environment_dict) != plan.environment:
            return None, "execution-plan environment is not canonical"
        resolved = _resolve_executable(plan.argv[0], plan.environment_dict)
        if resolved is None or str(resolved) != plan.executable_path:
            return None, "executable path identity changed after planning"
        source_fd = _open_verified(plan.executable_path, plan.executable_sha256)
    except (OSError, ValueError):
        return None, "executable bytes changed after planning"

    try:
        with tempfile.TemporaryDirectory(prefix="dissect-approved-executable-") as raw_directory:
            directory = Path(raw_directory)
            os.chmod(directory, 0o700)
            snapshot, snapshot_fd = _copy_snapshot(source_fd, directory, "executable")
            try:
                if os.fstat(source_fd).st_ino == os.fstat(snapshot_fd).st_ino or _sha256_handle(snapshot_fd) != plan.executable_sha256:
                    return None, "approved executable snapshot verification failed"
                interpreter_snapshot = None
                interpreter_fd = None
                if plan.interpreter_path:
                    interpreter_fd = _open_verified(plan.interpreter_path, plan.interpreter_sha256)
                    interpreter_snapshot, copied_interpreter_fd = _copy_snapshot(interpreter_fd, directory, "interpreter")
                    os.close(interpreter_fd)
                    interpreter_fd = None
                    if _sha256_handle(copied_interpreter_fd) != plan.interpreter_sha256:
                        os.close(copied_interpreter_fd)
                        return None, "approved interpreter snapshot verification failed"
                    os.close(copied_interpreter_fd)
                if runner is not None:
                    completed = runner(plan, snapshot_fd)
                else:
                    if sys.platform == "darwin" and not plan.interpreter_path and _sha256_file(Path(plan.executable_path)) != plan.executable_sha256:
                        return None, "executable bytes changed before execution"
                    if sys.platform == "darwin" and plan.interpreter_path and _sha256_file(Path(plan.interpreter_path)) != plan.interpreter_sha256:
                        return None, "script interpreter bytes changed before execution"
                    completed = _run_snapshot(plan, snapshot, interpreter_snapshot)
                return completed, None
            finally:
                if 'interpreter_fd' in locals() and interpreter_fd is not None:
                    os.close(interpreter_fd)
                os.close(snapshot_fd)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None, "approved executable could not be executed safely"
    finally:
        os.close(source_fd)
