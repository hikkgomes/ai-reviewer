"""Read repository complexity policy without executing repository commands."""
from __future__ import annotations

import configparser
import json
from pathlib import Path
import re
import tomllib
from typing import Any, Mapping


DEFAULT_THRESHOLD = 15


def _policy(threshold: int, source: str, path: str = "", rule: str = "") -> dict[str, Any]:
    return {"threshold": threshold, "source": source, "path": path, "rule": rule}


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        result = int(value.strip())
    else:
        return None
    return result if result > 0 else None


def _toml_file(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _pyproject(root: Path) -> dict[str, Any] | None:
    return _toml_file(root / "pyproject.toml")


def _repository_policy_at(root: Path, language_id: str) -> dict[str, Any] | None:
    root = root.resolve()
    pyproject = _pyproject(root)
    policy_path = "pyproject.toml"
    if pyproject is None and language_id == "python":
        for filename in ("ruff.toml", ".ruff.toml"):
            pyproject = _toml_file(root / filename)
            if pyproject is not None:
                policy_path = filename
                break
    if pyproject is not None and language_id == "python":
        tool = pyproject.get("tool") if isinstance(pyproject.get("tool"), Mapping) else {}
        ruff = tool.get("ruff") if isinstance(tool, Mapping) else {}
        flake8 = tool.get("flake8") if isinstance(tool, Mapping) else {}
        candidates = (
            ruff.get("lint", {}).get("mccabe", {}).get("max-complexity")
            if isinstance(ruff, Mapping) and isinstance(ruff.get("lint"), Mapping)
            and isinstance(ruff.get("lint", {}).get("mccabe"), Mapping) else None,
            ruff.get("mccabe", {}).get("max-complexity")
            if isinstance(ruff, Mapping) and isinstance(ruff.get("mccabe"), Mapping) else None,
            flake8.get("max-complexity") if isinstance(flake8, Mapping) else None,
            pyproject.get("lint", {}).get("mccabe", {}).get("max-complexity")
            if isinstance(pyproject.get("lint"), Mapping)
            and isinstance(pyproject.get("lint", {}).get("mccabe"), Mapping) else None,
        )
        for value in candidates:
            threshold = _number(value)
            if threshold is not None:
                return _policy(threshold, "repository", policy_path, "C901")
        if policy_path == "pyproject.toml":
            for filename in ("ruff.toml", ".ruff.toml"):
                standalone = _toml_file(root / filename)
                if not isinstance(standalone, Mapping):
                    continue
                mccabe = standalone.get("lint", {}).get("mccabe", {})
                threshold = _number(mccabe.get("max-complexity")) if isinstance(mccabe, Mapping) else None
                if threshold is not None:
                    return _policy(threshold, "repository", filename, "C901")
    if language_id == "python" and policy_path in {"ruff.toml", ".ruff.toml"} and isinstance(pyproject, Mapping):
        mccabe = pyproject.get("lint", {}).get("mccabe", {})
        threshold = _number(mccabe.get("max-complexity")) if isinstance(mccabe, Mapping) else None
        if threshold is not None:
            return _policy(threshold, "repository", policy_path, "C901")
    for filename in ("setup.cfg", "tox.ini", ".flake8"):
        path = root / filename
        if not path.exists() or language_id != "python":
            continue
        parser = configparser.ConfigParser()
        try:
            parser.read(path, encoding="utf-8")
            value = parser.get("flake8", "max-complexity", fallback=None)
        except (OSError, configparser.Error):
            value = None
        threshold = _number(value)
        if threshold is not None:
            return _policy(threshold, "repository", filename, "C901")

    if language_id in {"javascript", "typescript"}:
        for filename in (
            ".eslintrc.json", ".eslintrc", "eslint.config.json",
            "eslint.config.js", "eslint.config.cjs", "eslint.config.mjs",
        ):
            path = root / filename
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                data = None
            if isinstance(data, dict):
                value = (data.get("rules") or {}).get("complexity")
                if isinstance(value, list):
                    values = value[1:] if value and isinstance(value[0], str) else value
                    threshold = next((_number(item) for item in values), None)
                    if threshold is None:
                        threshold = next(
                            (
                                _number(item.get("max"))
                                for item in values
                                if isinstance(item, Mapping) and "max" in item
                            ),
                            None,
                        )
                else:
                    threshold = _number(value)
                if threshold is not None:
                    return _policy(threshold, "repository", filename, "complexity")
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            match = re.search(
                r"complexity\s*[:(]\s*(?:\[\s*)?(?:['\"](?:error|warn|off)['\"]\s*,\s*)?(\d+)",
                text,
            ) or re.search(r"complexity\s*:\s*\{[^}]*\bmax\s*:\s*(\d+)", text, re.S)
            match = match or re.search(
                r"complexity\s*:\s*\[\s*['\"](?:error|warn|off)['\"]\s*,\s*\{[^}]*\bmax\s*:\s*(\d+)",
                text,
                re.S,
            )
            if match:
                return _policy(int(match.group(1)), "repository", filename, "complexity")

    if language_id == "go":
        for filename in (".golangci.yml", ".golangci.yaml"):
            path = root / filename
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            match = re.search(
                r"(?is)(gocyclo|cyclop).{0,500}?(?:min-complexity|max-complexity|threshold)\s*:\s*(\d+)",
                text,
            )
            if match:
                return _policy(int(match.group(2)), "repository", filename, match.group(1).lower())
    return None


def repository_policy(
    root: Path,
    language_id: str,
    *,
    scope_path: str | Path | None = None,
) -> dict[str, Any] | None:
    """Resolve the nearest repository-native policy for a selected source."""
    root = root.resolve()
    roots: list[Path] = []
    if scope_path is not None:
        path = Path(scope_path)
        if not path.is_absolute():
            path = root / path
        try:
            path = path.resolve()
            path.relative_to(root)
            current = path if path.is_dir() else path.parent
        except (OSError, ValueError):
            current = root
        while True:
            roots.append(current)
            if current == root:
                break
            parent = current.parent
            if parent == current or not parent.is_relative_to(root):
                roots.append(root)
                break
            current = parent
    else:
        roots = [root]
    seen: set[Path] = set()
    for candidate_root in roots:
        if candidate_root in seen:
            continue
        seen.add(candidate_root)
        policy = _repository_policy_at(candidate_root, language_id)
        if policy is not None:
            if policy.get("path") and candidate_root != root:
                policy = {
                    **policy,
                    "path": (candidate_root / str(policy["path"])).relative_to(root).as_posix(),
                }
            return policy
    return None


def resolve_policy(
    root: Path,
    language_id: str,
    *,
    configured_threshold: int | None = None,
    fallback_threshold: int = DEFAULT_THRESHOLD,
    scope_path: str | Path | None = None,
) -> dict[str, Any]:
    if configured_threshold is not None:
        value = _number(configured_threshold)
        if value is None:
            raise ValueError("complexity threshold must be greater than zero")
        return _policy(value, "review configuration")
    repository = repository_policy(root, language_id, scope_path=scope_path)
    if repository is not None:
        return repository
    fallback = _number(fallback_threshold)
    if fallback is None:
        raise ValueError("complexity fallback threshold must be greater than zero")
    return _policy(fallback, "dissect fallback", "", "lizard")


parse_repository_policy = repository_policy
