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
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    return result if result > 0 else None


def _pyproject(root: Path) -> dict[str, Any] | None:
    try:
        with (root / "pyproject.toml").open("rb") as handle:
            value = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return value if isinstance(value, dict) else None


def repository_policy(root: Path, language_id: str) -> dict[str, Any] | None:
    root = root.resolve()
    pyproject = _pyproject(root)
    if pyproject is not None and language_id == "python":
        candidates = (
            ((pyproject.get("tool") or {}).get("ruff") or {}).get("lint", {}).get("mccabe", {}).get("max-complexity"),
            ((pyproject.get("tool") or {}).get("ruff") or {}).get("mccabe", {}).get("max-complexity"),
            ((pyproject.get("tool") or {}).get("flake8") or {}).get("max-complexity"),
        )
        for value in candidates:
            threshold = _number(value)
            if threshold is not None:
                return _policy(threshold, "repository", "pyproject.toml", "C901")
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
        for filename in (".eslintrc.json", ".eslintrc", "eslint.config.json"):
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
            match = re.search(r"complexity\s*[:(,]\s*(?:['\"](?:error|warn)['\"]\s*,\s*)?(\d+)", text)
            if match:
                return _policy(int(match.group(1)), "repository", filename, "complexity")

    if language_id == "go":
        for filename in (".golangci.yml", ".golangci.yaml"):
            path = root / filename
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            match = re.search(r"(?:gocyclo|cyclop)[^\n]{0,180}?(?:min-complexity|threshold)\s*:\s*(\d+)", text, re.I | re.S)
            if match:
                rule = "gocyclo" if "gocyclo" in match.group(0).lower() else "cyclop"
                return _policy(int(match.group(1)), "repository", filename, rule)
    return None


def resolve_policy(root: Path, language_id: str, *, configured_threshold: int | None = None, fallback_threshold: int = DEFAULT_THRESHOLD) -> dict[str, Any]:
    if configured_threshold is not None:
        value = _number(configured_threshold)
        if value is None:
            raise ValueError("complexity threshold must be greater than zero")
        return _policy(value, "review configuration")
    repository = repository_policy(root, language_id)
    if repository is not None:
        return repository
    fallback = _number(fallback_threshold)
    if fallback is None:
        raise ValueError("complexity fallback threshold must be greater than zero")
    return _policy(fallback, "dissect fallback", "", "lizard")


parse_repository_policy = repository_policy
