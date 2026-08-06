from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
import re
import shlex
import tomllib

from file_paths import iter_files
from typing import Callable


KNOWN_IMPORT_ALIASES = {
    "pil": "pillow",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit_learn",
    "cv2": "opencv_python",
}


@dataclass(frozen=True)
class PythonDependencyContext:
    paths: tuple[Path, ...]
    distributions: frozenset[str]
    constraints: frozenset[str] = frozenset()


def normalise_name(value: str) -> str:
    return re.sub(r"[-_.]+", "_", value).lower()


def dependency_name(specifier: str) -> str | None:
    editable = re.search(r"(?:#|&)egg=([A-Za-z0-9][A-Za-z0-9._-]*)", specifier)
    if editable:
        return normalise_name(editable.group(1))
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", specifier)
    return normalise_name(match.group(1)) if match else None


def _strip_comment(line: str) -> str:
    quote = ""
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
        elif char in {"'", '"'}:
            quote = "" if quote == char else (char if not quote else quote)
        elif char == "#" and not quote and (index == 0 or line[index - 1].isspace()):
            return line[:index]
    return line


def _requirement_file(
    path: Path,
    root: Path,
    visited: set[tuple[Path, str]],
    requirements: set[str],
    constraints: set[str],
    paths: list[Path],
    errors: list[str],
    *,
    mode: str,
) -> None:
    resolved = path.resolve()
    visit = (resolved, mode)
    if visit in visited:
        return
    visited.add(visit)
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        errors.append(f"dependency context: {mode} include escapes repository: {path}")
        return
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        try:
            label = path.relative_to(root).as_posix()
        except ValueError:
            label = path.as_posix()
        include_kind = "requirements" if mode == "requirement" else "constraint"
        errors.append(f"dependency context: missing included {include_kind} file {label}")
        return
    paths.append(path.relative_to(root))
    logical_lines = []
    pending = ""
    for raw in text.splitlines():
        pending += raw
        if pending.rstrip().endswith("\\"):
            pending = pending.rstrip()[:-1] + " "
            continue
        logical_lines.append(pending)
        pending = ""
    if pending:
        logical_lines.append(pending)
    for raw in logical_lines:
        line = _strip_comment(raw).strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            errors.append(f"dependency context: malformed requirement in {paths[-1].as_posix()}")
            continue
        if not tokens:
            continue
        if tokens[0] in {"-r", "--requirement", "-c", "--constraint"} and len(tokens) >= 2:
            included_mode = (
                "requirement" if tokens[0] in {"-r", "--requirement"} else "constraint"
            )
            _requirement_file(
                path.parent / tokens[1],
                root,
                visited,
                requirements,
                constraints,
                paths,
                errors,
                mode=included_mode,
            )
            continue
        for prefix in ("--requirement=", "--constraint="):
            if tokens[0].startswith(prefix):
                included_mode = (
                    "requirement" if prefix == "--requirement=" else "constraint"
                )
                _requirement_file(
                    path.parent / tokens[0][len(prefix):],
                    root,
                    visited,
                    requirements,
                    constraints,
                    paths,
                    errors,
                    mode=included_mode,
                )
                break
        else:
            specifier = line
            if tokens[0] in {"-e", "--editable"} and len(tokens) >= 2:
                specifier = tokens[1]
            elif tokens[0].startswith("--editable="):
                specifier = tokens[0].split("=", 1)[1]
            dependency = dependency_name(specifier)
            if dependency and not specifier.startswith((".", "/")):
                target = constraints if mode == "constraint" else requirements
                target.add(dependency)


def load_python_manifests(
    root: Path,
    ignored: Callable[[str], bool],
) -> tuple[dict[Path, PythonDependencyContext], list[str]]:
    collected: dict[Path, tuple[list[Path], set[str], set[str]]] = {}
    errors = []

    def add(
        directory: Path,
        paths: list[Path],
        dependencies: set[str],
        constraints: set[str] | None = None,
    ) -> None:
        known_paths, known_dependencies, known_constraints = collected.setdefault(
            directory, ([], set(), set())
        )
        known_paths.extend(path for path in paths if path not in known_paths)
        known_dependencies.update(dependencies)
        known_constraints.update(constraints or ())

    for path in iter_files(
        root,
        should_skip_dir=lambda directory: ignored(directory.relative_to(root).as_posix()),
    ):
        rel = path.relative_to(root)
        if ignored(rel.as_posix()):
            continue
        if path.name == "pyproject.toml":
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except OSError:
                errors.append(f"dependency context: could not read {rel.as_posix()}")
                continue
            except tomllib.TOMLDecodeError:
                errors.append(f"dependency context: invalid TOML in {rel.as_posix()}")
                continue
            dependencies = {
                dependency
                for specifier in (data.get("project") or {}).get("dependencies", [])
                if isinstance(specifier, str)
                for dependency in [dependency_name(specifier)]
                if dependency
            }
            for values in ((data.get("project") or {}).get("optional-dependencies") or {}).values():
                dependencies.update(
                    dependency
                    for specifier in values
                    if isinstance(specifier, str)
                    for dependency in [dependency_name(specifier)]
                    if dependency
                )
            poetry = ((data.get("tool") or {}).get("poetry") or {})
            poetry_groups = [poetry.get("dependencies") or {}]
            poetry_groups.extend(
                (group or {}).get("dependencies") or {}
                for group in (poetry.get("group") or {}).values()
            )
            for group in poetry_groups:
                dependencies.update(
                    normalise_name(package) for package in group if package.lower() != "python"
                )
            uv = ((data.get("tool") or {}).get("uv") or {})
            groups = [
                uv.get("dev-dependencies") or [],
                *((data.get("dependency-groups") or {}).values()),
            ]
            for values in groups:
                dependencies.update(
                    dependency
                    for specifier in values
                    if isinstance(specifier, str)
                    for dependency in [dependency_name(specifier)]
                    if dependency
                )
            add(rel.parent, [rel], dependencies)
        elif re.fullmatch(
            r"(?:requirements|constraints)(?:[-_.][A-Za-z0-9_.-]+)?\.(?:txt|in)",
            path.name,
            re.I,
        ):
            dependencies: set[str] = set()
            constraints: set[str] = set()
            paths: list[Path] = []
            mode = "constraint" if path.name.lower().startswith("constraints") else "requirement"
            _requirement_file(
                path,
                root,
                set(),
                dependencies,
                constraints,
                paths,
                errors,
                mode=mode,
            )
            add(rel.parent, paths, dependencies, constraints)
        elif path.name == "Pipfile":
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except OSError:
                errors.append(f"dependency context: could not read {rel.as_posix()}")
                continue
            except tomllib.TOMLDecodeError:
                errors.append(f"dependency context: invalid TOML in {rel.as_posix()}")
                continue
            dependencies = {
                normalise_name(package)
                for section in ("packages", "dev-packages")
                for package in (data.get(section) or {})
            }
            add(rel.parent, [rel], dependencies)
    return {
        directory: PythonDependencyContext(
            tuple(sorted(paths)),
            frozenset(dependencies),
            frozenset(constraints),
        )
        for directory, (paths, dependencies, constraints) in collected.items()
    }, errors


def nearest_context(
    rel: str,
    manifests: dict[Path, PythonDependencyContext],
) -> PythonDependencyContext | None:
    parent = Path(rel).parent
    for directory in (parent, *parent.parents):
        if directory in manifests:
            return manifests[directory]
    return manifests.get(Path("."))


def installed_aliases() -> dict[str, set[str]]:
    try:
        packages = metadata.packages_distributions()
    except Exception:
        return {}
    return {
        normalise_name(module): {normalise_name(distribution) for distribution in distributions}
        for module, distributions in packages.items()
    }
