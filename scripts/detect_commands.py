#!/usr/bin/env python3
from __future__ import annotations

from collections import OrderedDict
from pathlib import Path
import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


ROOT = Path.cwd()
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".idea",
    ".vscode",
    ".turbo",
    ".next",
    ".cache",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    "out",
    "tmp",
    "__pycache__",
}
REPO_MARKERS = {
    "package.json",
    "go.mod",
    "Cargo.toml",
    "pyproject.toml",
    "requirements.txt",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "pubspec.yaml",
    "Package.swift",
}
REPO_GLOBS = ("*.sln", "*.csproj")


def empty_result() -> dict:
    return {
        "stack": [],
        "package_managers": [],
        "commands": {
            "install": "",
            "lint": "",
            "typecheck": "",
            "test": "",
            "build": "",
            "format": "",
        },
        "paths": {
            "generated": [],
            "ignore": [],
            "critical": [],
        },
        "risk": {
            "auth_sensitive": [],
            "payment_sensitive": [],
            "migration_sensitive": [],
            "infra_sensitive": [],
            "pii_sensitive": [],
            "destructive_sensitive": [],
        },
        "architecture": {},
        "notes": [],
        "uncertain": [],
    }


def add_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def dedupe_in_place(result: dict) -> dict:
    for key in ("stack", "package_managers", "notes", "uncertain"):
        result[key] = list(dict.fromkeys(result.get(key, [])))
    for key in ("generated", "ignore", "critical"):
        result["paths"][key] = list(dict.fromkeys((result.get("paths") or {}).get(key, [])))
    for key, values in (result.get("risk") or {}).items():
        result["risk"][key] = list(dict.fromkeys(values))
    return result


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def read_toml(path: Path) -> dict:
    if tomllib is None:
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def exists(directory: Path, *names: str) -> bool:
    return any((directory / name).exists() for name in names)


def should_skip_dir(path: Path) -> bool:
    return any(part in SKIP_DIRS or part.startswith(".") for part in path.parts if part not in {".", ""})


def has_repo_marker(path: Path) -> bool:
    for marker in REPO_MARKERS:
        if (path / marker).exists():
            return True
    return any(True for pattern in REPO_GLOBS for _ in path.glob(pattern))


def normalize_workspace_name(path: Path, root: Path) -> str:
    rel = path.relative_to(root)
    return rel.as_posix()


def parse_package_manager(directory: Path, result: dict) -> tuple[str, str]:
    if (directory / "pnpm-lock.yaml").exists():
        add_unique(result["package_managers"], "pnpm")
        return "pnpm", "pnpm"
    if (directory / "yarn.lock").exists():
        add_unique(result["package_managers"], "yarn")
        return "yarn", "yarn"
    if (directory / "bun.lockb").exists() or (directory / "bun.lock").exists():
        add_unique(result["package_managers"], "bun")
        return "bun", "bun"
    add_unique(result["package_managers"], "npm")
    return "npm", "npm run"


def detect_for_directory(directory: Path) -> dict:
    result = empty_result()

    pkg = directory / "package.json"
    if pkg.exists():
        add_unique(result["stack"], "javascript/typescript")
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {}) or {}
            manager, runner = parse_package_manager(directory, result)
            installs = {
                "pnpm": "pnpm install",
                "yarn": "yarn install",
                "bun": "bun install",
                "npm": "npm install",
            }
            result["commands"]["install"] = installs[manager]
            if "lint" in scripts:
                result["commands"]["lint"] = f"{runner} lint"
            if "typecheck" in scripts:
                result["commands"]["typecheck"] = f"{runner} typecheck"
            elif "check-types" in scripts:
                result["commands"]["typecheck"] = f"{runner} check-types"
            if "test" in scripts:
                result["commands"]["test"] = f"{runner} test"
            if "build" in scripts:
                result["commands"]["build"] = f"{runner} build"
            if "format" in scripts:
                result["commands"]["format"] = f"{runner} format"
            if exists(directory, "next.config.js", "next.config.mjs", "next.config.ts"):
                add_unique(result["stack"], "nextjs")
                add_unique(result["paths"]["critical"], "app/")
                add_unique(result["paths"]["critical"], "middleware.ts")
                add_unique(result["risk"]["auth_sensitive"], "middleware.ts")
            if exists(directory, "tsconfig.json"):
                add_unique(result["stack"], "typescript")
            if (directory / "turbo.json").exists():
                add_unique(result["stack"], "turborepo")
            if (directory / "nx.json").exists():
                add_unique(result["stack"], "nx")
            if (directory / "lerna.json").exists():
                add_unique(result["stack"], "lerna")
        except Exception as exc:
            result["uncertain"].append(f"Could not parse package.json: {exc}")

    if exists(directory, "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "Pipfile", "poetry.lock", "uv.lock"):
        add_unique(result["stack"], "python")
        if (directory / "uv.lock").exists():
            add_unique(result["package_managers"], "uv")
            result["commands"]["install"] = result["commands"]["install"] or "uv sync"
            result["commands"]["test"] = result["commands"]["test"] or "uv run pytest"
            result["commands"]["lint"] = result["commands"]["lint"] or "uv run ruff check ."
            result["commands"]["format"] = result["commands"]["format"] or "uv run ruff format --check ."
        elif (directory / "poetry.lock").exists():
            add_unique(result["package_managers"], "poetry")
            result["commands"]["install"] = result["commands"]["install"] or "poetry install"
            result["commands"]["test"] = result["commands"]["test"] or "poetry run pytest"
            result["commands"]["lint"] = result["commands"]["lint"] or "poetry run ruff check ."
        else:
            add_unique(result["package_managers"], "pip")
            requirements = "requirements.txt" if (directory / "requirements.txt").exists() else "."
            install = "python -m pip install -r requirements.txt" if requirements == "requirements.txt" else "python -m pip install ."
            result["commands"]["install"] = result["commands"]["install"] or install
            result["commands"]["test"] = result["commands"]["test"] or "pytest"
            result["commands"]["lint"] = result["commands"]["lint"] or "ruff check ."
        if exists(directory, "mypy.ini", "pyrightconfig.json"):
            typecheck = "mypy ." if (directory / "mypy.ini").exists() else "pyright"
            result["commands"]["typecheck"] = result["commands"]["typecheck"] or typecheck

    if exists(directory, "go.mod"):
        add_unique(result["stack"], "go")
        add_unique(result["package_managers"], "go")
        result["commands"]["test"] = result["commands"]["test"] or "go test ./..."
        result["commands"]["build"] = result["commands"]["build"] or "go build ./..."
        result["commands"]["lint"] = result["commands"]["lint"] or "go vet ./..."

    if exists(directory, "Cargo.toml"):
        add_unique(result["stack"], "rust")
        add_unique(result["package_managers"], "cargo")
        result["commands"]["test"] = result["commands"]["test"] or "cargo test"
        result["commands"]["build"] = result["commands"]["build"] or "cargo build"
        result["commands"]["lint"] = result["commands"]["lint"] or "cargo clippy -- -D warnings"
        result["commands"]["format"] = result["commands"]["format"] or "cargo fmt -- --check"

    if exists(directory, "Gemfile"):
        add_unique(result["stack"], "ruby")
        add_unique(result["package_managers"], "bundler")
        result["commands"]["install"] = result["commands"]["install"] or "bundle install"
        result["commands"]["test"] = result["commands"]["test"] or "bundle exec rspec"
        result["commands"]["lint"] = result["commands"]["lint"] or "bundle exec rubocop"

    if exists(directory, "composer.json"):
        add_unique(result["stack"], "php")
        add_unique(result["package_managers"], "composer")
        result["commands"]["install"] = result["commands"]["install"] or "composer install"
        result["commands"]["test"] = result["commands"]["test"] or "composer test"
        result["commands"]["lint"] = result["commands"]["lint"] or "composer lint"

    if exists(directory, "pom.xml"):
        add_unique(result["stack"], "java")
        add_unique(result["package_managers"], "maven")
        result["commands"]["install"] = result["commands"]["install"] or "mvn -q -DskipTests compile"
        result["commands"]["test"] = result["commands"]["test"] or "mvn test"
        result["commands"]["build"] = result["commands"]["build"] or "mvn package"

    if exists(directory, "build.gradle", "build.gradle.kts"):
        add_unique(result["stack"], "java/kotlin")
        add_unique(result["package_managers"], "gradle")
        gradle = "./gradlew" if (directory / "gradlew").exists() else "gradle"
        result["commands"]["test"] = result["commands"]["test"] or f"{gradle} test"
        result["commands"]["build"] = result["commands"]["build"] or f"{gradle} build"

    if any(directory.glob("*.sln")) or any(directory.glob("*.csproj")):
        add_unique(result["stack"], ".net")
        add_unique(result["package_managers"], "dotnet")
        result["commands"]["build"] = result["commands"]["build"] or "dotnet build"
        result["commands"]["test"] = result["commands"]["test"] or "dotnet test"

    if exists(directory, "Package.swift"):
        add_unique(result["stack"], "swift")
        add_unique(result["package_managers"], "swift")
        result["commands"]["build"] = result["commands"]["build"] or "swift build"
        result["commands"]["test"] = result["commands"]["test"] or "swift test"

    if exists(directory, "pubspec.yaml"):
        text = read_text(directory / "pubspec.yaml")
        add_unique(result["package_managers"], "dart")
        if "flutter:" in text:
            add_unique(result["stack"], "flutter")
            result["commands"]["install"] = result["commands"]["install"] or "flutter pub get"
            result["commands"]["test"] = result["commands"]["test"] or "flutter test"
            result["commands"]["build"] = result["commands"]["build"] or "flutter build"
        else:
            add_unique(result["stack"], "dart")
            result["commands"]["install"] = result["commands"]["install"] or "dart pub get"
            result["commands"]["test"] = result["commands"]["test"] or "dart test"

    if any(directory.rglob("*.tf")):
        add_unique(result["stack"], "terraform")
        add_unique(result["package_managers"], "terraform")
        result["commands"]["format"] = result["commands"]["format"] or "terraform fmt -check -recursive"
        result["commands"]["build"] = result["commands"]["build"] or "terraform validate"
        add_unique(result["risk"]["infra_sensitive"], "*.tf")
        add_unique(result["paths"]["critical"], "infra/")

    for pattern in ["migrations", "db/migrations", "supabase/migrations", "prisma/migrations"]:
        if (directory / pattern).exists():
            add_unique(result["risk"]["migration_sensitive"], pattern)
            add_unique(result["paths"]["critical"], pattern)

    for pattern in ["auth", "src/auth", "app/api", "pages/api", "supabase", "database", "db", "payments", "billing"]:
        if (directory / pattern).exists():
            add_unique(result["paths"]["critical"], pattern)

    if (directory / ".github" / "workflows").exists():
        add_unique(result["paths"]["critical"], ".github/workflows")

    return dedupe_in_place(result)


def expand_patterns(root: Path, patterns: list[str]) -> list[Path]:
    discovered: list[Path] = []
    for raw in patterns:
        pattern = (raw or "").strip()
        if not pattern or pattern.startswith("!"):
            continue
        for path in root.glob(pattern):
            if not path.is_dir() or path == root or should_skip_dir(path.relative_to(root)):
                continue
            discovered.append(path.resolve())
    return discovered


def discover_from_package_json(root: Path) -> list[Path]:
    data = read_json(root / "package.json")
    workspaces = data.get("workspaces")
    patterns: list[str] = []
    if isinstance(workspaces, list):
        patterns.extend(x for x in workspaces if isinstance(x, str))
    elif isinstance(workspaces, dict):
        patterns.extend(x for x in (workspaces.get("packages") or []) if isinstance(x, str))
    return expand_patterns(root, patterns)


def discover_from_pnpm(root: Path) -> list[Path]:
    text = read_text(root / "pnpm-workspace.yaml")
    patterns = re.findall(r"^\s*-\s*['\"]?([^'\"]+)['\"]?\s*$", text, re.M)
    return expand_patterns(root, patterns)


def discover_from_cargo(root: Path) -> list[Path]:
    cargo = read_toml(root / "Cargo.toml")
    workspace = cargo.get("workspace") or {}
    members = workspace.get("members") or []
    return expand_patterns(root, [m for m in members if isinstance(m, str)])


def discover_from_lerna(root: Path) -> list[Path]:
    data = read_json(root / "lerna.json")
    packages = data.get("packages") or []
    return expand_patterns(root, [p for p in packages if isinstance(p, str)])


def discover_from_nx(root: Path) -> list[Path]:
    if not (root / "nx.json").exists():
        return []
    patterns = []
    for candidate in ["apps/*", "libs/*", "packages/*"]:
        if any(root.glob(candidate)):
            patterns.append(candidate)
    return expand_patterns(root, patterns)


def discover_from_turbo(root: Path) -> list[Path]:
    if not (root / "turbo.json").exists():
        return []
    patterns = []
    for candidate in ["apps/*", "libs/*", "packages/*"]:
        if any(root.glob(candidate)):
            patterns.append(candidate)
    return expand_patterns(root, patterns)


def discover_workspaces(root: Path) -> list[tuple[str, Path]]:
    explicit = OrderedDict()
    for path in (
        discover_from_package_json(root)
        + discover_from_pnpm(root)
        + discover_from_cargo(root)
        + discover_from_lerna(root)
        + discover_from_nx(root)
        + discover_from_turbo(root)
    ):
        if path == root:
            continue
        explicit[normalize_workspace_name(path, root)] = path

    if explicit:
        return list(explicit.items())

    fallback = []
    for child in sorted(root.iterdir()):
        if not child.is_dir():
            continue
        if should_skip_dir(child.relative_to(root)):
            continue
        if has_repo_marker(child):
            fallback.append((normalize_workspace_name(child, root), child.resolve()))
    return fallback


def main() -> None:
    root_result = detect_for_directory(ROOT)
    detected = {
        "project": {
            "stack": list(root_result["stack"]),
            "package_managers": list(root_result["package_managers"]),
            "monorepo": False,
        },
        "commands": root_result["commands"],
        "paths": root_result["paths"],
        "risk": root_result["risk"],
        "architecture": {},
        "workspaces": {},
        "notes": list(root_result["notes"]),
        "uncertain": list(root_result["uncertain"]),
    }

    sub_repos = discover_workspaces(ROOT)
    if sub_repos:
        detected["project"]["monorepo"] = True
        for name, path in sub_repos:
            workspace_result = detect_for_directory(path)
            workspace_result["root"] = str(path.relative_to(ROOT))
            detected["workspaces"][name] = workspace_result

    print(json.dumps(detected, indent=2))


if __name__ == "__main__":
    main()
