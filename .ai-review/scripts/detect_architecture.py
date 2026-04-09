#!/usr/bin/env python3
from __future__ import annotations

from collections import Counter
from pathlib import Path
import argparse
import json
import re

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


SKIP_DIRS = {
    ".git",
    ".next",
    ".turbo",
    ".cache",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    "__pycache__",
}
SOURCE_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".rb", ".php", ".java", ".kt", ".kts", ".cs"}
LIBRARY_CATEGORIES = {
    "framework": [
        "react",
        "next",
        "vue",
        "nuxt",
        "svelte",
        "angular",
        "django",
        "flask",
        "fastapi",
        "express",
        "nestjs",
        "koa",
        "rails",
        "laravel",
        "spring",
        "gin",
        "fiber",
        "flutter",
    ],
    "database": [
        "prisma",
        "sequelize",
        "typeorm",
        "drizzle",
        "knex",
        "mongoose",
        "sqlalchemy",
        "sqlmodel",
        "psycopg",
        "pg",
        "mysql",
        "postgres",
        "sqlite",
        "redis",
        "mongodb",
        "supabase",
    ],
    "testing": [
        "jest",
        "vitest",
        "testing-library",
        "playwright",
        "cypress",
        "pytest",
        "rspec",
        "minitest",
        "unittest",
    ],
    "http": [
        "axios",
        "requests",
        "httpx",
        "aiohttp",
        "faraday",
        "rest-client",
        "got",
    ],
    "state_management": [
        "redux",
        "zustand",
        "mobx",
        "pinia",
        "recoil",
        "xstate",
    ],
    "styling": [
        "tailwindcss",
        "styled-components",
        "emotion",
        "sass",
        "less",
        "bootstrap",
        "chakra-ui",
    ],
    "auth": [
        "next-auth",
        "authjs",
        "passport",
        "clerk",
        "auth0",
        "firebase-auth",
        "devise",
    ],
    "payments": [
        "stripe",
        "paypal",
        "braintree",
        "square",
    ],
    "validation": [
        "zod",
        "yup",
        "joi",
        "pydantic",
        "marshmallow",
        "class-validator",
    ],
}
DIRECTORY_LABELS = {
    "api": "API routes and handlers",
    "app": "application entry points and routes",
    "assets": "static assets",
    "auth": "authentication and authorization",
    "components": "UI components",
    "config": "runtime and build configuration",
    "controllers": "controller layer",
    "database": "database access and persistence",
    "db": "database access and persistence",
    "domains": "domain-oriented modules",
    "entities": "domain entities and models",
    "features": "feature modules",
    "hooks": "UI and state hooks",
    "lib": "shared utilities",
    "middleware": "middleware and request interception",
    "migrations": "database migrations",
    "models": "data models",
    "modules": "feature or domain modules",
    "pages": "page routes",
    "prisma": "database schema and migrations",
    "public": "public assets",
    "repositories": "repository layer",
    "routes": "routing layer",
    "scripts": "automation and tooling scripts",
    "services": "service layer",
    "src": "application source code",
    "store": "application state",
    "styles": "styling and design tokens",
    "test": "tests",
    "tests": "tests",
    "utils": "shared utilities",
    "views": "view layer",
}
CONFIG_PATTERNS = [
    ".editorconfig",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yaml",
    ".eslintrc.yml",
    ".prettierrc",
    ".prettierrc.js",
    ".prettierrc.cjs",
    ".prettierrc.json",
    ".prettierrc.yaml",
    ".prettierrc.yml",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.ts",
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "prettier.config.js",
    "prettier.config.cjs",
    "prettier.config.mjs",
    "prettier.config.ts",
    "tailwind.config.js",
    "tailwind.config.cjs",
    "tailwind.config.mjs",
    "tailwind.config.ts",
    "tsconfig.json",
    "tsconfig.*.json",
    "ruff.toml",
    "pyproject.toml",
    "mypy.ini",
    "pyrightconfig.json",
    "Dockerfile",
    "Dockerfile.*",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    ".github/workflows/*.yml",
    ".github/workflows/*.yaml",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=".", help="Directory to inspect")
    return parser.parse_args()


def is_skipped(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        parts = path.parts
    for part in parts:
        if part in SKIP_DIRS:
            return True
        if part.startswith(".") and part not in {".github"}:
            return True
    return False


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def read_toml(path: Path) -> dict:
    if tomllib is None:
        return {}
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def iter_files(root: Path, limit: int = 400) -> list[Path]:
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if is_skipped(path, root):
            continue
        files.append(path)
        if len(files) >= limit:
            break
    return files


def detect_patterns(root: Path) -> list[str]:
    found = []
    checks = {
        "mvc": [root / "models", root / "views", root / "controllers"],
        "component-based": [root / "components", root / "src" / "components"],
        "feature-based": [root / "features", root / "modules", root / "domains"],
        "layered": [root / "services", root / "repositories", root / "entities"],
        "pages-based": [root / "pages"],
        "app-router": [root / "app", root / "src" / "app"],
        "api-routes": [root / "api", root / "routes", root / "endpoints", root / "app" / "api", root / "pages" / "api"],
    }
    for label, candidates in checks.items():
        if any(path.exists() for path in candidates):
            found.append(label)
    return found


def package_dependencies(root: Path) -> list[str]:
    deps = []
    pkg = read_json(root / "package.json")
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        deps.extend((pkg.get(section) or {}).keys())
    return deps


def python_dependencies(root: Path) -> list[str]:
    deps = []
    pyproject = read_toml(root / "pyproject.toml")
    project = pyproject.get("project") or {}
    for item in project.get("dependencies") or []:
        if isinstance(item, str):
            deps.append(re.split(r"[<>=!~\s\[]", item, maxsplit=1)[0])
    poetry = ((pyproject.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    for name in poetry.keys():
        if str(name).lower() != "python":
            deps.append(str(name))
    return deps


def go_dependencies(root: Path) -> list[str]:
    text = read_text(root / "go.mod")
    deps = re.findall(r"^\s*require\s+([^\s]+)", text, re.M)
    deps.extend(re.findall(r"^\s*([^\s]+)\s+v[\w.+-]+\s*$", text, re.M))
    return deps


def ruby_dependencies(root: Path) -> list[str]:
    return re.findall(r"^\s*gem\s+['\"]([^'\"]+)['\"]", read_text(root / "Gemfile"), re.M)


def cargo_dependencies(root: Path) -> list[str]:
    cargo = read_toml(root / "Cargo.toml")
    deps = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        deps.extend((cargo.get(section) or {}).keys())
    return deps


def composer_dependencies(root: Path) -> list[str]:
    composer = read_json(root / "composer.json")
    deps = []
    deps.extend((composer.get("require") or {}).keys())
    deps.extend((composer.get("require-dev") or {}).keys())
    return deps


def collect_dependencies(root: Path) -> list[str]:
    deps = []
    deps.extend(package_dependencies(root))
    deps.extend(python_dependencies(root))
    deps.extend(go_dependencies(root))
    deps.extend(ruby_dependencies(root))
    deps.extend(cargo_dependencies(root))
    deps.extend(composer_dependencies(root))
    return list(dict.fromkeys(dep for dep in deps if dep))


def categorize_libraries(dependencies: list[str]) -> dict[str, list[str]]:
    categorized = {key: [] for key in LIBRARY_CATEGORIES}
    for dependency in dependencies:
        lowered = dependency.lower()
        for category, candidates in LIBRARY_CATEGORIES.items():
            if any(candidate in lowered for candidate in candidates):
                categorized[category].append(dependency)
    return {key: list(dict.fromkeys(values)) for key, values in categorized.items()}


def strip_known_suffixes(path: Path) -> str:
    name = path.name
    for suffix in [".d.ts", ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".test.js", ".spec.js"]:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def detect_name_style(name: str) -> str:
    if not name:
        return "unknown"
    if "-" in name:
        return "kebab-case"
    if "_" in name:
        return "snake_case"
    if re.match(r"^[A-Z][A-Za-z0-9]+$", name):
        return "PascalCase"
    if re.match(r"^[a-z][A-Za-z0-9]*$", name):
        return "camelCase"
    return "unknown"


def most_common(counter: Counter) -> str:
    for value, _count in counter.most_common():
        if value != "unknown":
            return value
    return ""


def detect_test_pattern(paths: list[Path]) -> str:
    labels = Counter()
    for path in paths:
        name = path.name
        if ".test." in name:
            labels[f"*.test{path.suffix}"] += 1
        elif ".spec." in name:
            labels[f"*.spec{path.suffix}"] += 1
        elif name.endswith("_test.go"):
            labels["*_test.go"] += 1
        elif name.startswith("test_"):
            labels[f"test_*{path.suffix}"] += 1
        elif name.endswith("_spec.rb"):
            labels["*_spec.rb"] += 1
    return labels.most_common(1)[0][0] if labels else ""


def detect_naming(root: Path, files: list[Path]) -> dict[str, str]:
    file_styles = Counter()
    variable_styles = Counter()
    component_styles = Counter()

    for path in files[:80]:
        file_styles[detect_name_style(strip_known_suffixes(path))] += 1
        text = read_text(path)
        if path.suffix in {".py"}:
            for match in re.finditer(r"^\s*(?:def|async\s+def)\s+([A-Za-z_][A-Za-z0-9_]*)|^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", text, re.M):
                name = next(group for group in match.groups() if group)
                variable_styles[detect_name_style(name)] += 1
        elif path.suffix in {".js", ".jsx", ".ts", ".tsx"}:
            for match in re.finditer(r"\b(?:const|let|var|function|class)\s+([A-Za-z_$][A-Za-z0-9_$]*)", text):
                variable_styles[detect_name_style(match.group(1))] += 1
            if path.suffix in {".jsx", ".tsx"}:
                for match in re.finditer(r"(?:export\s+default\s+function|export\s+function|const)\s+([A-Z][A-Za-z0-9]*)", text):
                    component_styles["PascalCase"] += 1

    return {
        "files": most_common(file_styles),
        "variables": most_common(variable_styles),
        "components": most_common(component_styles),
        "tests": detect_test_pattern(files),
    }


def describe_directory(rel: str) -> str:
    parts = rel.split("/")
    last = parts[-1]
    return DIRECTORY_LABELS.get(last, DIRECTORY_LABELS.get(parts[0], "application code"))


def detect_folder_structure(root: Path) -> dict[str, str]:
    structure = {}
    candidates = []
    for path in sorted(root.iterdir()):
        if not path.is_dir() or is_skipped(path, root):
            continue
        candidates.append(path)
        for child in sorted(path.iterdir()):
            if child.is_dir() and not is_skipped(child, root):
                candidates.append(child)
    for path in candidates[:30]:
        rel = path.relative_to(root).as_posix()
        structure[rel] = describe_directory(rel)
    return structure


def detect_config_files(root: Path) -> list[str]:
    found = []
    for pattern in CONFIG_PATTERNS:
        for path in root.glob(pattern):
            if path.is_file() and not is_skipped(path, root):
                found.append(path.relative_to(root).as_posix())
    return list(dict.fromkeys(sorted(found)))


def readme_description(root: Path) -> str:
    readme = root / "README.md"
    text = read_text(readme)
    if not text:
        return ""
    paragraphs = []
    current = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            if current:
                paragraphs.append(" ".join(current).strip())
                current = []
            continue
        if line.startswith("#") or line.startswith("![") or line.startswith("[!["):
            continue
        current.append(line)
    if current:
        paragraphs.append(" ".join(current).strip())
    return paragraphs[0] if paragraphs else ""


def project_description(root: Path) -> str:
    description = readme_description(root)
    if description:
        return description
    package_description = (read_json(root / "package.json").get("description") or "").strip()
    if package_description:
        return package_description
    pyproject = read_toml(root / "pyproject.toml")
    return ((pyproject.get("project") or {}).get("description") or "").strip()


def detect_entry_points(root: Path) -> list[str]:
    entries = []
    package_data = read_json(root / "package.json")
    for key in ("main", "module", "browser"):
        value = package_data.get(key)
        if isinstance(value, str) and value:
            entries.append(value)
    binary = package_data.get("bin")
    if isinstance(binary, str):
        entries.append(binary)
    elif isinstance(binary, dict):
        entries.extend(v for v in binary.values() if isinstance(v, str))

    conventional = [
        "app/layout.tsx",
        "src/app/layout.tsx",
        "src/main.ts",
        "src/main.tsx",
        "src/main.js",
        "src/main.jsx",
        "main.go",
        "Program.cs",
        "__main__.py",
        "manage.py",
        "app.py",
    ]
    for relative in conventional:
        if (root / relative).exists():
            entries.append(relative)
    return list(dict.fromkeys(entries))


def detect_env_keys(root: Path) -> list[str]:
    keys = []
    for name in [".env.example", ".env.sample", ".env.template", ".env.defaults"]:
        path = root / name
        if not path.exists():
            continue
        for line in read_text(path).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key = stripped.split("=", 1)[0].strip()
            if key:
                keys.append(key)
    return list(dict.fromkeys(keys))


def detect_docker_services(root: Path) -> list[str]:
    services = []
    for name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
        path = root / name
        if not path.exists():
            continue
        text = read_text(path)
        in_services = False
        base_indent = None
        for line in text.splitlines():
            if re.match(r"^\s*services\s*:\s*$", line):
                in_services = True
                base_indent = len(line) - len(line.lstrip(" "))
                continue
            if not in_services:
                continue
            if not line.strip():
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent <= (base_indent or 0):
                in_services = False
                continue
            match = re.match(r"^\s{2,}([A-Za-z0-9._-]+)\s*:\s*$", line)
            if match:
                services.append(match.group(1))
    return list(dict.fromkeys(services))


def refinement_needed(architecture: dict) -> list[str]:
    items = ["Confirm architecture pattern classification"]
    if not architecture["project_description"]:
        items.append("Add a concise project description from the codebase context")
    if not architecture["naming"].get("files") or not architecture["naming"].get("variables"):
        items.append("Identify naming conventions not captured by heuristics")
    else:
        items.append("Identify domain-specific conventions not captured by heuristics")
    if not any(architecture["key_libraries"].values()):
        items.append("Verify key libraries and runtime integrations")
    if not architecture["folder_structure"]:
        items.append("Label important folders that heuristics could not classify")
    if not architecture["env_keys"] and not architecture["docker_services"]:
        items.append("Confirm required environment setup and local services")
    return list(dict.fromkeys(items))


def main() -> None:
    args = parse_args()
    root = Path(args.dir).resolve()
    files = [path for path in iter_files(root) if path.suffix.lower() in SOURCE_EXTENSIONS]

    architecture = {
        "patterns": detect_patterns(root),
        "key_libraries": categorize_libraries(collect_dependencies(root)),
        "naming": detect_naming(root, files),
        "folder_structure": detect_folder_structure(root),
        "config_files": detect_config_files(root),
        "entry_points": detect_entry_points(root),
        "project_description": project_description(root),
        "env_keys": detect_env_keys(root),
        "docker_services": detect_docker_services(root),
        "ai_refinement_needed": [],
    }
    architecture["ai_refinement_needed"] = refinement_needed(architecture)

    print(json.dumps({"architecture": architecture}, indent=2))


if __name__ == "__main__":
    main()
