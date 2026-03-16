#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

usage() {
  cat <<'EOF'
Usage: scripts/release.sh [options]

Build and upload a release with uv + twine from a clean git working tree.

Options:
  --repository <name>  Twine repository name (default: pypi, e.g. testpypi)
  --skip-checks        Skip sync/tests/pre-commit checks before build
  --skip-tag           Do not create git tag for the current project version
  -h, --help           Show this help

Examples:
  scripts/release.sh
  scripts/release.sh --repository testpypi
  scripts/release.sh --skip-checks --skip-tag
EOF
}

repository="pypi"
skip_checks="false"
skip_tag="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repository)
      repository="$2"
      shift 2
      ;;
    --skip-checks)
      skip_checks="true"
      shift
      ;;
    --skip-tag)
      skip_tag="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is required but was not found in PATH." >&2
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required but was not found in PATH." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit/stash changes before releasing." >&2
  git status --short
  exit 1
fi

version="$({
python3 - <<'PY'
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib

project = tomllib.loads(Path("pyproject.toml").read_text())
print(project["project"]["version"])
PY
} | tr -d '[:space:]')"

if [[ -z "${version}" ]]; then
  echo "Unable to read project.version from pyproject.toml" >&2
  exit 1
fi

echo "Preparing release ${version} (repository: ${repository})"

if [[ "${skip_checks}" != "true" ]]; then
  echo "Running quality checks..."
  uv sync --extra dev --locked
  uv run pytest -q
  uv run pre-commit run --all-files
fi

echo "Building artifacts..."
rm -rf dist build
uv build

echo "Validating artifacts..."
uvx twine check dist/*

echo "Uploading artifacts to ${repository}..."
if [[ "${repository}" == "pypi" ]]; then
  uvx twine upload dist/*
else
  uvx twine upload --repository "${repository}" dist/*
fi

if [[ "${skip_tag}" != "true" ]]; then
  if git rev-parse -q --verify "refs/tags/${version}" >/dev/null; then
    echo "Tag ${version} already exists. Skipping tag creation." >&2
  else
    git tag -a "${version}" -m "Release ${version}"
    echo "Created tag ${version}."
    echo "Push it with: git push origin ${version}"
  fi
fi

echo "Release ${version} complete."
