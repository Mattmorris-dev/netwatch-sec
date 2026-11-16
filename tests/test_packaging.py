"""Packaging guards: every module ships in the wheel and the Docker image, and
the version is stated the same way everywhere."""
import os
import re

import netwatch

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    with open(os.path.join(REPO, name), encoding="utf-8") as fh:
        return fh.read()


def _modules():
    return sorted(f[:-3] for f in os.listdir(REPO) if f.endswith(".py"))


def test_wheel_lists_every_module():
    listed = re.search(r"^py-modules = \[(.*?)\]", _read("pyproject.toml"), re.M).group(1)
    assert sorted(re.findall(r'"(\w+)"', listed)) == _modules()


def test_docker_image_copies_every_module():
    copy = [line for line in _read("Dockerfile").splitlines() if line.startswith("COPY netwatch.py")]
    assert len(copy) == 1
    missing = [m for m in _modules() if f"{m}.py" not in copy[0].split()]
    assert missing == [], f"Dockerfile COPY is missing: {missing}"


def test_version_is_the_same_everywhere():
    pyproject = re.search(r'^version = "([^"]+)"', _read("pyproject.toml"), re.M).group(1)
    changelog = re.search(r"^## (\d+\.\d+\.\d+)", _read("CHANGELOG.md"), re.M).group(1)
    assert netwatch.VERSION == pyproject == changelog


def test_python_floor_is_the_same_everywhere():
    floor = re.search(r'^requires-python = ">=([\d.]+)"', _read("pyproject.toml"), re.M).group(1)
    assert f"python-{floor}+" in _read("README.md")
    assert f"Python {floor}+" in _read("install.sh")


def test_dependency_floors_match_in_both_files():
    def floors(text):
        return dict(re.findall(r"^\s*\"?([A-Za-z0-9_.-]+)>=([\d.]+)", text, re.M))
    req = floors("\n".join(line for line in _read("requirements.txt").splitlines() if not line.startswith("#")))
    deps = re.search(r"^dependencies = \[(.*?)^\]", _read("pyproject.toml"), re.M | re.S).group(1)
    assert req and req == floors(deps)
