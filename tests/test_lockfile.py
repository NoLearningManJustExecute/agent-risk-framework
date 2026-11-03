"""The lockfile must agree with the exact pins in pyproject.toml."""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK_PIN = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;]+)", re.MULTILINE)


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def test_every_direct_pin_is_exact_and_in_the_lockfile() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = config["project"]
    direct = [*project["dependencies"], *project["optional-dependencies"]["dev"]]
    lock_text = (ROOT / "requirements-lock.txt").read_text(encoding="utf-8")
    lock = {normalized(name): version for name, version in LOCK_PIN.findall(lock_text)}
    assert direct
    for requirement in direct:
        name, separator, version = requirement.partition("==")
        assert separator, requirement
        assert lock.get(normalized(name)) == version, requirement


def test_build_backend_is_an_exact_pin() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert all("==" in requirement for requirement in config["build-system"]["requires"])
