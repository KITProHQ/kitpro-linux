"""Hermetic Stable-generation fixture for installation-plan unit tests."""

from __future__ import annotations

import contextlib
import hashlib
import tempfile
from collections.abc import Iterator
from pathlib import Path
from unittest import mock

from tools import kitpro_repo
from tools.install import plan as install_plan


GENERATION = "0.1-dev-g0010"
RELEASE = "0.1-dev"
PACKAGE_COUNT = 199


@contextlib.contextmanager
def generation_fixture() -> Iterator[None]:
    """Provide build_plan with deterministic metadata but no external artifacts."""
    with tempfile.TemporaryDirectory(prefix="kitpro-plan-fixture-") as name:
        project_root = Path(name)
        generation_root = project_root / "repo/stable" / RELEASE / GENERATION
        generation_root.mkdir(parents=True)
        packages = []
        for index in range(PACKAGE_COUNT):
            filename = f"fixture-{index:03d}-1-1-x86_64.pkg.tar.zst"
            packages.append(
                {
                    "filename": filename,
                    "sha256": hashlib.sha256(filename.encode()).hexdigest(),
                }
            )
        manifest = {
            "release": RELEASE,
            "generation_id": GENERATION,
            "repositories": [{"packages": packages}],
        }
        kitpro_repo.atomic_write_json(generation_root / "manifest.json", manifest)
        with (
            mock.patch.object(install_plan, "PROJECT_ROOT", project_root),
            mock.patch.object(
                install_plan,
                "_generation",
                return_value=(generation_root, manifest),
            ),
        ):
            yield
