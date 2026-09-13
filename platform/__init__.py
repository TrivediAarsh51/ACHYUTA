"""ACHYUTA platform adapters.

This package also preserves the standard-library ``platform`` API because the
repository's required adapter path is ``platform.windows``.
"""

from __future__ import annotations

import importlib.util
import sysconfig
from pathlib import Path


_package_path = Path(__file__).parent
_stdlib_platform_path = Path(sysconfig.get_path("stdlib")) / "platform.py"
_stdlib_spec = importlib.util.spec_from_file_location(
    "_achyuta_stdlib_platform",
    _stdlib_platform_path,
)
if _stdlib_spec is None or _stdlib_spec.loader is None:
    raise ImportError("Unable to load the standard-library platform module.")

_stdlib_platform = importlib.util.module_from_spec(_stdlib_spec)
_stdlib_spec.loader.exec_module(_stdlib_platform)

for _name in dir(_stdlib_platform):
    if _name not in {
        "__name__",
        "__package__",
        "__loader__",
        "__spec__",
        "__file__",
        "__path__",
        "__cached__",
    }:
        globals()[_name] = getattr(_stdlib_platform, _name)

__path__ = [str(_package_path)]
