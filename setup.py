"""Compatibility shim.

Configuration lives in ``pyproject.toml``. This shim lets older pip versions
(<21.3, which lack PEP 660 editable support) still run ``pip install -e .`` and
register the ``aos8-acl-convert`` console script via legacy ``setup.py develop``.
Modern pip uses ``pyproject.toml`` directly and ignores this file's specifics.
"""

from setuptools import setup

setup()
