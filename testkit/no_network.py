"""The one guard every test uses: no socket may open. The client sends through
storekeeper.client._urlopen (no redirects); anything else would use urlopen."""

from __future__ import annotations

import importlib
import unittest
import urllib.request
from unittest import mock


def no_socket(*_a, **_k):
    raise AssertionError("a test opened a socket")


def block_network(case: unittest.TestCase) -> None:
    client = importlib.import_module("storekeeper.client")  # the caller has put src/ on sys.path
    for target in ((urllib.request, "urlopen"), (client, "_urlopen")):
        guard = mock.patch.object(*target, no_socket)
        guard.start()
        case.addCleanup(guard.stop)
