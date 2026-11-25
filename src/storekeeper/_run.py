"""Runs the command line from a source checkout or an install, also under -I
(which leaves this file's folder off sys.path): with-key.sh calls it so."""

import importlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.exit(importlib.import_module("storekeeper.cli").main(sys.argv[1:]))
