#!/usr/bin/env python3
"""
Thin wrapper — runs the NIST builder MCP server without installing the package.

Useful for development or running directly with:
  python3 server.py

The canonical server implementation lives in nist_builder/server.py.
"""
import sys
import os

# Ensure the package is importable when run from this directory
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nist_builder.server import run

if __name__ == "__main__":
    run()
