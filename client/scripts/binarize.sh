#!/bin/bash

set -e

poetry install

ROOT=$(pwd)
VENV=$(poetry env info -p)
PYTHON=$(poetry env info --executable)

TEMPDIR=$(mktemp -d)
(
	cd "$TEMPDIR"

	ln -s "$ROOT/src"
	ln -s "$ROOT" dist
	ln -s "$VENV/bin/augsburg-traceroute"

	"$PYTHON" -m PyInstaller -F augsburg-traceroute
)

rm -r "$TEMPDIR"
