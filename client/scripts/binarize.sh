#!/bin/bash

set -e

export HOME=$(mktemp -d -p /var/tmp)
export POETRY_HOME=$HOME/.local
export PATH=$PATH:$POETRY_HOME/bin

curl -sSL https://install.python-poetry.org | python3 -
ROOT=$(pwd)

TEMPDIR=$(mktemp -d)
cp -r * $TEMPDIR/
(
	cd "$TEMPDIR"
	
	poetry install
	CLIENT=$(poetry run which augsburg-traceroute)
	poetry run pyinstaller -F $CLIENT

	cp -r dist/* $ROOT/
)

rm -r "$TEMPDIR"
