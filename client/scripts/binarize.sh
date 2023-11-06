#!/bin/bash

set -e

command -v poetry >/dev/null 2>&1 || {
	export HOME=$(mktemp -d -p /var/tmp)
	export POETRY_HOME=$HOME/.local
	export PATH=$PATH:$POETRY_HOME/bin

	curl -sSL https://install.python-poetry.org | python3 -
}

poetry install
poetry run $SHELL <<- 'DONE'
	CLIENT=$(which augsburg-traceroute)
	pyinstaller -F $CLIENT --distpath . --workpath=$(mktemp -d) --specpath=$(mktemp -d)
DONE
