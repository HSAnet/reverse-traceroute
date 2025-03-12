#!/bin/bash

set -e

apt install -y /packages/*.deb
python3 test.py