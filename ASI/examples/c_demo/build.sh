#!/bin/sh
# Build the target instrumented for gcov coverage.
set -e
cc="${CC:-gcc}"
"$cc" --coverage -O0 -o calc calc.c
